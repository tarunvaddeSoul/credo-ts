/**
 * Local issuer/verifier agent for testing the demo extension wallet.
 *
 * Run from the repo root:
 *   pnpm --filter credo-demo-extension exec vite-node e2e/local-agent.ts
 *
 * It starts:
 * - a Credo Node agent with a WS inbound transport on ws://localhost:9001
 * - a control HTTP server on http://localhost:9000 to drive the flows:
 *     GET  /invitation                     -> out-of-band invitation URL (paste in the wallet)
 *     GET  /state                          -> connections/credentials/proofs of this agent
 *     POST /send-message?text=...          -> basic message to the latest connection
 *     POST /offer-jsonld?subjectDid=...    -> offer a W3C JSON-LD credential (subjectDid = wallet's did)
 *     POST /offer-anoncreds                -> offer an AnonCreds credential
 *     POST /request-proof-pex              -> request a DIF PEX proof of the JSON-LD credential
 *     POST /request-proof-anoncreds        -> request an AnonCreds proof (name + age >= 18)
 * - a fake indy-vdr-proxy on http://localhost:8080 serving the AnonCreds objects this agent
 *   registers in its in-memory registry, so the browser wallet can resolve them
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import type { AnonCredsCredentialDefinition, AnonCredsSchema } from '@credo-ts/anoncreds'
import {
  AnonCredsDidCommCredentialFormatService,
  AnonCredsDidCommProofFormatService,
  AnonCredsModule,
  DidCommCredentialV1Protocol,
  DidCommProofV1Protocol,
  LegacyIndyDidCommCredentialFormatService,
  LegacyIndyDidCommProofFormatService,
} from '@credo-ts/anoncreds'
import type { KeyDidCreateOptions, Module } from '@credo-ts/core'
import {
  Agent,
  CacheModule,
  ConsoleLogger,
  DidDocumentBuilder,
  DidsModule,
  defaultDocumentLoader,
  InMemoryLruCache,
  Kms,
  LogLevel,
  utils,
  W3cCredentialsModule,
} from '@credo-ts/core'
import {
  DidCommAutoAcceptCredential,
  DidCommAutoAcceptProof,
  DidCommCredentialV2Protocol,
  DidCommDifPresentationExchangeProofFormatService,
  DidCommHttpOutboundTransport,
  DidCommJsonLdCredentialFormatService,
  DidCommModule,
  DidCommProofV2Protocol,
  DidCommWsOutboundTransport,
} from '@credo-ts/didcomm'
import { agentDependencies, DidCommWsInboundTransport } from '@credo-ts/node'
import { anoncreds } from '@hyperledger/anoncreds-nodejs'
import { InMemoryAnonCredsRegistry } from '../../packages/anoncreds/tests/InMemoryAnonCredsRegistry'
import { LocalDidResolver } from '../../packages/anoncreds/tests/LocalDidResolver'
import { BrowserInMemoryKeyManagementStorage, BrowserKeyManagementService } from '../../packages/browser/src'
import { InMemoryWalletModule } from '../../tests/InMemoryWalletModule'
import { CREDENTIALS_EXAMPLES_V1 } from '../src/credentialsExamplesContext'

const WS_PORT = 9201
const CONTROL_PORT = 9202
const PROXY_PORT = 8080

const anoncredsIssuerId = 'did:indy:local:LjgpST2rjsoxYegQDRm7EL'
const legacyIssuerDid = 'LjgpST2rjsoxYegQDRm7EL'

// The registry writes registered objects into these maps (both qualified and
// legacy unqualified ids), the fake indy-vdr-proxy below serves from them
const schemas: Record<string, AnonCredsSchema> = {}
const credentialDefinitions: Record<string, AnonCredsCredentialDefinition> = {}

const agent = new Agent({
  config: {
    logger: new ConsoleLogger(LogLevel.info),
    allowInsecureHttpUrls: true,
  },
  dependencies: agentDependencies,
  modules: {
    inMemory: new InMemoryWalletModule({ enableKms: false }),
    // The browser KMS supports DIDComm v1 envelope crypto and runs fine under Node,
    // and is more stable than askar for a long-running harness
    browserKms: {
      register(dependencyManager) {
        const kmsConfig = dependencyManager.resolve(Kms.KeyManagementModuleConfig)
        kmsConfig.registerBackend(new BrowserKeyManagementService(new BrowserInMemoryKeyManagementStorage()))
      },
    } satisfies Module,
    dids: new DidsModule({ resolvers: [new LocalDidResolver()] }),
    cache: new CacheModule({ cache: new InMemoryLruCache({ limit: 100 }) }),
    w3cCredentials: new W3cCredentialsModule({
      documentLoader: (agentContext) =>
        defaultDocumentLoader(agentContext, {
          'https://www.w3.org/2018/credentials/examples/v1': CREDENTIALS_EXAMPLES_V1,
        }),
    }),
    anoncreds: new AnonCredsModule({
      anoncreds,
      registries: [
        new InMemoryAnonCredsRegistry({
          existingSchemas: schemas,
          existingCredentialDefinitions: credentialDefinitions,
        }),
      ],
    }),
    didcomm: new DidCommModule({
      endpoints: [`ws://localhost:${WS_PORT}`],
      connections: { autoAcceptConnections: true },
      credentials: {
        autoAcceptCredentials: DidCommAutoAcceptCredential.ContentApproved,
        credentialProtocols: [
          new DidCommCredentialV1Protocol({ indyCredentialFormat: new LegacyIndyDidCommCredentialFormatService() }),
          new DidCommCredentialV2Protocol({
            credentialFormats: [
              new AnonCredsDidCommCredentialFormatService(),
              new DidCommJsonLdCredentialFormatService(),
            ],
          }),
        ],
      },
      proofs: {
        autoAcceptProofs: DidCommAutoAcceptProof.ContentApproved,
        proofProtocols: [
          new DidCommProofV1Protocol({ indyProofFormat: new LegacyIndyDidCommProofFormatService() }),
          new DidCommProofV2Protocol({
            proofFormats: [
              new AnonCredsDidCommProofFormatService(),
              new DidCommDifPresentationExchangeProofFormatService(),
            ],
          }),
        ],
      },
    }),
  },
})

let jsonLdIssuerDid: string
let credentialDefinitionId: string
let lastConnectionId: string | undefined

async function setup() {
  agent.didcomm.registerInboundTransport(new DidCommWsInboundTransport({ port: WS_PORT }))
  agent.didcomm.registerOutboundTransport(new DidCommWsOutboundTransport())
  agent.didcomm.registerOutboundTransport(new DidCommHttpOutboundTransport())

  await agent.initialize()

  // Issuer did for JSON-LD credentials
  const didResult = await agent.dids.create<KeyDidCreateOptions>({
    method: 'key',
    options: { createKey: { type: { kty: 'OKP', crv: 'Ed25519' } } },
  })
  if (didResult.didState.state !== 'finished') throw new Error('Failed to create json-ld issuer did')
  jsonLdIssuerDid = didResult.didState.did

  // Issuer did + schema + credential definition for AnonCreds credentials
  await agent.dids.import({ did: anoncredsIssuerId, didDocument: new DidDocumentBuilder(anoncredsIssuerId).build() })

  const { schemaState } = await agent.modules.anoncreds.registerSchema({
    schema: { attrNames: ['name', 'age'], name: 'SSW Demo Schema', version: '1.0', issuerId: anoncredsIssuerId },
    options: {},
  })
  if (schemaState.state !== 'finished') throw new Error(`Failed to register schema: ${JSON.stringify(schemaState)}`)

  const { credentialDefinitionState } = await agent.modules.anoncreds.registerCredentialDefinition({
    credentialDefinition: { schemaId: schemaState.schemaId, issuerId: anoncredsIssuerId, tag: 'default' },
    options: { supportRevocation: false },
  })
  if (credentialDefinitionState.state !== 'finished') {
    throw new Error(`Failed to register credential definition: ${JSON.stringify(credentialDefinitionState)}`)
  }
  credentialDefinitionId = credentialDefinitionState.credentialDefinitionId

  agent.events.on('DidCommConnectionStateChanged', (event) => {
    const record = (event.payload as { connectionRecord: { id: string; state: string } }).connectionRecord

    if (record.state === 'completed') lastConnectionId = record.id
  })
}

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' })
  res.end(JSON.stringify(body, null, 2))
}

async function requireConnectionId(): Promise<string> {
  if (lastConnectionId) return lastConnectionId
  const connections = await agent.didcomm.connections.getAll()
  const completed = connections.find((connection) => connection.state === 'completed')
  if (!completed) throw new Error('No completed connection yet')
  return completed.id
}

async function handleControl(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? '/', `http://localhost:${CONTROL_PORT}`)

  try {
    if (url.pathname === '/invitation') {
      const { outOfBandInvitation } = await agent.didcomm.oob.createInvitation({ label: 'Local Issuer' })
      res.writeHead(200, { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' })
      res.end(outOfBandInvitation.toUrl({ domain: `http://localhost:${CONTROL_PORT}/invitation` }))
      return
    }

    if (url.pathname === '/send-message') {
      const connectionId = await requireConnectionId()
      const text = url.searchParams.get('text') ?? 'Hello from the local issuer agent!'
      await agent.didcomm.basicMessages.sendMessage(connectionId, text)
      return sendJson(res, 200, { sent: text })
    }

    if (url.pathname === '/offer-jsonld') {
      const subjectDid = url.searchParams.get('subjectDid')
      if (!subjectDid) return sendJson(res, 400, { error: 'subjectDid query parameter is required' })

      const connectionId = await requireConnectionId()
      const exchange = await agent.didcomm.credentials.offerCredential({
        connectionId,
        protocolVersion: 'v2',
        comment: 'SSW demo university degree',
        credentialFormats: {
          jsonld: {
            credential: {
              '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'],
              type: ['VerifiableCredential', 'UniversityDegreeCredential'],
              issuer: jsonLdIssuerDid,
              issuanceDate: '2017-10-22T12:23:48Z',
              credentialSubject: {
                id: subjectDid,
                degree: { type: 'BachelorDegree', name: 'Bachelor of Science and Arts' },
              },
            },
            options: { proofType: 'Ed25519Signature2018', proofPurpose: 'assertionMethod' },
          },
        },
      })
      return sendJson(res, 200, { credentialExchangeId: exchange.id, state: exchange.state })
    }

    if (url.pathname === '/offer-anoncreds-v1') {
      const connectionId = await requireConnectionId()
      const legacyCredentialDefinitionId = Object.keys(credentialDefinitions).find((id) => !id.startsWith('did:'))
      if (!legacyCredentialDefinitionId) return sendJson(res, 500, { error: 'No legacy credential definition id' })

      const exchange = await agent.didcomm.credentials.offerCredential({
        connectionId,
        protocolVersion: 'v1',
        comment: 'SSW demo legacy indy credential',
        credentialFormats: {
          indy: {
            credentialDefinitionId: legacyCredentialDefinitionId,
            attributes: [
              { name: 'name', value: 'Tarun (v1)' },
              { name: 'age', value: '28' },
            ],
          },
        },
      })
      return sendJson(res, 200, { credentialExchangeId: exchange.id, state: exchange.state })
    }

    if (url.pathname === '/request-proof-anoncreds-v1') {
      const connectionId = await requireConnectionId()
      const legacyCredentialDefinitionId = Object.keys(credentialDefinitions).find((id) => !id.startsWith('did:'))
      if (!legacyCredentialDefinitionId) return sendJson(res, 500, { error: 'No legacy credential definition id' })

      const exchange = await agent.didcomm.proofs.requestProof({
        connectionId,
        protocolVersion: 'v1',
        proofFormats: {
          indy: {
            name: 'SSW Demo Proof v1',
            version: '1.0',
            requested_attributes: {
              name: { name: 'name', restrictions: [{ cred_def_id: legacyCredentialDefinitionId }] },
            },
            requested_predicates: {
              age: {
                name: 'age',
                p_type: '>=',
                p_value: 18,
                restrictions: [{ cred_def_id: legacyCredentialDefinitionId }],
              },
            },
          },
        },
      })
      return sendJson(res, 200, { proofExchangeId: exchange.id, state: exchange.state })
    }

    if (url.pathname === '/offer-anoncreds') {
      const connectionId = await requireConnectionId()
      const exchange = await agent.didcomm.credentials.offerCredential({
        connectionId,
        protocolVersion: 'v2',
        comment: 'SSW demo anoncreds credential',
        credentialFormats: {
          anoncreds: {
            credentialDefinitionId,
            attributes: [
              { name: 'name', value: 'Tarun' },
              { name: 'age', value: '28' },
            ],
          },
        },
      })
      return sendJson(res, 200, { credentialExchangeId: exchange.id, state: exchange.state })
    }

    if (url.pathname === '/request-proof-pex') {
      const connectionId = await requireConnectionId()
      const exchange = await agent.didcomm.proofs.requestProof({
        connectionId,
        protocolVersion: 'v2',
        proofFormats: {
          presentationExchange: {
            presentationDefinition: {
              id: utils.uuid(),
              input_descriptors: [
                {
                  id: 'degree_input',
                  schema: [{ uri: 'https://www.w3.org/2018/credentials/examples/v1' }],
                  constraints: { fields: [{ path: ['$.credentialSubject.degree.type'] }] },
                },
              ],
            },
          },
        },
      })
      return sendJson(res, 200, { proofExchangeId: exchange.id, state: exchange.state })
    }

    if (url.pathname === '/request-proof-anoncreds') {
      const connectionId = await requireConnectionId()
      const exchange = await agent.didcomm.proofs.requestProof({
        connectionId,
        protocolVersion: 'v2',
        proofFormats: {
          anoncreds: {
            name: 'SSW Demo Proof',
            version: '1.0',
            requested_attributes: {
              name: { name: 'name', restrictions: [{ cred_def_id: credentialDefinitionId }] },
            },
            requested_predicates: {
              age: { name: 'age', p_type: '>=', p_value: 18, restrictions: [{ cred_def_id: credentialDefinitionId }] },
            },
          },
        },
      })
      return sendJson(res, 200, { proofExchangeId: exchange.id, state: exchange.state })
    }

    if (url.pathname === '/state') {
      const [connections, credentials, proofs, basicMessages] = await Promise.all([
        agent.didcomm.connections.getAll(),
        agent.didcomm.credentials.getAll(),
        agent.didcomm.proofs.getAll(),
        agent.didcomm.basicMessages.findAllByQuery({}),
      ])
      return sendJson(res, 200, {
        connections: connections.map((record) => ({
          id: record.id,
          state: record.state,
          theirLabel: record.theirLabel,
        })),
        credentialExchanges: credentials.map((record) => ({ id: record.id, state: record.state })),
        proofExchanges: proofs.map((record) => ({ id: record.id, state: record.state, isVerified: record.isVerified })),
        basicMessages: basicMessages.map((record) => ({ role: record.role, content: record.content })),
      })
    }

    sendJson(res, 404, { error: `Unknown path ${url.pathname}` })
  } catch (error) {
    sendJson(res, 500, { error: String(error) })
  }
}

/**
 * Minimal indy-vdr-proxy lookalike backed by the in-memory registry maps.
 * Serves only what IndyVdrProxyAnonCredsRegistry needs for non-revocable
 * credentials: /schema/{id}, /cred_def/{id} and /txn/DOMAIN/{seqNo}.
 */
function handleProxy(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? '/', `http://localhost:${PROXY_PORT}`)

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Accept, Content-Type',
    })
    res.end()
    return
  }

  // Strip an optional namespace prefix (e.g. /local/schema/... for did:indy:local:...)
  let segments = url.pathname.split('/').filter(Boolean).map(decodeURIComponent)
  if (segments.length > 0 && !['schema', 'cred_def', 'txn', 'submit'].includes(segments[0])) {
    segments = segments.slice(1)
  }

  const findCredentialDefinitionEntry = () =>
    Object.entries(credentialDefinitions).find(([id]) => id.includes(':3:CL:'))

  const seqNoFromCredentialDefinitionId = (credentialDefinitionEntry?: [string, AnonCredsCredentialDefinition]) => {
    const legacyId = credentialDefinitionEntry?.[0]
    const match = legacyId?.match(/:3:CL:(\d+):/)
    return match ? Number(match[1]) : 99
  }

  if (segments[0] === 'schema' && segments[1]) {
    const schema = schemas[segments[1]]
    if (!schema) return sendJson(res, 200, { op: 'REPLY', result: { data: {} } })

    return sendJson(res, 200, {
      op: 'REPLY',
      result: {
        seqNo: seqNoFromCredentialDefinitionId(findCredentialDefinitionEntry()),
        data: { attr_names: schema.attrNames, name: schema.name, version: schema.version },
      },
    })
  }

  if (segments[0] === 'cred_def' && segments[1]) {
    const credentialDefinition = credentialDefinitions[segments[1]]
    if (!credentialDefinition) return sendJson(res, 200, { op: 'REPLY', result: { data: {} } })

    const match = segments[1].match(/:3:CL:(\d+):(.+)$/)
    return sendJson(res, 200, {
      op: 'REPLY',
      result: {
        data: credentialDefinition.value,
        ref: match ? Number(match[1]) : 99,
        tag: match ? match[2] : credentialDefinition.tag,
      },
    })
  }

  if (segments[0] === 'txn' && segments[1] === 'DOMAIN' && segments[2]) {
    const schemaEntry = Object.entries(schemas).find(([id]) => !id.startsWith('did:'))
    if (!schemaEntry) return sendJson(res, 200, { op: 'REPLY', result: { data: {} } })

    const [, schema] = schemaEntry
    return sendJson(res, 200, {
      op: 'REPLY',
      result: {
        data: {
          txn: {
            type: '101',
            metadata: { from: legacyIssuerDid },
            data: { data: { name: schema.name, version: schema.version } },
          },
        },
      },
    })
  }

  sendJson(res, 404, { error: `Unknown proxy path ${url.pathname}` })
}

export async function main() {
  await setup()

  createServer(handleControl).listen(CONTROL_PORT, () => {})
  createServer(handleProxy).listen(PROXY_PORT, () => {})
}
