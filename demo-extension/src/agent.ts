import {
  AnonCredsDidCommCredentialFormatService,
  AnonCredsDidCommProofFormatService,
  AnonCredsModule,
  DidCommCredentialV1Protocol,
  DidCommProofV1Protocol,
  LegacyIndyDidCommCredentialFormatService,
  LegacyIndyDidCommProofFormatService,
} from '@credo-ts/anoncreds'
import { IndyVdrProxyAnonCredsRegistry, loadAnoncredsWasm } from '@credo-ts/anoncreds-browser'
import { agentDependencies, BrowserWalletModule } from '@credo-ts/browser'
import { Agent, ConsoleLogger, defaultDocumentLoader, LogLevel, W3cCredentialsModule } from '@credo-ts/core'
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
import { CREDENTIALS_EXAMPLES_V1 } from './credentialsExamplesContext'

export interface WalletAgentOptions {
  mediatorInvitationUrl?: string
  /** Base url of an indy-vdr-proxy server used to resolve AnonCreds objects */
  indyVdrProxyUrl?: string
  /** Indy namespace path prefix, for proxies running in multi-ledger mode (e.g. 'bcovrin:test') */
  indyNamespace?: string
  /** IndexedDB database name, allows testing with a fresh wallet */
  databaseName?: string
}

export async function createWalletAgent(options: WalletAgentOptions) {
  const anoncreds = await loadAnoncredsWasm()

  const legacyIndyCredentialFormatService = new LegacyIndyDidCommCredentialFormatService()
  const legacyIndyProofFormatService = new LegacyIndyDidCommProofFormatService()

  const agent = new Agent({
    config: {
      logger: new ConsoleLogger(LogLevel.Info),
      // Convenient for local testing against http:// and ws:// agents
      allowInsecureHttpUrls: true,
    },
    dependencies: agentDependencies,
    modules: {
      wallet: new BrowserWalletModule({ databaseName: options.databaseName ?? 'credo-demo-wallet' }),
      w3cCredentials: new W3cCredentialsModule({
        documentLoader: (agentContext) =>
          defaultDocumentLoader(agentContext, {
            'https://www.w3.org/2018/credentials/examples/v1': CREDENTIALS_EXAMPLES_V1,
          }),
      }),
      anoncreds: new AnonCredsModule({
        anoncreds,
        registries: [
          new IndyVdrProxyAnonCredsRegistry({
            proxyBaseUrl: options.indyVdrProxyUrl ?? 'http://localhost:8080',
            // Namespace used to qualify legacy unqualified indy identifiers (v1 protocols)
            indyNamespace: options.indyNamespace ?? 'local',
          }),
        ],
      }),
      didcomm: new DidCommModule({
        connections: {
          autoAcceptConnections: true,
        },
        credentials: {
          autoAcceptCredentials: DidCommAutoAcceptCredential.ContentApproved,
          credentialProtocols: [
            new DidCommCredentialV1Protocol({
              indyCredentialFormat: legacyIndyCredentialFormatService,
            }),
            new DidCommCredentialV2Protocol({
              credentialFormats: [
                legacyIndyCredentialFormatService,
                new AnonCredsDidCommCredentialFormatService(),
                new DidCommJsonLdCredentialFormatService(),
              ],
            }),
          ],
        },
        proofs: {
          autoAcceptProofs: DidCommAutoAcceptProof.ContentApproved,
          proofProtocols: [
            new DidCommProofV1Protocol({
              indyProofFormat: legacyIndyProofFormatService,
            }),
            new DidCommProofV2Protocol({
              proofFormats: [
                legacyIndyProofFormatService,
                new AnonCredsDidCommProofFormatService(),
                new DidCommDifPresentationExchangeProofFormatService(),
              ],
            }),
          ],
        },
        mediationRecipient: options.mediatorInvitationUrl
          ? { mediatorInvitationUrl: options.mediatorInvitationUrl }
          : true,
      }),
    },
  })

  agent.didcomm.registerOutboundTransport(new DidCommHttpOutboundTransport())
  agent.didcomm.registerOutboundTransport(new DidCommWsOutboundTransport())

  return agent
}

export type WalletAgent = Awaited<ReturnType<typeof createWalletAgent>>
