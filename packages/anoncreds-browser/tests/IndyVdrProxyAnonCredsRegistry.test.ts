import type { AgentContext } from '@credo-ts/core'

import { IndyVdrProxyAnonCredsRegistry } from '../src'

const did = 'TL1EaPFCZ8Si5aUrqScBDt'
const schemaId = `${did}:2:test:1.0`
const credentialDefinitionId = `${did}:3:CL:99:TAG`
const revocationRegistryDefinitionId = `${did}:4:${did}:3:CL:99:TAG:CL_ACCUM:tag`

type FetchCall = { url: string; init?: RequestInit }

function mockAgentContext(responses: Record<string, unknown>, calls: FetchCall[]) {
  const fetch = async (url: string, init?: RequestInit) => {
    calls.push({ url, init })
    const [path] = url.split('?')
    const key = Object.keys(responses).find((k) => path.includes(k))
    if (!key) return { ok: false, status: 404, json: async () => ({}) }
    return { ok: true, status: 200, json: async () => responses[key] }
  }

  return {
    config: {
      logger: { trace: () => {}, debug: () => {}, error: () => {} },
      agentDependencies: { fetch },
    },
  } as unknown as AgentContext
}

describe('IndyVdrProxyAnonCredsRegistry', () => {
  const registry = new IndyVdrProxyAnonCredsRegistry({ proxyBaseUrl: 'https://proxy.example.com' })

  test('resolves a schema', async () => {
    const calls: FetchCall[] = []
    const agentContext = mockAgentContext(
      {
        '/schema/': {
          op: 'REPLY',
          result: { seqNo: 99, data: { attr_names: ['name', 'age'], name: 'test', version: '1.0' } },
        },
      },
      calls
    )

    const result = await registry.getSchema(agentContext, schemaId)

    expect(calls[0].url).toBe(`https://proxy.example.com/schema/${encodeURIComponent(schemaId)}`)
    expect(result).toMatchObject({
      schema: { attrNames: ['name', 'age'], name: 'test', version: '1.0', issuerId: did },
      schemaId,
      schemaMetadata: { indyLedgerSeqNo: 99 },
    })
  })

  test('returns notFound for missing schema', async () => {
    const agentContext = mockAgentContext({ '/schema/': { op: 'REPLY', result: { data: {} } } }, [])
    const result = await registry.getSchema(agentContext, schemaId)
    expect(result.resolutionMetadata.error).toBe('notFound')
  })

  test('resolves a credential definition and reconstructs the schema id', async () => {
    const calls: FetchCall[] = []
    const agentContext = mockAgentContext(
      {
        '/cred_def/': {
          op: 'REPLY',
          result: { data: { primary: { n: '123' } }, ref: 99, tag: 'TAG' },
        },
        '/txn/DOMAIN/99': {
          op: 'REPLY',
          result: {
            data: { txn: { type: '101', metadata: { from: did }, data: { data: { name: 'test', version: '1.0' } } } },
          },
        },
      },
      calls
    )

    const result = await registry.getCredentialDefinition(agentContext, credentialDefinitionId)

    expect(result).toMatchObject({
      credentialDefinition: {
        issuerId: did,
        schemaId,
        tag: 'TAG',
        type: 'CL',
        value: { primary: { n: '123' } },
      },
      credentialDefinitionId,
    })
  })

  test('uses the did:indy namespace as path prefix', async () => {
    const calls: FetchCall[] = []
    const agentContext = mockAgentContext(
      {
        '/cred_def/': { op: 'REPLY', result: { data: { primary: {} }, ref: 99, tag: 'TAG' } },
        '/txn/DOMAIN/99': {
          op: 'REPLY',
          result: {
            data: { txn: { type: '101', metadata: { from: did }, data: { data: { name: 'test', version: '1.0' } } } },
          },
        },
      },
      calls
    )

    const didIndyCredentialDefinitionId = `did:indy:bcovrin:test:${did}/anoncreds/v0/CLAIM_DEF/99/TAG`
    const result = await registry.getCredentialDefinition(agentContext, didIndyCredentialDefinitionId)

    expect(calls[0].url).toBe(
      `https://proxy.example.com/bcovrin:test/cred_def/${encodeURIComponent(`${did}:3:CL:99:TAG`)}`
    )
    expect(result.credentialDefinition?.schemaId).toBe(`did:indy:bcovrin:test:${did}/anoncreds/v0/SCHEMA/test/1.0`)
    expect(result.credentialDefinitionMetadata.didIndyNamespace).toBe('bcovrin:test')
  })

  test('resolves a revocation status list via POST /submit', async () => {
    const calls: FetchCall[] = []
    const agentContext = mockAgentContext(
      {
        '/submit': {
          op: 'REPLY',
          result: {
            type: '117',
            txnTime: 150,
            data: { value: { accum_to: { value: { accum: '21 ABC' } }, issued: [0], revoked: [1] } },
          },
        },
        '/rev_reg_def/': {
          op: 'REPLY',
          result: {
            data: {
              revocDefType: 'CL_ACCUM',
              tag: 'tag',
              value: {
                maxCredNum: 4,
                tailsHash: 'hash',
                tailsLocation: 'location',
                publicKeys: { accumKey: { z: '1 0BB' } },
                issuanceType: 'ISSUANCE_BY_DEFAULT',
              },
            },
          },
        },
      },
      calls
    )

    const result = await registry.getRevocationStatusList(agentContext, revocationRegistryDefinitionId, 160)

    const submitCall = calls.find((call) => call.url.endsWith('/submit'))
    expect(submitCall?.init?.method).toBe('POST')
    const body = JSON.parse(submitCall?.init?.body as string)
    expect(body).toMatchObject({
      operation: { type: '117', revocRegDefId: `${did}:4:${did}:3:CL:99:TAG:CL_ACCUM:tag`, to: 160 },
      protocolVersion: 2,
    })

    expect(result.revocationStatusList).toEqual({
      issuerId: did,
      currentAccumulator: '21 ABC',
      revRegDefId: revocationRegistryDefinitionId,
      revocationList: [0, 1, 0, 0],
      timestamp: 150,
    })
  })

  test('does not support registration', async () => {
    const agentContext = mockAgentContext({}, [])
    const result = await registry.registerSchema(agentContext, {
      schema: { attrNames: ['name'], issuerId: did, name: 'test', version: '1.0' },
      options: {},
    })
    expect(result.schemaState.state).toBe('failed')
  })
})
