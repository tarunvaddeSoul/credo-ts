import type { AgentContext } from '@credo-ts/core'

import { IndyVdrProxyAnonCredsRegistry } from '../src'

const did = 'JM9L6HL2QCexjbn9WB46h9'
const schemaSeqNo = 2921997
const schemaId = `${did}:2:Globeracers:5.0`
const credentialDefinitionId = `${did}:3:CL:${schemaSeqNo}:Globeracers|Events|SoulVerse`
const proxyBaseUrl = 'http://localhost:8080'

function mockAgentContext(responses: Record<string, unknown>, urls: string[] = []) {
  const fetch = async (url: string) => {
    urls.push(url)
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

describe('IndyVdrProxyAnonCredsRegistry ledger replies', () => {
  const registry = new IndyVdrProxyAnonCredsRegistry({ proxyBaseUrl })

  test('an empty data object is not a resolved schema', async () => {
    const agentContext = mockAgentContext({ '/schema/': { op: 'REPLY', result: { data: {} } } })

    const result = await registry.getSchema(agentContext, schemaId)

    expect(result.schema).toBeUndefined()
    expect(result.resolutionMetadata.error).toBe('notFound')
    expect(result.resolutionMetadata.message).toContain(proxyBaseUrl)
  })

  test('an empty data object is not a resolved credential definition', async () => {
    const urls: string[] = []
    const agentContext = mockAgentContext(
      {
        '/cred_def/': { op: 'REPLY', result: { ref: schemaSeqNo, tag: 'Globeracers|Events|SoulVerse', data: {} } },
        [`/txn/DOMAIN/${schemaSeqNo}`]: {
          op: 'REPLY',
          result: {
            data: {
              txn: {
                type: '101',
                metadata: { from: did },
                data: { data: { attr_names: ['name'], name: 'Globeracers', version: '5.0' } },
              },
            },
          },
        },
      },
      urls
    )

    const result = await registry.getCredentialDefinition(agentContext, credentialDefinitionId)

    expect(result.credentialDefinition).toBeUndefined()
    expect(result.resolutionMetadata.error).toBe('notFound')
    expect(result.resolutionMetadata.message).toContain(proxyBaseUrl)
    expect(urls).toHaveLength(1)
  })

  test('a null data is not a resolved schema or credential definition', async () => {
    const schemaResult = await registry.getSchema(
      mockAgentContext({ '/schema/': { op: 'REPLY', result: { data: null } } }),
      schemaId
    )
    expect(schemaResult.resolutionMetadata.error).toBe('notFound')

    const credentialDefinitionResult = await registry.getCredentialDefinition(
      mockAgentContext({ '/cred_def/': { op: 'REPLY', result: { data: null } } }),
      credentialDefinitionId
    )
    expect(credentialDefinitionResult.resolutionMetadata.error).toBe('notFound')
  })

  test('a credential definition without a resolvable schema txn is not resolved', async () => {
    const agentContext = mockAgentContext({
      '/cred_def/': {
        op: 'REPLY',
        result: {
          origin: did,
          ref: schemaSeqNo,
          signature_type: 'CL',
          tag: 'Globeracers|Events|SoulVerse',
          type: '108',
          data: { primary: { n: '123' } },
        },
      },
      [`/txn/DOMAIN/${schemaSeqNo}`]: { op: 'REPLY', result: { data: {} } },
    })

    const result = await registry.getCredentialDefinition(agentContext, credentialDefinitionId)

    expect(result.credentialDefinition).toBeUndefined()
    expect(result.resolutionMetadata.error).toBe('notFound')
  })

  test('resolves a bcovrin credential definition with a legacy unqualified schema id', async () => {
    const agentContext = mockAgentContext({
      '/cred_def/': {
        op: 'REPLY',
        result: {
          origin: did,
          ref: schemaSeqNo,
          signature_type: 'CL',
          tag: 'Globeracers|Events|SoulVerse',
          type: '108',
          data: { primary: { n: '123', s: '456', r: { master_secret: '789' }, rctxt: '1', z: '2' } },
        },
      },
      [`/txn/DOMAIN/${schemaSeqNo}`]: {
        op: 'REPLY',
        result: {
          data: {
            txn: {
              type: '101',
              metadata: { from: did },
              data: { data: { attr_names: ['name', 'event'], name: 'Globeracers', version: '5.0' } },
            },
          },
          seqNo: schemaSeqNo,
        },
      },
    })

    const result = await registry.getCredentialDefinition(agentContext, credentialDefinitionId)

    expect(result.resolutionMetadata).toEqual({})
    expect(result.credentialDefinition).toMatchObject({
      issuerId: did,
      schemaId,
      tag: 'Globeracers|Events|SoulVerse',
      type: 'CL',
    })
    expect(result.credentialDefinition?.value).toHaveProperty('primary')
  })
})
