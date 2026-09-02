import 'fake-indexeddb/auto'

import { Agent, Kms, utils } from '@credo-ts/core'
import { agentDependencies, BrowserWalletModule } from '../src'

const createAgent = (databaseName: string) =>
  new Agent({
    dependencies: agentDependencies,
    modules: {
      wallet: new BrowserWalletModule({ databaseName }),
    },
  })

describe('browser agent', () => {
  it('initializes with the browser wallet module, persists records and signs with the browser kms', async () => {
    const databaseName = `agent-${utils.uuid()}`
    const agent = createAgent(databaseName)

    await agent.initialize()

    // Generic records go through the IndexedDB storage service
    const record = await agent.genericRecords.save({
      content: { name: 'SSW Extension' },
      tags: { walletType: 'browser' },
    })

    const found = await agent.genericRecords.findAllByQuery({ walletType: 'browser' })
    expect(found).toHaveLength(1)
    expect(found[0].content).toEqual({ name: 'SSW Extension' })

    // Keys are created and used through the browser key management backend
    const key = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
    expect(key.publicJwk.kty).toBe('EC')

    const data = new TextEncoder().encode('sign me')
    const { signature } = await agent.kms.sign({ keyId: key.keyId, algorithm: 'ES256', data })

    const verification = await agent.kms.verify({ key: { keyId: key.keyId }, algorithm: 'ES256', data, signature })
    expect(verification.verified).toBe(true)

    await agent.shutdown()

    // A second agent over the same IndexedDB database sees the persisted state
    const secondAgent = createAgent(databaseName)
    await secondAgent.initialize()

    const persistedRecord = await secondAgent.genericRecords.findById(record.id)
    expect(persistedRecord?.content).toEqual({ name: 'SSW Extension' })

    const persistedVerification = await secondAgent.kms.verify({
      key: { keyId: key.keyId },
      algorithm: 'ES256',
      data,
      signature,
    })
    expect(persistedVerification.verified).toBe(true)

    await secondAgent.shutdown()
  })

  it('removes all records and keys when the root agent context is deleted', async () => {
    const databaseName = `agent-${utils.uuid()}`
    const agent = createAgent(databaseName)
    await agent.initialize()

    await agent.genericRecords.save({ content: { name: 'to be deleted' } })
    const key = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })

    await agent.dependencyManager.deleteAgentContext(agent.context)

    // A fresh agent over the same database starts empty
    const secondAgent = createAgent(databaseName)
    await secondAgent.initialize()

    expect(await secondAgent.genericRecords.getAll()).toHaveLength(0)
    await expect(secondAgent.kms.getPublicKey({ keyId: key.keyId })).rejects.toThrow(Kms.KeyManagementKeyNotFoundError)

    await secondAgent.shutdown()
  })

  it('provides browser agent dependencies', () => {
    expect(agentDependencies.FileSystem).toBeDefined()
    expect(agentDependencies.fetch).toBeInstanceOf(Function)
    expect(agentDependencies.EventEmitterClass).toBeInstanceOf(Function)
  })
})
