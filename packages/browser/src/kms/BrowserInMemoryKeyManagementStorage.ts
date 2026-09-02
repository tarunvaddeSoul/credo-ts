import type { AgentContext, Kms } from '@credo-ts/core'
import type { BrowserKeyManagementStorage } from './BrowserKeyManagementStorage'

export class BrowserInMemoryKeyManagementStorage implements BrowserKeyManagementStorage {
  #storage = new Map<string, Map<string, Kms.KmsJwkPrivate>>()

  public async get(agentContext: AgentContext, keyId: string) {
    return this.storageForContext(agentContext).get(keyId) ?? null
  }

  public has(agentContext: AgentContext, keyId: string) {
    return this.storageForContext(agentContext).has(keyId)
  }

  public set(agentContext: AgentContext, keyId: string, jwk: Kms.KmsJwkPrivate) {
    this.storageForContext(agentContext).set(keyId, jwk)
  }

  public delete(agentContext: AgentContext, keyId: string) {
    return this.storageForContext(agentContext).delete(keyId)
  }

  public deleteAllForContext(agentContext: AgentContext) {
    this.#storage.delete(agentContext.contextCorrelationId)
  }

  public deleteAll() {
    this.#storage.clear()
  }

  private storageForContext(agentContext: AgentContext) {
    let storage = this.#storage.get(agentContext.contextCorrelationId)

    if (!storage) {
      storage = new Map()
      this.#storage.set(agentContext.contextCorrelationId, storage)
    }

    return storage
  }
}
