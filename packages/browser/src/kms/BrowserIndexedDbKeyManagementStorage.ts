import type { AgentContext, Kms } from '@credo-ts/core'
import type { IdbDatabase, IdbObjectStore } from '../indexedDb'
import { contextKeyRange, KEYS_OBJECT_STORE, openCredoDatabase, promisifyRequest, transactionDone } from '../indexedDb'
import type { BrowserKeyManagementStorage } from './BrowserKeyManagementStorage'

interface StoredKey {
  contextCorrelationId: string
  keyId: string
  jwk: Kms.KmsJwkPrivate
}

export class BrowserIndexedDbKeyManagementStorage implements BrowserKeyManagementStorage {
  #databaseName: string
  #database?: Promise<IdbDatabase>

  public constructor(options?: { databaseName?: string }) {
    this.#databaseName = options?.databaseName ?? 'credo'
  }

  public async get(agentContext: AgentContext, keyId: string): Promise<Kms.KmsJwkPrivate | null> {
    const store = await this.store('readonly')
    const storedKey = (await promisifyRequest(store.get([agentContext.contextCorrelationId, keyId]))) as
      | StoredKey
      | undefined

    return storedKey?.jwk ?? null
  }

  public async has(agentContext: AgentContext, keyId: string): Promise<boolean> {
    return (await this.get(agentContext, keyId)) !== null
  }

  public async set(agentContext: AgentContext, keyId: string, jwk: Kms.KmsJwkPrivate): Promise<void> {
    const { store, done } = await this.writeStore()
    await promisifyRequest(
      store.put({
        contextCorrelationId: agentContext.contextCorrelationId,
        keyId,
        jwk,
      } satisfies StoredKey)
    )
    await done
  }

  public async delete(agentContext: AgentContext, keyId: string): Promise<boolean> {
    const { store, done } = await this.writeStore()
    const existing = await promisifyRequest(store.get([agentContext.contextCorrelationId, keyId]))
    if (!existing) return false

    await promisifyRequest(store.delete([agentContext.contextCorrelationId, keyId]))
    await done

    return true
  }

  public async deleteAllForContext(agentContext: AgentContext): Promise<void> {
    const { store, done } = await this.writeStore()
    await promisifyRequest(store.delete(contextKeyRange(agentContext.contextCorrelationId)))
    await done
  }

  public async deleteAll(): Promise<void> {
    const { store, done } = await this.writeStore()
    await promisifyRequest(store.clear())
    await done
  }

  private database(): Promise<IdbDatabase> {
    if (!this.#database) {
      // Drop the cached connection when it closes or fails to open,
      // so the next operation reopens the database
      const invalidate = () => {
        if (this.#database === databasePromise) this.#database = undefined
      }
      const databasePromise = openCredoDatabase(this.#databaseName, invalidate)
      databasePromise.catch(invalidate)
      this.#database = databasePromise
    }

    return this.#database
  }

  private async store(mode: 'readonly' | 'readwrite'): Promise<IdbObjectStore> {
    const database = await this.database()
    return database.transaction(KEYS_OBJECT_STORE, mode).objectStore(KEYS_OBJECT_STORE)
  }

  private async writeStore(): Promise<{ store: IdbObjectStore; done: Promise<void> }> {
    const database = await this.database()
    const transaction = database.transaction(KEYS_OBJECT_STORE, 'readwrite')

    // Attach completion handlers before any request runs, and swallow rejections
    // for callers that bail out before awaiting `done` (the failed request itself rejects)
    const done = transactionDone(transaction)
    done.catch(() => {})

    return { store: transaction.objectStore(KEYS_OBJECT_STORE), done }
  }
}
