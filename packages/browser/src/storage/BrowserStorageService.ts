import type {
  AgentContext,
  BaseRecord,
  BaseRecordConstructor,
  Query,
  QueryOptions,
  StorageService,
  TagsBase,
} from '@credo-ts/core'
import { injectable, JsonTransformer, RecordDuplicateError, RecordNotFoundError } from '@credo-ts/core'
import type { IdbDatabase, IdbObjectStore } from '../indexedDb'
import {
  contextKeyRange,
  openCredoDatabase,
  promisifyRequest,
  RECORDS_OBJECT_STORE,
  transactionDone,
} from '../indexedDb'

interface StorageRecord {
  contextCorrelationId: string
  id: string
  type: string
  value: Record<string, unknown>
  tags: Record<string, unknown>
}

@injectable()
// biome-ignore lint/suspicious/noExplicitAny: base record type parameters
export class BrowserStorageService<T extends BaseRecord<any, any, any> = BaseRecord<any, any, any>>
  implements StorageService<T>
{
  public readonly supportsCursorPagination = false

  #databaseName: string
  #database?: Promise<IdbDatabase>

  public constructor(options?: { databaseName?: string }) {
    this.#databaseName = options?.databaseName ?? 'credo'
  }

  public async save(agentContext: AgentContext, record: T): Promise<void> {
    record.updatedAt = new Date()
    const storageRecord = this.toStorageRecord(agentContext, record)

    const { store, done } = await this.writeStore()
    const existing = await promisifyRequest(store.get([agentContext.contextCorrelationId, record.id]))
    if (existing) {
      throw new RecordDuplicateError(`Record with id ${record.id} already exists`, { recordType: record.type })
    }

    await promisifyRequest(store.add(storageRecord))
    await done
  }

  public async update(agentContext: AgentContext, record: T): Promise<void> {
    record.updatedAt = new Date()
    const storageRecord = this.toStorageRecord(agentContext, record)

    const { store, done } = await this.writeStore()
    const existing = (await promisifyRequest(store.get([agentContext.contextCorrelationId, record.id]))) as
      | StorageRecord
      | undefined
    if (!existing || existing.type !== record.type) {
      throw new RecordNotFoundError(`record with id ${record.id} not found.`, { recordType: record.type })
    }

    await promisifyRequest(store.put(storageRecord))
    await done
  }

  public async delete(agentContext: AgentContext, record: T): Promise<void> {
    await this.deleteByRecordId(agentContext, record.type, record.id)
  }

  public async deleteById(
    agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>,
    id: string
  ): Promise<void> {
    await this.deleteByRecordId(agentContext, recordClass.type, id)
  }

  private async deleteByRecordId(agentContext: AgentContext, recordType: string, id: string): Promise<void> {
    const { store, done } = await this.writeStore()
    const existing = (await promisifyRequest(store.get([agentContext.contextCorrelationId, id]))) as
      | StorageRecord
      | undefined
    if (!existing || existing.type !== recordType) {
      throw new RecordNotFoundError(`record with id ${id} not found.`, { recordType })
    }

    await promisifyRequest(store.delete([agentContext.contextCorrelationId, id]))
    await done
  }

  public async getById(agentContext: AgentContext, recordClass: BaseRecordConstructor<T>, id: string): Promise<T> {
    const store = await this.store('readonly')
    const storageRecord = (await promisifyRequest(store.get([agentContext.contextCorrelationId, id]))) as
      | StorageRecord
      | undefined

    if (!storageRecord || storageRecord.type !== recordClass.type) {
      throw new RecordNotFoundError(`record with id ${id} not found.`, { recordType: recordClass.type })
    }

    return this.recordToInstance(storageRecord, recordClass)
  }

  public async getAll(agentContext: AgentContext, recordClass: BaseRecordConstructor<T>): Promise<T[]> {
    const storageRecords = await this.getAllStorageRecords(agentContext, recordClass)

    return storageRecords.map((storageRecord) => this.recordToInstance(storageRecord, recordClass))
  }

  public async findByQuery(
    agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>,
    query: Query<T>,
    queryOptions?: QueryOptions
  ): Promise<T[]> {
    const { offset = 0, limit } = queryOptions ?? {}

    const storageRecords = (await this.getAllStorageRecords(agentContext, recordClass)).filter((storageRecord) =>
      filterByQuery(storageRecord, query)
    )

    const slicedRecords =
      limit !== undefined ? storageRecords.slice(offset, offset + limit) : storageRecords.slice(offset)

    return slicedRecords.map((storageRecord) => this.recordToInstance(storageRecord, recordClass))
  }

  /**
   * Remove all records for the context. Used when an agent context (e.g. a tenant) is deleted.
   */
  public async deleteAllForContext(agentContext: AgentContext): Promise<void> {
    const { store, done } = await this.writeStore()
    await promisifyRequest(store.delete(contextKeyRange(agentContext.contextCorrelationId)))
    await done
  }

  /**
   * Remove all records for every context. Used when the root agent context is deleted,
   * which also deletes all tenant contexts.
   */
  public async deleteAll(): Promise<void> {
    const { store, done } = await this.writeStore()
    await promisifyRequest(store.clear())
    await done
  }

  private async getAllStorageRecords(
    agentContext: AgentContext,
    recordClass: BaseRecordConstructor<T>
  ): Promise<StorageRecord[]> {
    const store = await this.store('readonly')

    return (await promisifyRequest(
      store.index('contextType').getAll([agentContext.contextCorrelationId, recordClass.type])
    )) as StorageRecord[]
  }

  private toStorageRecord(agentContext: AgentContext, record: T): StorageRecord {
    // _tags are stored separately and restored with replaceTags on read
    const { _tags, ...value } = JsonTransformer.toJSON(record)

    return {
      contextCorrelationId: agentContext.contextCorrelationId,
      id: record.id,
      type: record.type,
      value,
      tags: record.getTags(),
    }
  }

  private recordToInstance(storageRecord: StorageRecord, recordClass: BaseRecordConstructor<T>): T {
    const instance = JsonTransformer.fromJSON<T>(storageRecord.value, recordClass)
    instance.id = storageRecord.id
    instance.replaceTags(storageRecord.tags as TagsBase)

    return instance
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
    return database.transaction(RECORDS_OBJECT_STORE, mode).objectStore(RECORDS_OBJECT_STORE)
  }

  private async writeStore(): Promise<{ store: IdbObjectStore; done: Promise<void> }> {
    const database = await this.database()
    const transaction = database.transaction(RECORDS_OBJECT_STORE, 'readwrite')

    // Attach completion handlers before any request runs, and swallow rejections
    // for callers that bail out before awaiting `done` (the failed request itself rejects)
    const done = transactionDone(transaction)
    done.catch(() => {})

    return { store: transaction.objectStore(RECORDS_OBJECT_STORE), done }
  }
}

// biome-ignore lint/suspicious/noExplicitAny: base record type parameters
function filterByQuery<T extends BaseRecord<any, any, any>>(storageRecord: StorageRecord, query: Query<T>): boolean {
  const { $and, $or, $not, ...restQuery } = query

  if (!matchSimpleQuery(storageRecord, restQuery)) return false

  // All $and queries MUST match
  if ($and) {
    const allAndMatch = ($and as Query<T>[]).every((and) => filterByQuery(storageRecord, and))
    if (!allAndMatch) return false
  }

  // Only one $or query has to match
  if ($or) {
    const oneOrMatch = ($or as Query<T>[]).some((or) => filterByQuery(storageRecord, or))
    if (!oneOrMatch) return false
  }

  // The $not query must not match
  if ($not) {
    if (filterByQuery(storageRecord, $not as Query<T>)) return false
  }

  return true
}

// biome-ignore lint/suspicious/noExplicitAny: base record type parameters
function matchSimpleQuery<T extends BaseRecord<any, any, any>>(storageRecord: StorageRecord, query: Query<T>): boolean {
  const tags = storageRecord.tags as TagsBase

  for (const [key, value] of Object.entries(query)) {
    // We don't query for value undefined, the value should be null in that case
    if (value === undefined) continue

    if (Array.isArray(value)) {
      const tagValue = tags[key]
      if (!Array.isArray(tagValue) || !value.every((v) => tagValue.includes(v))) {
        return false
      }
    } else if (tags[key] !== value) {
      return false
    }
  }

  return true
}
