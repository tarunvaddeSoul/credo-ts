import 'fake-indexeddb/auto'

import type { TagsBase } from '@credo-ts/core'
import { BaseRecord, RecordDuplicateError, RecordNotFoundError, utils } from '@credo-ts/core'
import { getAgentContext } from '../../core/tests'
import { BrowserStorageService } from '../src'

type TestRecordTags = TagsBase

class TestRecord extends BaseRecord<TestRecordTags> {
  public static readonly type = 'TestRecord'
  public readonly type = TestRecord.type

  public foo!: string

  public constructor(props: { id?: string; foo: string; tags?: TestRecordTags }) {
    super()

    if (props) {
      this.id = props.id ?? utils.uuid()
      this.createdAt = new Date()
      this.foo = props.foo
      this._tags = props.tags ?? {}
    }
  }

  public getTags() {
    return this._tags
  }
}

class OtherRecord extends BaseRecord {
  public static readonly type = 'OtherRecord'
  public readonly type = OtherRecord.type

  public getTags() {
    return this._tags
  }
}

const agentContext = getAgentContext({ contextCorrelationId: 'default' })
const agentContextTenant = getAgentContext({ contextCorrelationId: 'tenant-1' })

describe('BrowserStorageService', () => {
  let storageService: BrowserStorageService<TestRecord>

  beforeEach(() => {
    storageService = new BrowserStorageService({ databaseName: `test-${utils.uuid()}` })
  })

  describe('save and getById', () => {
    it('saves a record and retrieves it by id', async () => {
      const record = new TestRecord({ foo: 'bar', tags: { myTag: 'value' } })
      await storageService.save(agentContext, record)

      const retrieved = await storageService.getById(agentContext, TestRecord, record.id)

      expect(retrieved).toBeInstanceOf(TestRecord)
      expect(retrieved.id).toBe(record.id)
      expect(retrieved.foo).toBe('bar')
      expect(retrieved.getTags()).toEqual({ myTag: 'value' })
    })

    it('throws RecordDuplicateError on duplicate id', async () => {
      const record = new TestRecord({ foo: 'bar' })
      await storageService.save(agentContext, record)

      await expect(storageService.save(agentContext, record)).rejects.toThrow(RecordDuplicateError)
    })

    it('throws RecordNotFoundError for a missing record', async () => {
      await expect(storageService.getById(agentContext, TestRecord, 'missing')).rejects.toThrow(RecordNotFoundError)
    })

    it('does not return records of another type with the same id', async () => {
      const record = new TestRecord({ foo: 'bar' })
      await storageService.save(agentContext, record)

      await expect(storageService.getById(agentContext, OtherRecord as never, record.id)).rejects.toThrow(
        RecordNotFoundError
      )
    })

    it('persists records across service instances using the same database', async () => {
      const databaseName = `persistent-${utils.uuid()}`
      const first = new BrowserStorageService<TestRecord>({ databaseName })
      const record = new TestRecord({ foo: 'persisted' })
      await first.save(agentContext, record)

      const second = new BrowserStorageService<TestRecord>({ databaseName })
      const retrieved = await second.getById(agentContext, TestRecord, record.id)
      expect(retrieved.foo).toBe('persisted')
    })
  })

  describe('update', () => {
    it('updates an existing record', async () => {
      const record = new TestRecord({ foo: 'before' })
      await storageService.save(agentContext, record)

      record.foo = 'after'
      record.setTag('updated', true)
      await storageService.update(agentContext, record)

      const retrieved = await storageService.getById(agentContext, TestRecord, record.id)
      expect(retrieved.foo).toBe('after')
      expect(retrieved.getTag('updated')).toBe(true)
    })

    it('throws RecordNotFoundError for a missing record', async () => {
      const record = new TestRecord({ foo: 'bar' })
      await expect(storageService.update(agentContext, record)).rejects.toThrow(RecordNotFoundError)
    })
  })

  describe('delete', () => {
    it('deletes a record', async () => {
      const record = new TestRecord({ foo: 'bar' })
      await storageService.save(agentContext, record)

      await storageService.delete(agentContext, record)

      await expect(storageService.getById(agentContext, TestRecord, record.id)).rejects.toThrow(RecordNotFoundError)
    })

    it('deletes a record by id', async () => {
      const record = new TestRecord({ foo: 'bar' })
      await storageService.save(agentContext, record)

      await storageService.deleteById(agentContext, TestRecord, record.id)

      await expect(storageService.getById(agentContext, TestRecord, record.id)).rejects.toThrow(RecordNotFoundError)
    })

    it('throws RecordNotFoundError when deleting a missing record', async () => {
      await expect(storageService.deleteById(agentContext, TestRecord, 'missing')).rejects.toThrow(RecordNotFoundError)
    })
  })

  describe('getAll and findByQuery', () => {
    beforeEach(async () => {
      await storageService.save(
        agentContext,
        new TestRecord({ id: 'record-1', foo: 'one', tags: { group: 'a', enabled: true, items: ['x', 'y'] } })
      )
      await storageService.save(
        agentContext,
        new TestRecord({ id: 'record-2', foo: 'two', tags: { group: 'a', enabled: false, items: ['x'] } })
      )
      await storageService.save(
        agentContext,
        new TestRecord({ id: 'record-3', foo: 'three', tags: { group: 'b', enabled: true } })
      )
    })

    it('returns all records of the type', async () => {
      const records = await storageService.getAll(agentContext, TestRecord)
      expect(records.map((record) => record.id).sort()).toEqual(['record-1', 'record-2', 'record-3'])
    })

    it('matches on simple tags including booleans', async () => {
      const records = await storageService.findByQuery(agentContext, TestRecord, { group: 'a', enabled: true })
      expect(records.map((record) => record.id)).toEqual(['record-1'])
    })

    it('matches array tags as subsets', async () => {
      expect(
        (await storageService.findByQuery(agentContext, TestRecord, { items: ['x'] })).map((record) => record.id).sort()
      ).toEqual(['record-1', 'record-2'])

      expect(
        (await storageService.findByQuery(agentContext, TestRecord, { items: ['x', 'y'] })).map((record) => record.id)
      ).toEqual(['record-1'])
    })

    it('supports $and, $or and $not queries', async () => {
      const andRecords = await storageService.findByQuery(agentContext, TestRecord, {
        $and: [{ group: 'a' }, { enabled: true }],
      })
      expect(andRecords.map((record) => record.id)).toEqual(['record-1'])

      const orRecords = await storageService.findByQuery(agentContext, TestRecord, {
        $or: [{ group: 'b' }, { enabled: false }],
      })
      expect(orRecords.map((record) => record.id).sort()).toEqual(['record-2', 'record-3'])

      const notRecords = await storageService.findByQuery(agentContext, TestRecord, {
        $not: { group: 'a' },
      })
      expect(notRecords.map((record) => record.id)).toEqual(['record-3'])
    })

    it('supports offset and limit', async () => {
      const all = await storageService.findByQuery(agentContext, TestRecord, {})
      expect(all).toHaveLength(3)

      const limited = await storageService.findByQuery(agentContext, TestRecord, {}, { limit: 2 })
      expect(limited).toHaveLength(2)

      const offsetted = await storageService.findByQuery(agentContext, TestRecord, {}, { offset: 2 })
      expect(offsetted).toHaveLength(1)
    })
  })

  describe('multi tenancy', () => {
    it('isolates records by context correlation id', async () => {
      const record = new TestRecord({ foo: 'root-only' })
      await storageService.save(agentContext, record)

      await expect(storageService.getById(agentContextTenant, TestRecord, record.id)).rejects.toThrow(
        RecordNotFoundError
      )
      expect(await storageService.getAll(agentContextTenant, TestRecord)).toHaveLength(0)
    })

    it('deletes all records for a context', async () => {
      await storageService.save(agentContext, new TestRecord({ foo: 'root' }))
      await storageService.save(agentContextTenant, new TestRecord({ foo: 'tenant' }))

      await storageService.deleteAllForContext(agentContextTenant)

      expect(await storageService.getAll(agentContextTenant, TestRecord)).toHaveLength(0)
      expect(await storageService.getAll(agentContext, TestRecord)).toHaveLength(1)
    })

    it('deletes records of every context with deleteAll', async () => {
      await storageService.save(agentContext, new TestRecord({ foo: 'root' }))
      await storageService.save(agentContextTenant, new TestRecord({ foo: 'tenant' }))

      await storageService.deleteAll()

      expect(await storageService.getAll(agentContext, TestRecord)).toHaveLength(0)
      expect(await storageService.getAll(agentContextTenant, TestRecord)).toHaveLength(0)
    })
  })
})
