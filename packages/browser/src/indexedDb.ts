import { CredoError } from '@credo-ts/core'

// Minimal structural types for the IndexedDB API surface used by this package.
// The repo type-checks without DOM lib types, and these avoid conflicts with
// lib.dom in consuming applications.

export interface IdbRequest<T = unknown> {
  readonly result: T
  readonly error: { message?: string } | null
  onsuccess: (() => void) | null
  onerror: (() => void) | null
}

export interface IdbOpenRequest extends IdbRequest<IdbDatabase> {
  onupgradeneeded: (() => void) | null
}

export interface IdbIndex {
  getAll(query?: unknown): IdbRequest<unknown[]>
}

export interface IdbObjectStore {
  get(key: unknown): IdbRequest
  add(value: unknown): IdbRequest
  put(value: unknown): IdbRequest
  delete(key: unknown): IdbRequest
  clear(): IdbRequest
  createIndex(name: string, keyPath: string | string[]): unknown
  index(name: string): IdbIndex
}

export interface IdbTransaction {
  oncomplete: (() => void) | null
  onerror: (() => void) | null
  onabort: (() => void) | null
  readonly error: { message?: string } | null
  objectStore(name: string): IdbObjectStore
}

export interface IdbDatabase {
  readonly objectStoreNames: { contains(name: string): boolean }
  onclose: (() => void) | null
  onversionchange: (() => void) | null
  transaction(storeNames: string | string[], mode?: 'readonly' | 'readwrite'): IdbTransaction
  createObjectStore(name: string, options?: { keyPath?: string | string[] }): IdbObjectStore
  close(): void
}

interface IdbFactory {
  open(name: string, version?: number): IdbOpenRequest
}

interface IdbKeyRangeConstructor {
  bound(lower: unknown, upper: unknown): unknown
}

export const RECORDS_OBJECT_STORE = 'records'
export const KEYS_OBJECT_STORE = 'keys'
const DATABASE_VERSION = 1

function getIndexedDbFactory(): IdbFactory {
  const factory = (globalThis as { indexedDB?: IdbFactory }).indexedDB
  if (!factory) {
    throw new CredoError(
      'IndexedDB is not available in this environment. The @credo-ts/browser storage requires a browser environment with IndexedDB support.'
    )
  }

  return factory
}

/**
 * A key range matching every entry of a context, for object stores with a
 * `[contextCorrelationId, x]` key path. In IndexedDB key ordering an array sorts
 * after every string, so `[contextCorrelationId, []]` is an upper bound for all
 * `[contextCorrelationId, string]` keys.
 */
export function contextKeyRange(contextCorrelationId: string): unknown {
  const keyRange = (globalThis as { IDBKeyRange?: IdbKeyRangeConstructor }).IDBKeyRange
  if (!keyRange) {
    throw new CredoError('IDBKeyRange is not available in this environment.')
  }

  return keyRange.bound([contextCorrelationId], [contextCorrelationId, []])
}

export function promisifyRequest<T>(request: IdbRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(new CredoError(`IndexedDB request failed: ${request.error?.message}`))
  })
}

export function transactionDone(transaction: IdbTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(new CredoError(`IndexedDB transaction failed: ${transaction.error?.message}`))
    transaction.onabort = () => reject(new CredoError(`IndexedDB transaction aborted: ${transaction.error?.message}`))
  })
}

/**
 * Opens the credo IndexedDB database, creating the object stores when needed.
 * Both the storage service and the key management storage use the same database,
 * so the full schema is always created here.
 *
 * `onConnectionClosed` is invoked when the connection can no longer be used
 * (browser-forced close, or closed in response to a versionchange request),
 * so callers can drop their cached connection and reopen on the next operation.
 */
export function openCredoDatabase(databaseName: string, onConnectionClosed?: () => void): Promise<IdbDatabase> {
  const request = getIndexedDbFactory().open(databaseName, DATABASE_VERSION)

  request.onupgradeneeded = () => {
    const database = request.result

    if (!database.objectStoreNames.contains(RECORDS_OBJECT_STORE)) {
      const recordsStore = database.createObjectStore(RECORDS_OBJECT_STORE, {
        keyPath: ['contextCorrelationId', 'id'],
      })
      recordsStore.createIndex('contextType', ['contextCorrelationId', 'type'])
    }

    if (!database.objectStoreNames.contains(KEYS_OBJECT_STORE)) {
      database.createObjectStore(KEYS_OBJECT_STORE, { keyPath: ['contextCorrelationId', 'keyId'] })
    }
  }

  return promisifyRequest(request).then((database) => {
    // Browsers can force-close connections (e.g. Safari under memory pressure)
    database.onclose = () => onConnectionClosed?.()

    // Another context (tab, extension page) wants to upgrade or delete the database.
    // Close this connection, otherwise that request is blocked indefinitely.
    database.onversionchange = () => {
      onConnectionClosed?.()
      database.close()
    }

    return database
  })
}
