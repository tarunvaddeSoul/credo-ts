import type { AgentDependencies } from '@credo-ts/core'

import { EventEmitter } from 'events'

import { BrowserFileSystem } from './BrowserFileSystem'

export { BrowserWalletModule, type BrowserWalletModuleConfigOptions } from './BrowserWalletModule'
export { BrowserIndexedDbKeyManagementStorage } from './kms/BrowserIndexedDbKeyManagementStorage'
export { BrowserInMemoryKeyManagementStorage } from './kms/BrowserInMemoryKeyManagementStorage'
export { BrowserKeyManagementService } from './kms/BrowserKeyManagementService'
export type { BrowserKeyManagementStorage } from './kms/BrowserKeyManagementStorage'
export { BrowserStorageService } from './storage/BrowserStorageService'
export { BrowserFileSystem }

// Browser fetch must keep its `this` binding, otherwise calls fail with 'Illegal invocation'
const fetch = globalThis.fetch.bind(globalThis) as AgentDependencies['fetch']
const WebSocket = globalThis.WebSocket as unknown as AgentDependencies['WebSocketClass']

const agentDependencies: AgentDependencies = {
  FileSystem: BrowserFileSystem,
  fetch,
  EventEmitterClass: EventEmitter,
  WebSocketClass: WebSocket,
}

export { agentDependencies }
