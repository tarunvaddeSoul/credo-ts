import type { AgentContext, DependencyManager, Module } from '@credo-ts/core'
import { CredoError, InjectionSymbols, Kms, StorageUpdateService } from '@credo-ts/core'
import { BrowserIndexedDbKeyManagementStorage } from './kms/BrowserIndexedDbKeyManagementStorage'
import { BrowserKeyManagementService } from './kms/BrowserKeyManagementService'
import type { BrowserKeyManagementStorage } from './kms/BrowserKeyManagementStorage'
import { BrowserStorageService } from './storage/BrowserStorageService'

export interface BrowserWalletModuleConfigOptions {
  /**
   * Whether to register the IndexedDB backed {@link BrowserStorageService} as storage service.
   *
   * @default true
   */
  enableStorage?: boolean

  /**
   * Whether to register the {@link BrowserKeyManagementService} as key management backend.
   *
   * @default true
   */
  enableKms?: boolean

  /**
   * The IndexedDB database name to use for records and keys.
   *
   * @default 'credo'
   */
  databaseName?: string

  /**
   * Storage to use for keys. Defaults to an IndexedDB backed storage using `databaseName`.
   * Keys are stored as plaintext JWKs, so an implementation backed by a secure environment
   * can be provided here instead.
   */
  kmsStorage?: BrowserKeyManagementStorage
}

export class BrowserWalletModule implements Module {
  private enableStorage: boolean
  private enableKms: boolean
  private storageService?: BrowserStorageService
  private kmsStorage?: BrowserKeyManagementStorage

  public constructor(config: BrowserWalletModuleConfigOptions = {}) {
    this.enableStorage = config.enableStorage ?? true
    this.enableKms = config.enableKms ?? true

    if (this.enableStorage) {
      this.storageService = new BrowserStorageService({ databaseName: config.databaseName })
    }
    if (this.enableKms) {
      this.kmsStorage =
        config.kmsStorage ?? new BrowserIndexedDbKeyManagementStorage({ databaseName: config.databaseName })
    }
  }

  public register(dependencyManager: DependencyManager) {
    if (this.enableStorage && this.storageService) {
      if (dependencyManager.isRegistered(InjectionSymbols.StorageService)) {
        throw new CredoError(
          'Unable to register BrowserStorageService. There is an instance of StorageService already registered'
        )
      }
      dependencyManager.registerInstance(InjectionSymbols.StorageService, this.storageService)
    }

    if (this.enableKms && this.kmsStorage) {
      const kmsConfig = dependencyManager.resolve(Kms.KeyManagementModuleConfig)

      const browserKeyManagementService = new BrowserKeyManagementService(this.kmsStorage)
      if (kmsConfig.backends.find((backend) => backend.backend === browserKeyManagementService.backend)) {
        throw new CredoError(
          `Unable to register BrowserKeyManagementService. There is a key management backend with name '${browserKeyManagementService.backend}' already registered. If you have manually registered the BrowserKeyManagementService on the KeyManagementModule, set 'enableKms' to false in the BrowserWalletModule.`
        )
      }

      kmsConfig.registerBackend(browserKeyManagementService)
    }
  }

  public async onInitializeContext(agentContext: AgentContext): Promise<void> {
    if (!this.enableStorage || !agentContext.isRootAgentContext) return

    // A fresh store does not have a storage version record yet. Write it at the current
    // framework version, otherwise initialization assumes an old store that needs migration.
    const storageUpdateService = agentContext.resolve(StorageUpdateService)
    if (!(await storageUpdateService.hasStorageVersionRecord(agentContext))) {
      await storageUpdateService.setCurrentStorageVersion(agentContext, StorageUpdateService.frameworkStorageVersion)
    }
  }

  public async onProvisionContext(agentContext: AgentContext): Promise<void> {
    // This method is never called for the root agent context
    if (!this.enableStorage || agentContext.isRootAgentContext) return

    const storageUpdateService = agentContext.resolve(StorageUpdateService)
    await storageUpdateService.setCurrentStorageVersion(agentContext, StorageUpdateService.frameworkStorageVersion)
  }

  public async onDeleteContext(agentContext: AgentContext): Promise<void> {
    // Deleting the root agent context deletes all tenant contexts with it,
    // so all records and keys are removed (mirrors the drizzle and askar modules)
    if (agentContext.isRootAgentContext) {
      if (this.enableStorage && this.storageService) {
        await this.storageService.deleteAll()
      }

      if (this.enableKms && this.kmsStorage?.deleteAll) {
        await this.kmsStorage.deleteAll()
      }

      return
    }

    if (this.enableStorage && this.storageService) {
      await this.storageService.deleteAllForContext(agentContext)
    }

    if (this.enableKms && this.kmsStorage?.deleteAllForContext) {
      await this.kmsStorage.deleteAllForContext(agentContext)
    }
  }
}
