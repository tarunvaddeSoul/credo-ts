import type { AgentContext, CanBePromise, Kms } from '@credo-ts/core'

export interface BrowserKeyManagementStorage {
  get(agentContext: AgentContext, keyId: string): CanBePromise<Kms.KmsJwkPrivate | null>
  has(agentContext: AgentContext, keyId: string): CanBePromise<boolean>

  set(agentContext: AgentContext, keyId: string, jwk: Kms.KmsJwkPrivate): CanBePromise<void>

  /**
   * @returns whether the item existed and was removed
   */
  delete(agentContext: AgentContext, keyId: string): CanBePromise<boolean>

  /**
   * Remove all keys for the context. Used when an agent context (e.g. a tenant) is deleted.
   */
  deleteAllForContext?(agentContext: AgentContext): CanBePromise<void>

  /**
   * Remove all keys for every context. Used when the root agent context is deleted,
   * which also deletes all tenant contexts.
   */
  deleteAll?(): CanBePromise<void>
}
