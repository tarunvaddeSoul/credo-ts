import type { Query, QueryOptions } from '@credo-ts/core'
import { AgentContext, injectable } from '@credo-ts/core'

import type { GroupMessagingState } from './GroupMessagingState'
import type { GroupPolicy } from './repository/GroupRecord'
import type { GroupMessageRecord } from './repository/GroupMessageRecord'
import type { GroupRecord } from './repository/GroupRecord'
import { GroupMessagingService } from './services/GroupMessagingService'

@injectable()
export class GroupMessagingApi {
  private service: GroupMessagingService
  private agentContext: AgentContext

  public constructor(service: GroupMessagingService, agentContext: AgentContext) {
    this.service = service
    this.agentContext = agentContext
  }

  // ─── Group Lifecycle ───────────────────────────────────────────────

  /**
   * Create a new group with the given members.
   *
   * @param options.name - Optional human-readable group name
   * @param options.memberConnectionIds - Connection IDs to existing pairwise connections with initial members
   * @param options.policy - Optional group policy overrides
   * @returns The created GroupRecord
   */
  public async createGroup(options: {
    name?: string
    memberConnectionIds: string[]
    policy?: Partial<GroupPolicy>
  }): Promise<GroupRecord> {
    return this.service.createGroup(this.agentContext, options)
  }

  /**
   * Add a member to an existing group. Only admins can add members.
   *
   * @param groupId - The group's URN UUID
   * @param connectionId - Connection ID to the new member
   * @returns Updated GroupRecord
   */
  public async addMember(groupId: string, connectionId: string): Promise<GroupRecord> {
    return this.service.addMember(this.agentContext, groupId, connectionId)
  }

  /**
   * Remove a member from an existing group. Only admins can remove members.
   * Triggers key rotation — removed member cannot decrypt future messages.
   *
   * @param groupId - The group's URN UUID
   * @param memberDid - DID of the member to remove
   * @returns Updated GroupRecord
   */
  public async removeMember(groupId: string, memberDid: string): Promise<GroupRecord> {
    return this.service.removeMember(this.agentContext, groupId, memberDid)
  }

  /**
   * Leave a group voluntarily. Triggers key rotation by admin.
   *
   * @param groupId - The group's URN UUID
   */
  public async leaveGroup(groupId: string): Promise<void> {
    return this.service.leaveGroup(this.agentContext, groupId)
  }

  /**
   * Manually trigger a key rotation. Only admins can rotate keys.
   *
   * @param groupId - The group's URN UUID
   * @param reason - Reason for rotation (e.g., 'scheduled', 'compromise')
   * @returns Updated GroupRecord
   */
  public async rotateKey(groupId: string, reason?: string): Promise<GroupRecord> {
    return this.service.rotateKey(this.agentContext, groupId, reason)
  }

  // ─── Messaging ─────────────────────────────────────────────────────

  /**
   * Send a message to all members of a group.
   * Encrypts once with the Group Content Key (O(1)), then fans out delivery.
   *
   * @param groupId - The group's URN UUID
   * @param content - Message content string
   * @returns The created GroupMessageRecord
   */
  public async sendMessage(groupId: string, content: string): Promise<GroupMessageRecord> {
    return this.service.sendMessage(this.agentContext, groupId, content)
  }

  // ─── Queries ───────────────────────────────────────────────────────

  /**
   * Get all groups, optionally filtered by state.
   */
  public async getGroups(query?: { state?: GroupMessagingState }) {
    return this.service.findAllGroups(this.agentContext, query)
  }

  /**
   * Get a group by its internal record ID.
   */
  public async getGroupById(id: string): Promise<GroupRecord> {
    return this.service.getGroupById(this.agentContext, id)
  }

  /**
   * Get a group by its group URN UUID.
   */
  public async getGroupByGroupId(groupId: string): Promise<GroupRecord> {
    return this.service.getGroupByGroupId(this.agentContext, groupId)
  }

  /**
   * Get all messages in a group, ordered by creation time.
   */
  public async getMessages(groupId: string): Promise<GroupMessageRecord[]> {
    return this.service.getMessages(this.agentContext, groupId)
  }

  /**
   * Get a message by its internal record ID.
   */
  public async getMessageById(messageId: string): Promise<GroupMessageRecord> {
    return this.service.getMessageById(this.agentContext, messageId)
  }
}
