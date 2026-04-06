import type { AgentContext } from '@credo-ts/core'
import { CredoError, EventEmitter, injectable, utils } from '@credo-ts/core'

import { DidCommMessageSender } from '../../../DidCommMessageSender'
import { DidCommOutboundMessageContext } from '../../../models'
import { DidCommConnectionService } from '../../connections/services'
import { GroupMessagingEventTypes } from '../GroupMessagingEvents'
import type {
  GroupCreatedEvent,
  GroupKeyRotatedEvent,
  GroupMemberAddedEvent,
  GroupMemberLeftEvent,
  GroupMemberRemovedEvent,
  GroupMessageReceivedEvent,
} from '../GroupMessagingEvents'
import { GroupMessagingRole } from '../GroupMessagingRole'
import { GroupMessagingState } from '../GroupMessagingState'
import {
  GroupAddMemberMessage,
  GroupCreateAckMessage,
  GroupCreateMessage,
  GroupDeliveryMessage,
  GroupKeyRotateMessage,
  GroupLeaveAckMessage,
  GroupLeaveMessage,
  GroupRemoveMemberMessage,
} from '../messages'
import { DEFAULT_GROUP_POLICY, GroupRecord, type GroupMemberEntry, type GroupPolicy } from '../repository/GroupRecord'
import { GroupMessageRecord } from '../repository/GroupMessageRecord'
import { GroupMessageRepository } from '../repository/GroupMessageRepository'
import { GroupRepository } from '../repository/GroupRepository'
import { GroupCryptoService } from './GroupCryptoService'

@injectable()
export class GroupMessagingService {
  private groupRepository: GroupRepository
  private groupMessageRepository: GroupMessageRepository
  private cryptoService: GroupCryptoService
  private connectionService: DidCommConnectionService
  private messageSender: DidCommMessageSender
  private eventEmitter: EventEmitter

  public constructor(
    groupRepository: GroupRepository,
    groupMessageRepository: GroupMessageRepository,
    cryptoService: GroupCryptoService,
    connectionService: DidCommConnectionService,
    messageSender: DidCommMessageSender,
    eventEmitter: EventEmitter
  ) {
    this.groupRepository = groupRepository
    this.groupMessageRepository = groupMessageRepository
    this.cryptoService = cryptoService
    this.connectionService = connectionService
    this.messageSender = messageSender
    this.eventEmitter = eventEmitter
  }

  // ─── Group Creation ────────────────────────────────────────────────

  public async createGroup(
    agentContext: AgentContext,
    options: {
      name?: string
      memberConnectionIds: string[]
      policy?: Partial<GroupPolicy>
    }
  ): Promise<GroupRecord> {
    const groupId = `urn:uuid:${utils.uuid()}`
    const gck = this.cryptoService.generateGck(agentContext)
    const policy = { ...DEFAULT_GROUP_POLICY, ...options.policy }

    // Resolve connections and build member list — all must be DIDComm v2
    const myDid = await this.getAgentDid(agentContext, options.memberConnectionIds[0])
    const members: GroupMemberEntry[] = [{ did: myDid, role: 'admin' }]
    const memberConnectionMap: Record<string, string> = {}

    for (const connectionId of options.memberConnectionIds) {
      const connection = await this.connectionService.getById(agentContext, connectionId)
      if (!connection.theirDid) {
        throw new CredoError(`Connection ${connectionId} does not have a theirDid`)
      }
      if (connection.didcommVersion !== 'v2') {
        throw new CredoError(
          `Group messaging requires DIDComm v2 connections. Connection ${connectionId} uses ${connection.didcommVersion ?? 'v1'}.`
        )
      }
      members.push({ did: connection.theirDid, role: 'member' })
      memberConnectionMap[connection.theirDid] = connectionId
    }

    // Compute epoch hash for epoch 0 (genesis)
    const epochHash = this.cryptoService.computeEpochHash(undefined, 0, members, gck)

    // Create local group record
    const groupRecord = new GroupRecord({
      groupId,
      ourDid: myDid,
      name: options.name,
      epoch: 0,
      role: GroupMessagingRole.Admin,
      state: GroupMessagingState.Active,
      members,
      gck,
      epochHash,
      policy,
      messageCount: 0,
      lastKeyRotation: new Date().toISOString(),
      memberConnectionMap,
    })
    await this.groupRepository.save(agentContext, groupRecord)

    // Send create message to each member via pairwise authcrypt
    const createMessage = new GroupCreateMessage({
      groupId,
      name: options.name,
      epoch: 0,
      members: members.map((m) => ({ did: m.did, role: m.role })),
      gck: { k: gck, alg: 'A256GCM' },
      policy: {
        memberCanInvite: policy.memberCanInvite,
        memberCanLeave: policy.memberCanLeave,
        rotationPeriodSeconds: policy.rotationPeriodSeconds,
        rotationPeriodMessages: policy.rotationPeriodMessages,
        maxMembers: policy.maxMembers,
      },
    })

    for (const connectionId of options.memberConnectionIds) {
      createMessage.from = undefined
      createMessage.to = undefined
      const connection = await this.connectionService.getById(agentContext, connectionId)
      const outbound = new DidCommOutboundMessageContext(createMessage, {
        agentContext,
        connection,
      })
      await this.messageSender.sendMessage(outbound)
    }

    this.eventEmitter.emit<GroupCreatedEvent>(agentContext, {
      type: GroupMessagingEventTypes.GroupCreated,
      payload: { groupRecord: groupRecord.clone() },
    })

    return groupRecord
  }

  // ─── Process Incoming Create ───────────────────────────────────────

  public async processCreate(
    agentContext: AgentContext,
    message: GroupCreateMessage,
    senderDid: string,
    ourDid: string,
    senderConnectionId: string
  ): Promise<GroupRecord> {
    const policy: GroupPolicy = message.policy
      ? {
          memberCanInvite: message.policy.memberCanInvite ?? DEFAULT_GROUP_POLICY.memberCanInvite,
          memberCanLeave: message.policy.memberCanLeave ?? DEFAULT_GROUP_POLICY.memberCanLeave,
          rotationPeriodSeconds: message.policy.rotationPeriodSeconds ?? DEFAULT_GROUP_POLICY.rotationPeriodSeconds,
          rotationPeriodMessages: message.policy.rotationPeriodMessages ?? DEFAULT_GROUP_POLICY.rotationPeriodMessages,
          maxMembers: message.policy.maxMembers ?? DEFAULT_GROUP_POLICY.maxMembers,
        }
      : DEFAULT_GROUP_POLICY

    const members = message.members.map((m) => ({ did: m.did, role: m.role as 'admin' | 'member' }))

    // Compute epoch hash to establish chain integrity from epoch 0
    const epochHash = this.cryptoService.computeEpochHash(undefined, message.epoch, members, message.gck.k)

    const groupRecord = new GroupRecord({
      groupId: message.groupId,
      ourDid,
      name: message.name,
      epoch: message.epoch,
      role: GroupMessagingRole.Member,
      state: GroupMessagingState.Active,
      members,
      gck: message.gck.k,
      epochHash,
      policy,
      messageCount: 0,
      lastKeyRotation: new Date().toISOString(),
      adminConnectionId: senderConnectionId,
    })
    await this.groupRepository.save(agentContext, groupRecord)

    this.eventEmitter.emit<GroupCreatedEvent>(agentContext, {
      type: GroupMessagingEventTypes.GroupCreated,
      payload: { groupRecord: groupRecord.clone() },
    })

    return groupRecord
  }

  // ─── Send Group Message ────────────────────────────────────────────

  public async sendMessage(agentContext: AgentContext, groupId: string, content: string): Promise<GroupMessageRecord> {
    const groupRecord = await this.getGroupByGroupId(agentContext, groupId)

    if (groupRecord.state !== GroupMessagingState.Active) {
      throw new CredoError(`Cannot send message to group ${groupId} in state ${groupRecord.state}`)
    }

    const myDid = this.getMyDidFromGroup(agentContext, groupRecord)

    // Build the inner plaintext as JSON
    const innerPlaintext = JSON.stringify({
      id: utils.uuid(),
      type: 'https://didcomm.org/group-messaging/1.0/message',
      from: myDid,
      created_time: Math.floor(Date.now() / 1000),
      body: { content },
      thid: groupId,
    })

    // GCK encrypt — O(1) regardless of group size
    const { ciphertext, iv, tag } = this.cryptoService.encrypt(
      innerPlaintext,
      groupRecord.gck,
      groupId,
      groupRecord.epoch,
      myDid
    )

    // Build delivery envelope
    const delivery = new GroupDeliveryMessage({
      groupId,
      epoch: groupRecord.epoch,
      sender: myDid,
      ciphertext,
      iv,
      tag,
    })

    // Fan out to each member via known connections (from memberConnectionMap)
    await this.fanOutDelivery(agentContext, groupRecord, delivery, myDid)

    // Save locally
    const messageRecord = new GroupMessageRecord({
      groupId,
      messageId: delivery.id,
      senderDid: myDid,
      epoch: groupRecord.epoch,
      content,
      sentTime: new Date().toISOString(),
    })
    await this.groupMessageRepository.save(agentContext, messageRecord)

    // Update message count
    groupRecord.messageCount += 1
    await this.groupRepository.update(agentContext, groupRecord)

    return messageRecord
  }

  // ─── Process Incoming Delivery ─────────────────────────────────────

  public async processDelivery(
    agentContext: AgentContext,
    message: GroupDeliveryMessage,
    envelopeSenderDid?: string
  ): Promise<GroupMessageRecord | undefined> {
    const logger = agentContext.config.logger

    const groupRecord = await this.findGroupByGroupId(agentContext, message.groupId)
    if (!groupRecord) return undefined // silently discard per spec

    if (groupRecord.state !== GroupMessagingState.Active) return undefined

    // Verify sender is a group member
    if (!groupRecord.members.some((m) => m.did === message.sender)) {
      logger.warn(`[GroupMessaging] Delivery from non-member sender ${message.sender} for group ${message.groupId}`)
      return undefined
    }

    // Note: Envelope sender verification is intentionally not checked against the
    // member DID list because peer:4 pairwise DIDs differ per connection.
    // Security is ensured by: (1) DIDComm authcrypt at transport layer,
    // (2) GCK AEAD binding sender DID in AAD, (3) member list check above.

    // Replay protection: check for duplicate message IDs via indexed tag query.
    // Wrapped in try-catch because concurrent Askar session access can cause
    // transient "Invalid resource handle" errors in high-throughput scenarios.
    try {
      const existing = await this.groupMessageRepository.findByQuery(agentContext, { messageId: message.id })
      if (existing.length > 0) {
        logger.debug(`[GroupMessaging] Duplicate message ${message.id} discarded`)
        return undefined
      }
    } catch (error) {
      logger.warn(`[GroupMessaging] Replay check query failed for message ${message.id}, proceeding: ${error}`)
    }

    // Determine which GCK to use (current or previous epoch grace window)
    let gck: string | undefined
    if (message.epoch === groupRecord.epoch) {
      gck = groupRecord.gck
    } else if (message.epoch === groupRecord.epoch - 1 && groupRecord.previousGck) {
      gck = groupRecord.previousGck
    }
    if (!gck) {
      logger.warn(`[GroupMessaging] No GCK for epoch ${message.epoch} (current: ${groupRecord.epoch})`)
      return undefined
    }

    // Decrypt
    let plaintext: string
    try {
      plaintext = this.cryptoService.decrypt(
        message.ciphertext,
        message.iv,
        message.tag,
        gck,
        message.groupId,
        message.epoch,
        message.sender
      )
    } catch (error) {
      logger.warn(`[GroupMessaging] Decryption failed for message ${message.id}: ${error}`)
      return undefined
    }
    const innerMessage = JSON.parse(plaintext)
    const content = innerMessage.body?.content ?? ''

    const messageRecord = new GroupMessageRecord({
      groupId: message.groupId,
      messageId: message.id,
      senderDid: message.sender,
      epoch: message.epoch,
      content,
      sentTime: new Date().toISOString(),
    })

    // Retry save/update to handle transient Askar session contention that can
    // occur when the transport delivers multiple messages concurrently.
    await this.retrySave(agentContext, messageRecord)

    groupRecord.messageCount += 1
    await this.retryUpdate(agentContext, groupRecord)

    this.eventEmitter.emit<GroupMessageReceivedEvent>(agentContext, {
      type: GroupMessagingEventTypes.GroupMessageReceived,
      payload: {
        groupRecord: groupRecord.clone(),
        messageRecord: messageRecord.clone(),
      },
    })

    // Admin forwarding: if we are the admin, forward the delivery to members
    // who the original sender can't reach directly (hub-and-spoke model).
    // This enables communication even when members lack pairwise connections.
    if (groupRecord.role === GroupMessagingRole.Admin) {
      const myDid = this.getMyDidFromGroup(agentContext, groupRecord)
      await this.fanOutDelivery(agentContext, groupRecord, message, myDid, [message.sender])
    }

    return messageRecord
  }

  // ─── Add Member ────────────────────────────────────────────────────

  public async addMember(
    agentContext: AgentContext,
    groupId: string,
    connectionId: string
  ): Promise<GroupRecord> {
    const groupRecord = await this.getGroupByGroupId(agentContext, groupId)

    if (groupRecord.role !== GroupMessagingRole.Admin) {
      throw new CredoError('Only admins can add members')
    }

    const connection = await this.connectionService.getById(agentContext, connectionId)
    if (!connection.theirDid) {
      throw new CredoError(`Connection ${connectionId} does not have a theirDid`)
    }

    const newMemberDid = connection.theirDid
    if (groupRecord.members.some((m) => m.did === newMemberDid)) {
      throw new CredoError(`${newMemberDid} is already a member of group ${groupId}`)
    }

    if (groupRecord.members.length >= groupRecord.policy.maxMembers) {
      throw new CredoError(`Group ${groupId} has reached max members (${groupRecord.policy.maxMembers})`)
    }

    // New epoch
    const newEpoch = groupRecord.epoch + 1
    const newGck = this.cryptoService.generateGck(agentContext)
    const newMembers: GroupMemberEntry[] = [...groupRecord.members, { did: newMemberDid, role: 'member' }]
    const epochHash = this.cryptoService.computeEpochHash(groupRecord.epochHash, newEpoch, newMembers, newGck)

    // Send add-member to existing members
    const addMessage = new GroupAddMemberMessage({
      groupId,
      epoch: newEpoch,
      added: [{ did: newMemberDid, role: 'member' }],
      members: newMembers.map((m) => ({ did: m.did, role: m.role })),
      gck: { k: newGck, alg: 'A256GCM' },
      epochHash,
    })

    const myDid = this.getMyDidFromGroup(agentContext, groupRecord)
    for (const member of groupRecord.members) {
      if (member.did === myDid) continue
      const connId = groupRecord.memberConnectionMap[member.did]
      if (!connId) continue
      addMessage.from = undefined
      addMessage.to = undefined
      const conn = await this.connectionService.getById(agentContext, connId)
      await this.messageSender.sendMessage(
        new DidCommOutboundMessageContext(addMessage, { agentContext, connection: conn })
      )
    }

    // Send create to new member (they get the full group state at the new epoch)
    const createForNew = new GroupCreateMessage({
      groupId,
      name: groupRecord.name,
      epoch: newEpoch,
      members: newMembers.map((m) => ({ did: m.did, role: m.role })),
      gck: { k: newGck, alg: 'A256GCM' },
      policy: {
        memberCanInvite: groupRecord.policy.memberCanInvite,
        memberCanLeave: groupRecord.policy.memberCanLeave,
        rotationPeriodSeconds: groupRecord.policy.rotationPeriodSeconds,
        rotationPeriodMessages: groupRecord.policy.rotationPeriodMessages,
        maxMembers: groupRecord.policy.maxMembers,
      },
    })
    await this.messageSender.sendMessage(
      new DidCommOutboundMessageContext(createForNew, { agentContext, connection })
    )

    // Update local state — add new member to connection map
    groupRecord.memberConnectionMap[newMemberDid] = connectionId
    groupRecord.previousGck = groupRecord.gck
    groupRecord.gck = newGck
    groupRecord.epoch = newEpoch
    groupRecord.members = newMembers
    groupRecord.epochHash = epochHash
    groupRecord.messageCount = 0
    groupRecord.lastKeyRotation = new Date().toISOString()
    await this.groupRepository.update(agentContext, groupRecord)

    this.eventEmitter.emit<GroupMemberAddedEvent>(agentContext, {
      type: GroupMessagingEventTypes.GroupMemberAdded,
      payload: { groupRecord: groupRecord.clone(), addedDids: [newMemberDid] },
    })

    return groupRecord
  }

  // ─── Process Incoming Add Member ───────────────────────────────────

  public async processAddMember(
    agentContext: AgentContext,
    message: GroupAddMemberMessage
  ): Promise<GroupRecord> {
    const groupRecord = await this.getGroupByGroupId(agentContext, message.groupId)

    // Verify epoch hash
    if (
      !this.cryptoService.verifyEpochHash(
        message.epochHash,
        groupRecord.epochHash,
        message.epoch,
        message.members,
        message.gck.k
      )
    ) {
      throw new CredoError(`Epoch hash mismatch for group ${message.groupId} epoch ${message.epoch}`)
    }

    groupRecord.previousGck = groupRecord.gck
    groupRecord.gck = message.gck.k
    groupRecord.epoch = message.epoch
    groupRecord.members = message.members.map((m) => ({ did: m.did, role: m.role }))
    groupRecord.epochHash = message.epochHash
    groupRecord.messageCount = 0
    groupRecord.lastKeyRotation = new Date().toISOString()
    await this.groupRepository.update(agentContext, groupRecord)

    this.eventEmitter.emit<GroupMemberAddedEvent>(agentContext, {
      type: GroupMessagingEventTypes.GroupMemberAdded,
      payload: { groupRecord: groupRecord.clone(), addedDids: message.added.map((a) => a.did) },
    })

    return groupRecord
  }

  // ─── Remove Member ─────────────────────────────────────────────────

  public async removeMember(
    agentContext: AgentContext,
    groupId: string,
    memberDid: string
  ): Promise<GroupRecord> {
    const groupRecord = await this.getGroupByGroupId(agentContext, groupId)

    if (groupRecord.role !== GroupMessagingRole.Admin) {
      throw new CredoError('Only admins can remove members')
    }

    const myDid = this.getMyDidFromGroup(agentContext, groupRecord)
    if (memberDid === myDid) {
      throw new CredoError('Admin cannot remove themselves. Use leaveGroup instead.')
    }

    // New epoch
    const newEpoch = groupRecord.epoch + 1
    const newGck = this.cryptoService.generateGck(agentContext)
    const newMembers = groupRecord.members.filter((m) => m.did !== memberDid)
    const epochHash = this.cryptoService.computeEpochHash(groupRecord.epochHash, newEpoch, newMembers, newGck)

    // Send remove-member with new GCK to remaining members
    const removeMessage = new GroupRemoveMemberMessage({
      groupId,
      epoch: newEpoch,
      removed: [memberDid],
      members: newMembers.map((m) => ({ did: m.did, role: m.role })),
      gck: { k: newGck, alg: 'A256GCM' },
      epochHash,
    })

    for (const member of newMembers) {
      if (member.did === myDid) continue
      const connId = groupRecord.memberConnectionMap[member.did]
      if (!connId) continue
      removeMessage.from = undefined
      removeMessage.to = undefined
      const conn = await this.connectionService.getById(agentContext, connId)
      await this.messageSender.sendMessage(
        new DidCommOutboundMessageContext(removeMessage, { agentContext, connection: conn })
      )
    }

    // Send notification to removed member (NO gck, NO members, NO epochHash)
    const removeNotification = new GroupRemoveMemberMessage({
      groupId,
      removed: [memberDid],
    })
    const removedConnId = groupRecord.memberConnectionMap[memberDid]
    if (removedConnId) {
      const removedConn = await this.connectionService.getById(agentContext, removedConnId)
      await this.messageSender.sendMessage(
        new DidCommOutboundMessageContext(removeNotification, { agentContext, connection: removedConn })
      )
    }

    // Update local state — remove from connection map
    delete groupRecord.memberConnectionMap[memberDid]
    groupRecord.previousGck = groupRecord.gck
    groupRecord.gck = newGck
    groupRecord.epoch = newEpoch
    groupRecord.members = newMembers
    groupRecord.epochHash = epochHash
    groupRecord.messageCount = 0
    groupRecord.lastKeyRotation = new Date().toISOString()
    await this.groupRepository.update(agentContext, groupRecord)

    this.eventEmitter.emit<GroupMemberRemovedEvent>(agentContext, {
      type: GroupMessagingEventTypes.GroupMemberRemoved,
      payload: { groupRecord: groupRecord.clone(), removedDids: [memberDid] },
    })

    return groupRecord
  }

  // ─── Process Incoming Remove Member ────────────────────────────────

  public async processRemoveMember(
    agentContext: AgentContext,
    message: GroupRemoveMemberMessage,
    myDid: string
  ): Promise<GroupRecord> {
    const groupRecord = await this.getGroupByGroupId(agentContext, message.groupId)

    // Am I being removed?
    if (message.removed.includes(myDid)) {
      groupRecord.state = GroupMessagingState.Left
      await this.groupRepository.update(agentContext, groupRecord)
      return groupRecord
    }

    // I'm staying — verify and update
    if (!message.gck || !message.members || !message.epochHash || message.epoch === undefined) {
      throw new CredoError('Remove-member message for remaining member missing required fields')
    }

    if (
      !this.cryptoService.verifyEpochHash(
        message.epochHash,
        groupRecord.epochHash,
        message.epoch,
        message.members,
        message.gck.k
      )
    ) {
      throw new CredoError(`Epoch hash mismatch for group ${message.groupId}`)
    }

    groupRecord.previousGck = groupRecord.gck
    groupRecord.gck = message.gck.k
    groupRecord.epoch = message.epoch
    groupRecord.members = message.members.map((m) => ({ did: m.did, role: m.role }))
    groupRecord.epochHash = message.epochHash
    groupRecord.messageCount = 0
    groupRecord.lastKeyRotation = new Date().toISOString()
    await this.groupRepository.update(agentContext, groupRecord)

    this.eventEmitter.emit<GroupMemberRemovedEvent>(agentContext, {
      type: GroupMessagingEventTypes.GroupMemberRemoved,
      payload: { groupRecord: groupRecord.clone(), removedDids: message.removed },
    })

    return groupRecord
  }

  // ─── Leave Group ───────────────────────────────────────────────────

  public async leaveGroup(agentContext: AgentContext, groupId: string): Promise<void> {
    const groupRecord = await this.getGroupByGroupId(agentContext, groupId)
    const myDid = this.getMyDidFromGroup(agentContext, groupRecord)

    const leaveMessage = new GroupLeaveMessage({ groupId })

    if (groupRecord.role === GroupMessagingRole.Admin) {
      // Admin leaving: notify all members via connectionMap
      for (const member of groupRecord.members) {
        if (member.did === myDid) continue
        const connId = groupRecord.memberConnectionMap[member.did]
        if (!connId) continue
        leaveMessage.from = undefined
        leaveMessage.to = undefined
        const conn = await this.connectionService.getById(agentContext, connId)
        await this.messageSender.sendMessage(
          new DidCommOutboundMessageContext(leaveMessage, { agentContext, connection: conn })
        )
      }
    } else if (groupRecord.adminConnectionId) {
      // Member leaving: notify admin only
      const conn = await this.connectionService.getById(agentContext, groupRecord.adminConnectionId)
      await this.messageSender.sendMessage(
        new DidCommOutboundMessageContext(leaveMessage, { agentContext, connection: conn })
      )
    }

    groupRecord.state = GroupMessagingState.Left
    await this.groupRepository.update(agentContext, groupRecord)

    this.eventEmitter.emit<GroupMemberLeftEvent>(agentContext, {
      type: GroupMessagingEventTypes.GroupMemberLeft,
      payload: { groupRecord: groupRecord.clone(), memberDid: myDid },
    })
  }

  // ─── Process Incoming Leave ────────────────────────────────────────

  public async processLeave(
    agentContext: AgentContext,
    message: GroupLeaveMessage,
    senderDid: string
  ): Promise<GroupRecord> {
    const groupRecord = await this.getGroupByGroupId(agentContext, message.groupId)

    // If I'm admin, trigger key rotation (remove the leaving member)
    if (groupRecord.role === GroupMessagingRole.Admin) {
      const connId = groupRecord.memberConnectionMap[senderDid]
      if (connId) {
        const conn = await this.connectionService.getById(agentContext, connId)
        const ack = new GroupLeaveAckMessage({
          groupId: message.groupId,
          status: 'acknowledged',
          threadId: message.id,
        })
        await this.messageSender.sendMessage(
          new DidCommOutboundMessageContext(ack, { agentContext, connection: conn })
        )
      }

      // Remove them and rotate key
      return await this.removeMember(agentContext, message.groupId, senderDid)
    }

    this.eventEmitter.emit<GroupMemberLeftEvent>(agentContext, {
      type: GroupMessagingEventTypes.GroupMemberLeft,
      payload: { groupRecord: groupRecord.clone(), memberDid: senderDid },
    })

    return groupRecord
  }

  // ─── Key Rotation ──────────────────────────────────────────────────

  public async rotateKey(
    agentContext: AgentContext,
    groupId: string,
    reason: string = 'scheduled'
  ): Promise<GroupRecord> {
    const groupRecord = await this.getGroupByGroupId(agentContext, groupId)

    if (groupRecord.role !== GroupMessagingRole.Admin) {
      throw new CredoError('Only admins can rotate keys')
    }

    const newEpoch = groupRecord.epoch + 1
    const newGck = this.cryptoService.generateGck(agentContext)
    const epochHash = this.cryptoService.computeEpochHash(
      groupRecord.epochHash,
      newEpoch,
      groupRecord.members,
      newGck
    )

    const rotateMessage = new GroupKeyRotateMessage({
      groupId,
      epoch: newEpoch,
      reason,
      gck: { k: newGck, alg: 'A256GCM' },
      epochHash,
    })

    const myDid = this.getMyDidFromGroup(agentContext, groupRecord)
    for (const member of groupRecord.members) {
      if (member.did === myDid) continue
      const connId = groupRecord.memberConnectionMap[member.did]
      if (!connId) continue
      rotateMessage.from = undefined
      rotateMessage.to = undefined
      const conn = await this.connectionService.getById(agentContext, connId)
      await this.messageSender.sendMessage(
        new DidCommOutboundMessageContext(rotateMessage, { agentContext, connection: conn })
      )
    }

    groupRecord.previousGck = groupRecord.gck
    groupRecord.gck = newGck
    groupRecord.epoch = newEpoch
    groupRecord.epochHash = epochHash
    groupRecord.messageCount = 0
    groupRecord.lastKeyRotation = new Date().toISOString()
    await this.groupRepository.update(agentContext, groupRecord)

    this.eventEmitter.emit<GroupKeyRotatedEvent>(agentContext, {
      type: GroupMessagingEventTypes.GroupKeyRotated,
      payload: { groupRecord: groupRecord.clone(), reason },
    })

    return groupRecord
  }

  // ─── Process Incoming Key Rotate ───────────────────────────────────

  public async processKeyRotate(
    agentContext: AgentContext,
    message: GroupKeyRotateMessage
  ): Promise<GroupRecord> {
    const groupRecord = await this.getGroupByGroupId(agentContext, message.groupId)

    if (
      !this.cryptoService.verifyEpochHash(
        message.epochHash,
        groupRecord.epochHash,
        message.epoch,
        groupRecord.members,
        message.gck.k
      )
    ) {
      throw new CredoError(`Epoch hash mismatch for key rotation in group ${message.groupId}`)
    }

    groupRecord.previousGck = groupRecord.gck
    groupRecord.gck = message.gck.k
    groupRecord.epoch = message.epoch
    groupRecord.epochHash = message.epochHash
    groupRecord.messageCount = 0
    groupRecord.lastKeyRotation = new Date().toISOString()
    await this.groupRepository.update(agentContext, groupRecord)

    this.eventEmitter.emit<GroupKeyRotatedEvent>(agentContext, {
      type: GroupMessagingEventTypes.GroupKeyRotated,
      payload: { groupRecord: groupRecord.clone(), reason: message.reason ?? 'unknown' },
    })

    return groupRecord
  }

  // ─── Queries ───────────────────────────────────────────────────────

  public async getGroupByGroupId(agentContext: AgentContext, groupId: string): Promise<GroupRecord> {
    return this.groupRepository.getSingleByQuery(agentContext, { groupId })
  }

  public async findGroupByGroupId(agentContext: AgentContext, groupId: string): Promise<GroupRecord | null> {
    return this.groupRepository.findSingleByQuery(agentContext, { groupId })
  }

  public async getGroupById(agentContext: AgentContext, id: string): Promise<GroupRecord> {
    return this.groupRepository.getById(agentContext, id)
  }

  public async findAllGroups(agentContext: AgentContext, query: { state?: GroupMessagingState } = {}) {
    return this.groupRepository.findByQuery(agentContext, query)
  }

  public async getMessages(agentContext: AgentContext, groupId: string) {
    return this.groupMessageRepository.findByQuery(agentContext, { groupId })
  }

  public async getMessageById(agentContext: AgentContext, id: string): Promise<GroupMessageRecord> {
    return this.groupMessageRepository.getById(agentContext, id)
  }

  // ─── Helpers ───────────────────────────────────────────────────────

  private getMyDidFromGroup(_agentContext: AgentContext, groupRecord: GroupRecord): string {
    return groupRecord.ourDid
  }

  private async getAgentDid(agentContext: AgentContext, connectionId: string): Promise<string> {
    const connection = await this.connectionService.getById(agentContext, connectionId)
    if (!connection.did) {
      throw new CredoError(`Connection ${connectionId} does not have our DID`)
    }
    return connection.did
  }

  /**
   * Fan out a delivery message to group members using the memberConnectionMap.
   * Only sends to members we have a known connectionId for.
   *
   * @param excludeDids - additional DIDs to exclude (e.g., the original sender during admin forwarding)
   */
  private async fanOutDelivery(
    agentContext: AgentContext,
    groupRecord: GroupRecord,
    delivery: GroupDeliveryMessage,
    myDid: string,
    excludeDids: string[] = []
  ): Promise<void> {
    if (groupRecord.role === GroupMessagingRole.Admin) {
      // Admin: send directly to each member via connectionMap
      for (const member of groupRecord.members) {
        if (member.did === myDid) continue
        if (excludeDids.includes(member.did)) continue

        const connectionId = groupRecord.memberConnectionMap[member.did]
        if (!connectionId) continue

        try {
          // Clear DIDComm v2 routing fields so the packer sets them fresh
          // from the target connection's pairwise DIDs. Without this, stale
          // from/to from a previous send would cause connection lookup failures.
          delivery.from = undefined
          delivery.to = undefined

          const connection = await this.connectionService.getById(agentContext, connectionId)
          await this.messageSender.sendMessage(
            new DidCommOutboundMessageContext(delivery, { agentContext, connection })
          )
        } catch (error) {
          agentContext.config.logger.warn(
            `[GroupMessaging] Failed to send delivery to member ${member.did}: ${error}`
          )
        }
      }
    } else {
      // Member: send to admin only (hub-and-spoke)
      if (groupRecord.adminConnectionId) {
        try {
          delivery.from = undefined
          delivery.to = undefined

          const connection = await this.connectionService.getById(agentContext, groupRecord.adminConnectionId)
          await this.messageSender.sendMessage(
            new DidCommOutboundMessageContext(delivery, { agentContext, connection })
          )
        } catch (error) {
          agentContext.config.logger.warn(
            `[GroupMessaging] Failed to send delivery to admin: ${error}`
          )
        }
      }
    }
  }

  /**
   * Retry a save operation with backoff to handle transient Askar session contention.
   */
  private async retrySave(agentContext: AgentContext, record: GroupMessageRecord, maxRetries = 2): Promise<void> {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        await this.groupMessageRepository.save(agentContext, record)
        return
      } catch (error) {
        if (attempt === maxRetries) throw error
        agentContext.config.logger.warn(`[GroupMessaging] Save failed (attempt ${attempt + 1}), retrying: ${error}`)
        await new Promise((r) => setTimeout(r, 50 * (attempt + 1)))
      }
    }
  }

  /**
   * Retry an update operation with backoff to handle transient Askar session contention.
   */
  private async retryUpdate(agentContext: AgentContext, record: GroupRecord, maxRetries = 2): Promise<void> {
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        await this.groupRepository.update(agentContext, record)
        return
      } catch (error) {
        if (attempt === maxRetries) throw error
        agentContext.config.logger.warn(`[GroupMessaging] Update failed (attempt ${attempt + 1}), retrying: ${error}`)
        await new Promise((r) => setTimeout(r, 50 * (attempt + 1)))
      }
    }
  }
}
