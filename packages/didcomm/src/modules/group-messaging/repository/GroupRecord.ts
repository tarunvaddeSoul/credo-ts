import type { RecordTags, TagsBase } from '@credo-ts/core'
import { BaseRecord, utils } from '@credo-ts/core'
import type { GroupMessagingRole } from '../GroupMessagingRole'
import type { GroupMessagingState } from '../GroupMessagingState'

export interface GroupMemberEntry {
  did: string
  role: 'admin' | 'member'
}

export interface GroupPolicy {
  memberCanInvite: boolean
  memberCanLeave: boolean
  rotationPeriodSeconds: number
  rotationPeriodMessages: number
  maxMembers: number
}

export const DEFAULT_GROUP_POLICY: GroupPolicy = {
  memberCanInvite: false,
  memberCanLeave: true,
  rotationPeriodSeconds: 604800,
  rotationPeriodMessages: 100,
  maxMembers: 256,
}

export type CustomGroupTags = TagsBase
export type DefaultGroupTags = {
  groupId: string
  role: string
  state: string
}

export type GroupRecordTags = RecordTags<GroupRecord>

export interface GroupRecordStorageProps {
  id?: string
  createdAt?: Date
  groupId: string
  ourDid: string
  name?: string
  epoch: number
  role: GroupMessagingRole
  state: GroupMessagingState
  members: GroupMemberEntry[]
  gck: string
  previousGck?: string
  epochHash?: string
  policy?: GroupPolicy
  groupMediatorDid?: string
  groupMediatorEndpoint?: string
  messageCount: number
  lastKeyRotation?: string
  /** Maps member DID → connectionId for members the agent can directly reach (admin only) */
  memberConnectionMap?: Record<string, string>
  /** ConnectionId to reach the admin — set on members, undefined on admin */
  adminConnectionId?: string
  tags?: CustomGroupTags
}

export class GroupRecord extends BaseRecord<DefaultGroupTags, CustomGroupTags> {
  public groupId!: string
  public ourDid!: string
  public name?: string
  public epoch!: number
  public role!: GroupMessagingRole
  public state!: GroupMessagingState
  public members!: GroupMemberEntry[]
  public gck!: string
  public previousGck?: string
  public epochHash?: string
  public policy!: GroupPolicy
  public groupMediatorDid?: string
  public groupMediatorEndpoint?: string
  public messageCount!: number
  public lastKeyRotation?: string
  /** Maps member DID → connectionId for members the agent can directly reach (admin only) */
  public memberConnectionMap!: Record<string, string>
  /** ConnectionId to reach the admin — set on members, undefined on admin */
  public adminConnectionId?: string

  public static readonly type = 'GroupRecord'
  public readonly type = GroupRecord.type

  public constructor(props: GroupRecordStorageProps) {
    super()

    if (props) {
      this.id = props.id ?? utils.uuid()
      this.createdAt = props.createdAt ?? new Date()
      this.groupId = props.groupId
      this.ourDid = props.ourDid
      this.name = props.name
      this.epoch = props.epoch
      this.role = props.role
      this.state = props.state
      this.members = props.members
      this.gck = props.gck
      this.previousGck = props.previousGck
      this.epochHash = props.epochHash
      this.policy = props.policy ?? DEFAULT_GROUP_POLICY
      this.groupMediatorDid = props.groupMediatorDid
      this.groupMediatorEndpoint = props.groupMediatorEndpoint
      this.messageCount = props.messageCount ?? 0
      this.lastKeyRotation = props.lastKeyRotation
      this.memberConnectionMap = props.memberConnectionMap ?? {}
      this.adminConnectionId = props.adminConnectionId
      this._tags = props.tags ?? {}
    }
  }

  public getTags() {
    return {
      ...this._tags,
      groupId: this.groupId,
      role: this.role,
      state: this.state,
    }
  }
}
