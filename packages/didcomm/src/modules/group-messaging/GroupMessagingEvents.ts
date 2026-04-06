import type { BaseEvent } from '@credo-ts/core'
import type { GroupMessageRecord, GroupRecord } from './repository'

export enum GroupMessagingEventTypes {
  GroupCreated = 'GroupCreated',
  GroupMessageReceived = 'GroupMessageReceived',
  GroupMemberAdded = 'GroupMemberAdded',
  GroupMemberRemoved = 'GroupMemberRemoved',
  GroupKeyRotated = 'GroupKeyRotated',
  GroupMemberLeft = 'GroupMemberLeft',
  GroupStateChanged = 'GroupStateChanged',
}

export interface GroupCreatedEvent extends BaseEvent {
  type: typeof GroupMessagingEventTypes.GroupCreated
  payload: { groupRecord: GroupRecord }
}

export interface GroupMessageReceivedEvent extends BaseEvent {
  type: typeof GroupMessagingEventTypes.GroupMessageReceived
  payload: {
    groupRecord: GroupRecord
    messageRecord: GroupMessageRecord
  }
}

export interface GroupMemberAddedEvent extends BaseEvent {
  type: typeof GroupMessagingEventTypes.GroupMemberAdded
  payload: {
    groupRecord: GroupRecord
    addedDids: string[]
  }
}

export interface GroupMemberRemovedEvent extends BaseEvent {
  type: typeof GroupMessagingEventTypes.GroupMemberRemoved
  payload: {
    groupRecord: GroupRecord
    removedDids: string[]
  }
}

export interface GroupKeyRotatedEvent extends BaseEvent {
  type: typeof GroupMessagingEventTypes.GroupKeyRotated
  payload: {
    groupRecord: GroupRecord
    reason: string
  }
}

export interface GroupMemberLeftEvent extends BaseEvent {
  type: typeof GroupMessagingEventTypes.GroupMemberLeft
  payload: {
    groupRecord: GroupRecord
    memberDid: string
  }
}
