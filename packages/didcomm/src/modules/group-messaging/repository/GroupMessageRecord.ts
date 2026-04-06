import type { RecordTags, TagsBase } from '@credo-ts/core'
import { BaseRecord, utils } from '@credo-ts/core'

export type CustomGroupMessageTags = TagsBase
export type DefaultGroupMessageTags = {
  groupId: string
  senderDid: string
  messageId: string
}

export type GroupMessageRecordTags = RecordTags<GroupMessageRecord>

export interface GroupMessageRecordStorageProps {
  id?: string
  createdAt?: Date
  groupId: string
  messageId: string
  senderDid: string
  epoch: number
  content: string
  sentTime: string
  tags?: CustomGroupMessageTags
}

export class GroupMessageRecord extends BaseRecord<DefaultGroupMessageTags, CustomGroupMessageTags> {
  public groupId!: string
  public messageId!: string
  public senderDid!: string
  public epoch!: number
  public content!: string
  public sentTime!: string

  public static readonly type = 'GroupMessageRecord'
  public readonly type = GroupMessageRecord.type

  public constructor(props: GroupMessageRecordStorageProps) {
    super()

    if (props) {
      this.id = props.id ?? utils.uuid()
      this.createdAt = props.createdAt ?? new Date()
      this.groupId = props.groupId
      this.messageId = props.messageId
      this.senderDid = props.senderDid
      this.epoch = props.epoch
      this.content = props.content
      this.sentTime = props.sentTime
      this._tags = props.tags ?? {}
    }
  }

  public getTags() {
    return {
      ...this._tags,
      groupId: this.groupId,
      senderDid: this.senderDid,
      messageId: this.messageId,
    }
  }
}
