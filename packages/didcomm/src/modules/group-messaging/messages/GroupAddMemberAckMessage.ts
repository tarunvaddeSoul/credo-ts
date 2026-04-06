import { Expose } from 'class-transformer'
import { IsInt, IsString } from 'class-validator'

import { DidCommMessage } from '../../../DidCommMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export class GroupAddMemberAckMessage extends DidCommMessage {
  public readonly allowDidSovPrefix = false
  public readonly supportedDidCommVersions = ['v2'] as const

  public constructor(options: { id?: string; groupId: string; epoch: number; status: string; threadId: string }) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.groupId = options.groupId
      this.epoch = options.epoch
      this.status = options.status
      this.setThread({ threadId: options.threadId })
    }
  }

  @IsValidMessageType(GroupAddMemberAckMessage.type)
  public readonly type = GroupAddMemberAckMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/group-messaging/1.0/add-member-ack')

  @Expose({ name: 'group_id' })
  @IsString()
  public groupId!: string

  @Expose({ name: 'epoch' })
  @IsInt()
  public epoch!: number

  @Expose({ name: 'status' })
  @IsString()
  public status!: string
}
