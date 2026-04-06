import { Expose } from 'class-transformer'
import { IsString } from 'class-validator'

import { DidCommMessage } from '../../../DidCommMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export class GroupLeaveAckMessage extends DidCommMessage {
  public readonly allowDidSovPrefix = false
  public readonly supportedDidCommVersions = ['v2'] as const

  public constructor(options: { id?: string; groupId: string; status: string; threadId: string }) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.groupId = options.groupId
      this.status = options.status
      this.setThread({ threadId: options.threadId })
    }
  }

  @IsValidMessageType(GroupLeaveAckMessage.type)
  public readonly type = GroupLeaveAckMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/group-messaging/1.0/leave-ack')

  @Expose({ name: 'group_id' })
  @IsString()
  public groupId!: string

  @Expose({ name: 'status' })
  @IsString()
  public status!: string
}
