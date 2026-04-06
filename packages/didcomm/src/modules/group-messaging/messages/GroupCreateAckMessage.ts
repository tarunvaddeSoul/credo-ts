import { Expose } from 'class-transformer'
import { IsString } from 'class-validator'

import { DidCommMessage } from '../../../DidCommMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export class GroupCreateAckMessage extends DidCommMessage {
  public readonly allowDidSovPrefix = false
  public readonly supportedDidCommVersions = ['v2'] as const

  public constructor(options: { id?: string; groupId: string; status: 'accepted' | 'rejected'; threadId: string }) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.groupId = options.groupId
      this.status = options.status
      this.setThread({ threadId: options.threadId })
    }
  }

  @IsValidMessageType(GroupCreateAckMessage.type)
  public readonly type = GroupCreateAckMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/group-messaging/1.0/create-ack')

  @Expose({ name: 'group_id' })
  @IsString()
  public groupId!: string

  @Expose({ name: 'status' })
  @IsString()
  public status!: 'accepted' | 'rejected'
}
