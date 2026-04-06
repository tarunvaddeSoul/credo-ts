import { Expose } from 'class-transformer'
import { IsString } from 'class-validator'

import { DidCommMessage } from '../../../DidCommMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export class GroupLeaveMessage extends DidCommMessage {
  public readonly allowDidSovPrefix = false
  public readonly supportedDidCommVersions = ['v2'] as const

  public constructor(options: { id?: string; groupId: string }) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.groupId = options.groupId
    }
  }

  @IsValidMessageType(GroupLeaveMessage.type)
  public readonly type = GroupLeaveMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/group-messaging/1.0/leave')

  @Expose({ name: 'group_id' })
  @IsString()
  public groupId!: string
}
