import { Expose } from 'class-transformer'
import { IsInt, IsString } from 'class-validator'

import { DidCommMessage } from '../../../DidCommMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

/**
 * The delivery envelope wraps a GCK-encrypted group message for transport.
 * This is the message that actually traverses the network.
 */
export class GroupDeliveryMessage extends DidCommMessage {
  public readonly allowDidSovPrefix = false
  public readonly supportedDidCommVersions = ['v2'] as const

  public constructor(options: {
    id?: string
    groupId: string
    epoch: number
    sender: string
    ciphertext: string
    iv: string
    tag: string
  }) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.groupId = options.groupId
      this.epoch = options.epoch
      this.sender = options.sender
      this.ciphertext = options.ciphertext
      this.iv = options.iv
      this.tag = options.tag
    }
  }

  @IsValidMessageType(GroupDeliveryMessage.type)
  public readonly type = GroupDeliveryMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/group-messaging/1.0/delivery')

  @Expose({ name: 'group_id' })
  @IsString()
  public groupId!: string

  @Expose({ name: 'epoch' })
  @IsInt()
  public epoch!: number

  @Expose({ name: 'sender' })
  @IsString()
  public sender!: string

  @Expose({ name: 'ciphertext' })
  @IsString()
  public ciphertext!: string

  @Expose({ name: 'iv' })
  @IsString()
  public iv!: string

  @Expose({ name: 'tag' })
  @IsString()
  public tag!: string
}
