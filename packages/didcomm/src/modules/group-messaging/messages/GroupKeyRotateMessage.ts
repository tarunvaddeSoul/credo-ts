import { Expose, Type } from 'class-transformer'
import { IsInt, IsOptional, IsString, ValidateNested } from 'class-validator'

import { DidCommMessage } from '../../../DidCommMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'
import { GroupGckDto } from './GroupCreateMessage'

export class GroupKeyRotateMessage extends DidCommMessage {
  public readonly allowDidSovPrefix = false
  public readonly supportedDidCommVersions = ['v2'] as const

  public constructor(options: {
    id?: string
    groupId: string
    epoch: number
    reason?: string
    gck: { k: string; alg: string }
    epochHash: string
  }) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.groupId = options.groupId
      this.epoch = options.epoch
      this.reason = options.reason
      this.gck = options.gck as GroupGckDto
      this.epochHash = options.epochHash
    }
  }

  @IsValidMessageType(GroupKeyRotateMessage.type)
  public readonly type = GroupKeyRotateMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/group-messaging/1.0/key-rotate')

  @Expose({ name: 'group_id' })
  @IsString()
  public groupId!: string

  @Expose({ name: 'epoch' })
  @IsInt()
  public epoch!: number

  @Expose({ name: 'reason' })
  @IsString()
  @IsOptional()
  public reason?: string

  @Expose({ name: 'gck' })
  @ValidateNested()
  @Type(() => GroupGckDto)
  public gck!: GroupGckDto

  @Expose({ name: 'epoch_hash' })
  @IsString()
  public epochHash!: string
}
