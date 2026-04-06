import { Expose, Type } from 'class-transformer'
import { IsArray, IsInt, IsOptional, IsString, ValidateNested } from 'class-validator'

import { DidCommMessage } from '../../../DidCommMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'
import { GroupGckDto, GroupMemberEntryDto } from './GroupCreateMessage'

/**
 * Sent by admin to remaining members when one or more members are removed.
 * Removed members receive this message WITHOUT the gck, members, or epochHash fields.
 */
export class GroupRemoveMemberMessage extends DidCommMessage {
  public readonly allowDidSovPrefix = false
  public readonly supportedDidCommVersions = ['v2'] as const

  public constructor(options: {
    id?: string
    groupId: string
    epoch?: number
    removed: string[]
    members?: { did: string; role: 'admin' | 'member' }[]
    gck?: { k: string; alg: string }
    epochHash?: string
  }) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.groupId = options.groupId
      this.epoch = options.epoch
      this.removed = options.removed
      this.members = options.members as GroupMemberEntryDto[] | undefined
      this.gck = options.gck as GroupGckDto | undefined
      this.epochHash = options.epochHash
    }
  }

  @IsValidMessageType(GroupRemoveMemberMessage.type)
  public readonly type = GroupRemoveMemberMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/group-messaging/1.0/remove-member')

  @Expose({ name: 'group_id' })
  @IsString()
  public groupId!: string

  @Expose({ name: 'epoch' })
  @IsInt()
  @IsOptional()
  public epoch?: number

  @Expose({ name: 'removed' })
  @IsArray()
  @IsString({ each: true })
  public removed!: string[]

  @Expose({ name: 'members' })
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => GroupMemberEntryDto)
  public members?: GroupMemberEntryDto[]

  @Expose({ name: 'gck' })
  @IsOptional()
  @ValidateNested()
  @Type(() => GroupGckDto)
  public gck?: GroupGckDto

  @Expose({ name: 'epoch_hash' })
  @IsString()
  @IsOptional()
  public epochHash?: string
}
