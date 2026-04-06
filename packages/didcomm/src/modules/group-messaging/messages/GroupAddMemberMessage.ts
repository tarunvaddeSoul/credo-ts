import { Expose, Type } from 'class-transformer'
import { IsArray, IsInt, IsString, ValidateNested } from 'class-validator'

import { DidCommMessage } from '../../../DidCommMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'
import { GroupGckDto, GroupMemberEntryDto } from './GroupCreateMessage'

export class GroupAddMemberMessage extends DidCommMessage {
  public readonly allowDidSovPrefix = false
  public readonly supportedDidCommVersions = ['v2'] as const

  public constructor(options: {
    id?: string
    groupId: string
    epoch: number
    added: { did: string; role: 'admin' | 'member' }[]
    members: { did: string; role: 'admin' | 'member' }[]
    gck: { k: string; alg: string }
    epochHash: string
  }) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.groupId = options.groupId
      this.epoch = options.epoch
      this.added = options.added as GroupMemberEntryDto[]
      this.members = options.members as GroupMemberEntryDto[]
      this.gck = options.gck as GroupGckDto
      this.epochHash = options.epochHash
    }
  }

  @IsValidMessageType(GroupAddMemberMessage.type)
  public readonly type = GroupAddMemberMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/group-messaging/1.0/add-member')

  @Expose({ name: 'group_id' })
  @IsString()
  public groupId!: string

  @Expose({ name: 'epoch' })
  @IsInt()
  public epoch!: number

  @Expose({ name: 'added' })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => GroupMemberEntryDto)
  public added!: GroupMemberEntryDto[]

  @Expose({ name: 'members' })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => GroupMemberEntryDto)
  public members!: GroupMemberEntryDto[]

  @Expose({ name: 'gck' })
  @ValidateNested()
  @Type(() => GroupGckDto)
  public gck!: GroupGckDto

  @Expose({ name: 'epoch_hash' })
  @IsString()
  public epochHash!: string
}
