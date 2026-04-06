import { Expose, Type } from 'class-transformer'
import { IsArray, IsInt, IsObject, IsOptional, IsString, ValidateNested } from 'class-validator'

import { DidCommMessage } from '../../../DidCommMessage'
import { IsValidMessageType, parseMessageType } from '../../../util/messageType'

export class GroupMemberEntryDto {
  @IsString()
  public did!: string

  @IsString()
  public role!: 'admin' | 'member'
}

export class GroupGckDto {
  @IsString()
  public k!: string

  @IsString()
  public alg!: string
}

export class GroupPolicyDto {
  @Expose({ name: 'member_can_invite' })
  public memberCanInvite!: boolean

  @Expose({ name: 'member_can_leave' })
  public memberCanLeave!: boolean

  @Expose({ name: 'rotation_period_seconds' })
  @IsInt()
  public rotationPeriodSeconds!: number

  @Expose({ name: 'rotation_period_messages' })
  @IsInt()
  public rotationPeriodMessages!: number

  @Expose({ name: 'max_members' })
  @IsInt()
  public maxMembers!: number
}

export class GroupCreateMessage extends DidCommMessage {
  public readonly allowDidSovPrefix = false
  public readonly supportedDidCommVersions = ['v2'] as const

  public constructor(options: {
    id?: string
    groupId: string
    name?: string
    epoch: number
    members: { did: string; role: 'admin' | 'member' }[]
    gck: { k: string; alg: string }
    policy?: {
      memberCanInvite?: boolean
      memberCanLeave?: boolean
      rotationPeriodSeconds?: number
      rotationPeriodMessages?: number
      maxMembers?: number
    }
  }) {
    super()

    if (options) {
      this.id = options.id || this.generateId()
      this.groupId = options.groupId
      this.name = options.name
      this.epoch = options.epoch
      this.members = options.members as GroupMemberEntryDto[]
      this.gck = options.gck as GroupGckDto
      if (options.policy) {
        this.policy = options.policy as GroupPolicyDto
      }
    }
  }

  @IsValidMessageType(GroupCreateMessage.type)
  public readonly type = GroupCreateMessage.type.messageTypeUri
  public static readonly type = parseMessageType('https://didcomm.org/group-messaging/1.0/create')

  @Expose({ name: 'group_id' })
  @IsString()
  public groupId!: string

  @Expose({ name: 'name' })
  @IsString()
  @IsOptional()
  public name?: string

  @Expose({ name: 'epoch' })
  @IsInt()
  public epoch!: number

  @Expose({ name: 'members' })
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => GroupMemberEntryDto)
  public members!: GroupMemberEntryDto[]

  @Expose({ name: 'gck' })
  @IsObject()
  @ValidateNested()
  @Type(() => GroupGckDto)
  public gck!: GroupGckDto

  @Expose({ name: 'policy' })
  @IsOptional()
  @ValidateNested()
  @Type(() => GroupPolicyDto)
  public policy?: GroupPolicyDto
}
