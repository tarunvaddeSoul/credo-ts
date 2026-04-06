import type { AgentContext, DependencyManager, Module } from '@credo-ts/core'

import { DidCommFeatureRegistry } from '../../DidCommFeatureRegistry'
import { DidCommMessageHandlerRegistry } from '../../DidCommMessageHandlerRegistry'
import { DidCommProtocol } from '../../models'
import { GroupMessagingApi } from './GroupMessagingApi'
import type { GroupMessagingModuleConfigOptions } from './GroupMessagingModuleConfig'
import { GroupMessagingModuleConfig } from './GroupMessagingModuleConfig'
import { GroupMessagingRole } from './GroupMessagingRole'
import {
  GroupAddMemberAckHandler,
  GroupAddMemberHandler,
  GroupCreateAckHandler,
  GroupCreateHandler,
  GroupDeliveryHandler,
  GroupKeyRotateAckHandler,
  GroupKeyRotateHandler,
  GroupLeaveAckHandler,
  GroupLeaveHandler,
  GroupRemoveMemberAckHandler,
  GroupRemoveMemberHandler,
} from './handlers'
import { GroupMessageRepository, GroupRepository } from './repository'
import { GroupCryptoService, GroupMessagingService } from './services'

export class GroupMessagingModule implements Module {
  public readonly config: GroupMessagingModuleConfig
  public readonly api = GroupMessagingApi

  public constructor(config?: GroupMessagingModuleConfigOptions) {
    this.config = new GroupMessagingModuleConfig(config)
  }

  public register(dependencyManager: DependencyManager): void {
    dependencyManager.registerInstance(GroupMessagingModuleConfig, this.config)
    dependencyManager.registerSingleton(GroupMessagingService)
    dependencyManager.registerSingleton(GroupCryptoService)
    dependencyManager.registerSingleton(GroupRepository)
    dependencyManager.registerSingleton(GroupMessageRepository)
  }

  public async initialize(agentContext: AgentContext): Promise<void> {
    const featureRegistry = agentContext.dependencyManager.resolve(DidCommFeatureRegistry)
    const messageHandlerRegistry = agentContext.resolve(DidCommMessageHandlerRegistry)
    const service = agentContext.resolve(GroupMessagingService)

    // Register all message handlers
    messageHandlerRegistry.registerMessageHandler(new GroupCreateHandler(service))
    messageHandlerRegistry.registerMessageHandler(new GroupCreateAckHandler(service))
    messageHandlerRegistry.registerMessageHandler(new GroupDeliveryHandler(service))
    messageHandlerRegistry.registerMessageHandler(new GroupAddMemberHandler(service))
    messageHandlerRegistry.registerMessageHandler(new GroupAddMemberAckHandler(service))
    messageHandlerRegistry.registerMessageHandler(new GroupRemoveMemberHandler(service))
    messageHandlerRegistry.registerMessageHandler(new GroupRemoveMemberAckHandler(service))
    messageHandlerRegistry.registerMessageHandler(new GroupKeyRotateHandler(service))
    messageHandlerRegistry.registerMessageHandler(new GroupKeyRotateAckHandler(service))
    messageHandlerRegistry.registerMessageHandler(new GroupLeaveHandler(service))
    messageHandlerRegistry.registerMessageHandler(new GroupLeaveAckHandler(service))

    // Register protocol feature for discovery
    featureRegistry.register(
      new DidCommProtocol({
        id: 'https://didcomm.org/group-messaging/1.0',
        roles: [GroupMessagingRole.Admin, GroupMessagingRole.Member],
      })
    )
  }
}
