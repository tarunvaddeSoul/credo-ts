import type { DidCommMessageHandler, DidCommMessageHandlerInboundMessage } from '../../../handlers'
import { GroupRemoveMemberAckMessage } from '../messages'
import type { GroupMessagingService } from '../services/GroupMessagingService'

export class GroupRemoveMemberAckHandler implements DidCommMessageHandler {
  private service: GroupMessagingService
  public supportedMessages = [GroupRemoveMemberAckMessage]

  public constructor(service: GroupMessagingService) {
    this.service = service
  }

  public async handle(_messageContext: DidCommMessageHandlerInboundMessage<GroupRemoveMemberAckHandler>) {
    return undefined
  }
}
