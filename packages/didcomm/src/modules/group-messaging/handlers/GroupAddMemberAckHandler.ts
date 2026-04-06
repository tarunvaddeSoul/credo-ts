import type { DidCommMessageHandler, DidCommMessageHandlerInboundMessage } from '../../../handlers'
import { GroupAddMemberAckMessage } from '../messages'
import type { GroupMessagingService } from '../services/GroupMessagingService'

export class GroupAddMemberAckHandler implements DidCommMessageHandler {
  private service: GroupMessagingService
  public supportedMessages = [GroupAddMemberAckMessage]

  public constructor(service: GroupMessagingService) {
    this.service = service
  }

  public async handle(_messageContext: DidCommMessageHandlerInboundMessage<GroupAddMemberAckHandler>) {
    return undefined
  }
}
