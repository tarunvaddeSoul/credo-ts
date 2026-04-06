import type { DidCommMessageHandler, DidCommMessageHandlerInboundMessage } from '../../../handlers'
import { GroupLeaveAckMessage } from '../messages'
import type { GroupMessagingService } from '../services/GroupMessagingService'

export class GroupLeaveAckHandler implements DidCommMessageHandler {
  private service: GroupMessagingService
  public supportedMessages = [GroupLeaveAckMessage]

  public constructor(service: GroupMessagingService) {
    this.service = service
  }

  public async handle(_messageContext: DidCommMessageHandlerInboundMessage<GroupLeaveAckHandler>) {
    return undefined
  }
}
