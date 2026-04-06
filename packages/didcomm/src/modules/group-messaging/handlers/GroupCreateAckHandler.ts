import type { DidCommMessageHandler, DidCommMessageHandlerInboundMessage } from '../../../handlers'
import { GroupCreateAckMessage } from '../messages'
import type { GroupMessagingService } from '../services/GroupMessagingService'

export class GroupCreateAckHandler implements DidCommMessageHandler {
  private service: GroupMessagingService
  public supportedMessages = [GroupCreateAckMessage]

  public constructor(service: GroupMessagingService) {
    this.service = service
  }

  public async handle(_messageContext: DidCommMessageHandlerInboundMessage<GroupCreateAckHandler>) {
    // Ack received — no action needed for MVP.
    // Future: track which members have acknowledged.
    return undefined
  }
}
