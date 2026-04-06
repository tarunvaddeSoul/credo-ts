import type { DidCommMessageHandler, DidCommMessageHandlerInboundMessage } from '../../../handlers'
import { GroupKeyRotateAckMessage } from '../messages'
import type { GroupMessagingService } from '../services/GroupMessagingService'

export class GroupKeyRotateAckHandler implements DidCommMessageHandler {
  private service: GroupMessagingService
  public supportedMessages = [GroupKeyRotateAckMessage]

  public constructor(service: GroupMessagingService) {
    this.service = service
  }

  public async handle(_messageContext: DidCommMessageHandlerInboundMessage<GroupKeyRotateAckHandler>) {
    return undefined
  }
}
