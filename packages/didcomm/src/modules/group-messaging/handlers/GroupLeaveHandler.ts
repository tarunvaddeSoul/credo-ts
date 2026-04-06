import type { DidCommMessageHandler, DidCommMessageHandlerInboundMessage } from '../../../handlers'
import { GroupLeaveMessage } from '../messages'
import type { GroupMessagingService } from '../services/GroupMessagingService'

export class GroupLeaveHandler implements DidCommMessageHandler {
  private service: GroupMessagingService
  public supportedMessages = [GroupLeaveMessage]

  public constructor(service: GroupMessagingService) {
    this.service = service
  }

  public async handle(messageContext: DidCommMessageHandlerInboundMessage<GroupLeaveHandler>) {
    const connection = messageContext.assertReadyConnection()
    const { message, agentContext } = messageContext
    const senderDid = connection.theirDid ?? ''

    // processLeave handles ack sending and key rotation if we're admin
    await this.service.processLeave(agentContext, message, senderDid)

    return undefined
  }
}
