import type { DidCommMessageHandler, DidCommMessageHandlerInboundMessage } from '../../../handlers'
import { DidCommOutboundMessageContext } from '../../../models'
import { GroupCreateAckMessage, GroupCreateMessage } from '../messages'
import type { GroupMessagingService } from '../services/GroupMessagingService'

export class GroupCreateHandler implements DidCommMessageHandler {
  private service: GroupMessagingService
  public supportedMessages = [GroupCreateMessage]

  public constructor(service: GroupMessagingService) {
    this.service = service
  }

  public async handle(messageContext: DidCommMessageHandlerInboundMessage<GroupCreateHandler>) {
    const connection = messageContext.assertReadyConnection()
    const { message, agentContext } = messageContext

    const senderDid = connection.theirDid ?? ''
    const ourDid = connection.did ?? ''

    await this.service.processCreate(agentContext, message, senderDid, ourDid, connection.id)

    // Send ack back
    const ack = new GroupCreateAckMessage({
      groupId: message.groupId,
      status: 'accepted',
      threadId: message.id,
    })

    return new DidCommOutboundMessageContext(ack, { agentContext, connection })
  }
}
