import type { DidCommMessageHandler, DidCommMessageHandlerInboundMessage } from '../../../handlers'
import { DidCommOutboundMessageContext } from '../../../models'
import { GroupKeyRotateAckMessage, GroupKeyRotateMessage } from '../messages'
import type { GroupMessagingService } from '../services/GroupMessagingService'

export class GroupKeyRotateHandler implements DidCommMessageHandler {
  private service: GroupMessagingService
  public supportedMessages = [GroupKeyRotateMessage]

  public constructor(service: GroupMessagingService) {
    this.service = service
  }

  public async handle(messageContext: DidCommMessageHandlerInboundMessage<GroupKeyRotateHandler>) {
    const connection = messageContext.assertReadyConnection()
    const { message, agentContext } = messageContext

    await this.service.processKeyRotate(agentContext, message)

    const ack = new GroupKeyRotateAckMessage({
      groupId: message.groupId,
      epoch: message.epoch,
      status: 'accepted',
      threadId: message.id,
    })

    return new DidCommOutboundMessageContext(ack, { agentContext, connection })
  }
}
