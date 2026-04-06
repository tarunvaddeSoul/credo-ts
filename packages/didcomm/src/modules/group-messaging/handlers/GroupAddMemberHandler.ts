import type { DidCommMessageHandler, DidCommMessageHandlerInboundMessage } from '../../../handlers'
import { DidCommOutboundMessageContext } from '../../../models'
import { GroupAddMemberAckMessage, GroupAddMemberMessage } from '../messages'
import type { GroupMessagingService } from '../services/GroupMessagingService'

export class GroupAddMemberHandler implements DidCommMessageHandler {
  private service: GroupMessagingService
  public supportedMessages = [GroupAddMemberMessage]

  public constructor(service: GroupMessagingService) {
    this.service = service
  }

  public async handle(messageContext: DidCommMessageHandlerInboundMessage<GroupAddMemberHandler>) {
    const connection = messageContext.assertReadyConnection()
    const { message, agentContext } = messageContext

    await this.service.processAddMember(agentContext, message)

    const ack = new GroupAddMemberAckMessage({
      groupId: message.groupId,
      epoch: message.epoch,
      status: 'accepted',
      threadId: message.id,
    })

    return new DidCommOutboundMessageContext(ack, { agentContext, connection })
  }
}
