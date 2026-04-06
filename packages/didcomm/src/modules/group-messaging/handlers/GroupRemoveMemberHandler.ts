import type { DidCommMessageHandler, DidCommMessageHandlerInboundMessage } from '../../../handlers'
import { DidCommOutboundMessageContext } from '../../../models'
import { GroupRemoveMemberAckMessage, GroupRemoveMemberMessage } from '../messages'
import type { GroupMessagingService } from '../services/GroupMessagingService'

export class GroupRemoveMemberHandler implements DidCommMessageHandler {
  private service: GroupMessagingService
  public supportedMessages = [GroupRemoveMemberMessage]

  public constructor(service: GroupMessagingService) {
    this.service = service
  }

  public async handle(messageContext: DidCommMessageHandlerInboundMessage<GroupRemoveMemberHandler>) {
    const connection = messageContext.assertReadyConnection()
    const { message, agentContext } = messageContext
    const ourDid = connection.did ?? ''

    const groupRecord = await this.service.processRemoveMember(agentContext, message, ourDid)

    // Only send ack if we're still in the group (not removed)
    if (message.epoch !== undefined && message.gck) {
      const ack = new GroupRemoveMemberAckMessage({
        groupId: message.groupId,
        epoch: message.epoch,
        status: 'accepted',
        threadId: message.id,
      })
      return new DidCommOutboundMessageContext(ack, { agentContext, connection })
    }

    return undefined
  }
}
