import type { DidCommMessageHandler, DidCommMessageHandlerInboundMessage } from '../../../handlers'
import { GroupDeliveryMessage } from '../messages'
import type { GroupMessagingService } from '../services/GroupMessagingService'

export class GroupDeliveryHandler implements DidCommMessageHandler {
  private service: GroupMessagingService
  public supportedMessages = [GroupDeliveryMessage]

  public constructor(service: GroupMessagingService) {
    this.service = service
  }

  public async handle(messageContext: DidCommMessageHandlerInboundMessage<GroupDeliveryHandler>) {
    const { message, agentContext } = messageContext

    // Extract the authenticated DIDComm envelope sender for verification.
    // In hub-and-spoke, the envelope sender may be the admin (relay), not the
    // group-layer sender. processDelivery validates group membership of message.sender.
    const connection = messageContext.assertReadyConnection()
    const envelopeSenderDid = connection.theirDid

    await this.service.processDelivery(agentContext, message, envelopeSenderDid)

    // No response message per spec
    return undefined
  }
}
