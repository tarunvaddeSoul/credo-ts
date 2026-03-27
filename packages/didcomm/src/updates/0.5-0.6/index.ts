import type { BaseAgent } from '@credo-ts/core'

import { backfillMediationRecipientDids } from './mediation'

export async function updateV0_5ToV0_6<Agent extends BaseAgent>(agent: Agent): Promise<void> {
  await backfillMediationRecipientDids(agent)
}
