import type { BaseAgent } from '@credo-ts/core'
import { getAlternativeDidsForNumAlgo4Did } from '@credo-ts/core'

import { DidCommMediationRepository } from '../../modules/routing/repository/DidCommMediationRepository'
import { DidCommMediationRole } from '../../modules/routing/models/DidCommMediationRole'
import { DidCommMediationState } from '../../modules/routing/models/DidCommMediationState'

/**
 * Backfills `recipientDids` on granted mediator records so that both short and long
 * did:peer:4 forms are present. This allows forward `next` lookups to work via a
 * single indexed `$or` query without expensive full-table scans.
 */
export async function backfillMediationRecipientDids<Agent extends BaseAgent>(agent: Agent): Promise<void> {
  agent.config.logger.info('Backfilling mediation recipientDids with did:peer:4 alternative forms')
  const mediationRepository = agent.dependencyManager.resolve(DidCommMediationRepository)

  const grantedMediators = await mediationRepository.findByQuery(agent.context, {
    role: DidCommMediationRole.Mediator,
    state: DidCommMediationState.Granted,
  })

  agent.config.logger.debug(`Found ${grantedMediators.length} granted mediator records to check`)

  let updatedCount = 0
  for (const record of grantedMediators) {
    const existing = record.recipientDids ?? []
    let changed = false

    for (const did of [...existing]) {
      const alternatives = getAlternativeDidsForNumAlgo4Did(did)
      if (!alternatives) continue
      for (const alt of alternatives) {
        if (!existing.includes(alt)) {
          record.addRecipientDid(alt)
          changed = true
        }
      }
    }

    if (changed) {
      await mediationRepository.update(agent.context, record)
      updatedCount++
    }
  }

  agent.config.logger.info(`Backfilled recipientDids on ${updatedCount} mediation records`)
}
