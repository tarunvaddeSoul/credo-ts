// Long-running harness that keeps the local issuer/verifier agent alive.
// Runs under vitest because its transform pipeline emits the decorator
// metadata Credo needs (vite-node currently does not).
import 'reflect-metadata'

import { test } from 'vitest'
import { main } from './local-agent'

test('run local issuer/verifier agent until killed', async () => {
  await main()

  await new Promise(() => {})
}, 86_400_000)
