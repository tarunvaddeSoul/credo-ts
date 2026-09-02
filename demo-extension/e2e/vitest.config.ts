import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['**/local-agent.harness.ts'],
    watch: false,
    testTimeout: 86_400_000,
    hookTimeout: 120_000,
  },
})
