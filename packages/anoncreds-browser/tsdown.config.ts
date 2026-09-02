import { defineConfig } from 'tsdown'
import config from '../../tsdown.config.base'

export default defineConfig(
  config.map((entry) => ({
    ...entry,
    // keep the wasm-bindgen glue (and its .wasm asset URL) out of the bundle
    external: [/wasm\/pkg\/anoncreds_wasm/],
  }))
)
