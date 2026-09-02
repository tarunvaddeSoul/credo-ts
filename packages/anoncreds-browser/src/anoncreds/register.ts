import type { Anoncreds } from '@hyperledger/anoncreds-shared'
import { NativeAnoncreds } from '@hyperledger/anoncreds-shared'

import init from '../../wasm/pkg/anoncreds_wasm.js'
import type { ResolveTailsFile } from './WasmAnoncreds'
import { WasmAnoncreds } from './WasmAnoncreds'

export interface LoadAnoncredsWasmOptions {
  /**
   * Override the location (or raw bytes/compiled WebAssembly.Module) of the anoncreds_wasm_bg.wasm
   * binary. By default it is resolved relative to the wasm-bindgen glue module (bundlers like vite
   * handle this automatically).
   */
  // `object` stands in for WebAssembly.Module, the repo type-checks without DOM lib types
  wasm?: string | URL | BufferSource | object

  /**
   * Synchronously resolve tails file bytes for a tails path/location, required only when
   * creating revocation states (holder side of revocable credentials).
   */
  resolveTailsFile?: ResolveTailsFile
}

let anoncredsWasm: WasmAnoncreds | undefined

/**
 * Initializes the anoncreds-rs WASM module and registers it as the native anoncreds
 * implementation for @hyperledger/anoncreds-shared. Must be awaited before the agent
 * performs any AnonCreds operation. Safe to call multiple times.
 */
export async function loadAnoncredsWasm(options: LoadAnoncredsWasmOptions = {}): Promise<Anoncreds> {
  if (!anoncredsWasm) {
    await init(options.wasm ? { module_or_path: options.wasm } : undefined)
    anoncredsWasm = new WasmAnoncreds({ resolveTailsFile: options.resolveTailsFile })
    NativeAnoncreds.register(anoncredsWasm)
  }
  return anoncredsWasm
}
