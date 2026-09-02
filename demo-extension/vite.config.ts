import { resolve } from 'node:path'
import type { Plugin } from 'vite'
import { defineConfig } from 'vite'

// When bundling from the workspace sources, core's package.json "browser" field
// remap (which points at built file paths) does not apply. Swap the node JSON-LD
// document loader for the XHR based one the way a published build would.
const browserDocumentLoader: Plugin = {
  name: 'credo-browser-document-loader',
  enforce: 'pre',
  resolveId(source, importer) {
    if (source.endsWith('/nativeDocumentLoader') && importer?.includes('packages/core')) {
      return resolve(import.meta.dirname, '../packages/core/src/modules/vc/jsonld/nativeDocumentLoader.native.ts')
    }
    return null
  },
}

export default defineConfig({
  base: './',
  plugins: [browserDocumentLoader],
  build: {
    target: 'es2022',
    outDir: 'dist',
    rollupOptions: {
      input: {
        popup: resolve(import.meta.dirname, 'popup.html'),
        wallet: resolve(import.meta.dirname, 'wallet.html'),
      },
    },
  },
})
