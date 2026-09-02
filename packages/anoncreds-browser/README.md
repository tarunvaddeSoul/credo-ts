# Credo - AnonCreds Browser

AnonCreds support for Credo agents running in browsers and web extensions.

This package provides:

- `loadAnoncredsWasm()`: an implementation of the `Anoncreds` interface from
  `@hyperledger/anoncreds-shared` backed by a WASM build of
  [anoncreds-rs](https://github.com/anoncreds/anoncreds-rs) (v0.2.3). Once loaded and
  registered, `@credo-ts/anoncreds` works unchanged in the browser.
- `IndyVdrProxyAnonCredsRegistry`: an `AnonCredsRegistry` that resolves Indy schemas,
  credential definitions, revocation registry definitions and revocation status lists over
  HTTP via an [indy-vdr-proxy](https://github.com/hyperledger-indy/indy-vdr/tree/main/indy-vdr-proxy)
  server, since native indy-vdr cannot run in a browser. Resolution only, registration is
  not supported.

## Usage

```ts
import { AnonCredsModule } from '@credo-ts/anoncreds'
import { IndyVdrProxyAnonCredsRegistry, loadAnoncredsWasm } from '@credo-ts/anoncreds-browser'

// must be awaited before the agent performs any AnonCreds operation
const anoncreds = await loadAnoncredsWasm()

const agent = new Agent({
  // ...
  modules: {
    anoncreds: new AnonCredsModule({
      anoncreds,
      registries: [
        new IndyVdrProxyAnonCredsRegistry({
          proxyBaseUrl: 'https://indy-vdr-proxy.example.com',
          // for proxies running in multi-ledger mode
          indyNamespace: 'bcovrin:test',
        }),
      ],
    }),
  },
})
```

Web extensions (MV3) must allow WebAssembly in the extension pages CSP:

```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
}
```

## WASM module

The `wasm/` directory contains a Rust crate binding anoncreds-rs to JavaScript with
wasm-bindgen. The anoncreds-rs v0.2.3 sources are vendored in `wasm/vendor/anoncreds-rs`
with two small patches (marked `[credo-ts browser vendor patch]`): the pure Rust bignum
backend of anoncreds-clsignatures instead of OpenSSL, and a tails reader that works
without a filesystem. Tails files are kept in an in-memory store, pass `resolveTailsFile`
to `loadAnoncredsWasm()` to supply downloaded tails file bytes for revocation states.

The built module in `wasm/pkg` is committed. Rebuild with `wasm/build.sh` (requires rust
with the wasm32-unknown-unknown target).
