<p align="center">
  <br />
  <img
    alt="Credo Logo"
    src="https://github.com/openwallet-foundation/credo-ts/blob/c7886cb8377ceb8ee4efe8d264211e561a75072d/images/credo-logo.png"
    height="250px"
  />
</p>
<h1 align="center"><b>Credo - Browser</b></h1>
<p align="center">
  <a
    href="https://raw.githubusercontent.com/openwallet-foundation/credo-ts/main/LICENSE"
    ><img
      alt="License"
      src="https://img.shields.io/badge/License-Apache%202.0-blue.svg"
  /></a>
  <a href="https://www.typescriptlang.org/"
    ><img
      alt="typescript"
      src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg"
  /></a>
    <a href="https://www.npmjs.com/package/@credo-ts/browser"
    ><img
      alt="@credo-ts/browser version"
      src="https://img.shields.io/npm/v/@credo-ts/browser"
  /></a>

</p>
<br />

Credo Browser provides platform specific dependencies to run Credo in browsers and browser extensions. See the [Getting Started Guide](https://github.com/openwallet-foundation/credo-ts#getting-started) for installation instructions.

It provides:

- `agentDependencies` based on the browser `fetch`, `WebSocket` and an in-memory file system
- `BrowserStorageService`, an IndexedDB backed storage service
- `BrowserKeyManagementService`, a key management backend based on WebCrypto (with pure JS fallbacks for algorithms WebCrypto does not support, such as Ed25519, X25519, secp256k1 and ChaCha20-Poly1305), including the NaCl crypto box operations used by DIDComm v1 envelopes (ECDH-HSALSA20 with XSALSA20-POLY1305)
- `BrowserWalletModule`, which registers the storage service and key management backend on the agent

## Usage

```ts
import { Agent } from '@credo-ts/core'
import { agentDependencies, BrowserWalletModule } from '@credo-ts/browser'

const agent = new Agent({
  dependencies: agentDependencies,
  modules: {
    wallet: new BrowserWalletModule(),
  },
})

await agent.initialize()
```

Keys are stored as plaintext JWKs in IndexedDB. If your environment provides a secure key store, implement the `BrowserKeyManagementStorage` interface and pass it via `kmsStorage`.
