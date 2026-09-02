---
'@credo-ts/anoncreds-browser': patch
---

feat: add @credo-ts/anoncreds-browser package. Implements the Anoncreds interface from @hyperledger/anoncreds-shared on top of a WASM build of anoncreds-rs so @credo-ts/anoncreds works unchanged in browsers, and adds IndyVdrProxyAnonCredsRegistry which resolves Indy AnonCreds objects over HTTP via an indy-vdr-proxy server.
