# Credo SSI Wallet - Demo Web Extension

A demo browser extension (Manifest V3) that runs a full Credo agent in the browser using `@credo-ts/browser`. Records are stored in IndexedDB, keys in the WebCrypto based browser KMS.

## What you can test

- Create/open a wallet (agent initialization with persistence across restarts)
- Connect to a mediator (paste your mediator's out-of-band invitation URL before initializing) for inbound DIDComm
- Receive out-of-band invitations and establish DIDComm connections
- Send/receive basic messages over DIDComm
- Receive W3C JSON-LD credentials (DIDComm issue-credential v2, `ldp_vc` format)
- Receive AnonCreds credentials (issue-credential v1 and v2, via the `@credo-ts/anoncreds-browser` WASM binding, ledger objects resolved over an indy-vdr-proxy)
- Present proofs (present-proof v2, DIF Presentation Exchange and AnonCreds formats)

The indy-vdr-proxy base url defaults to `http://localhost:8080` and can be changed in `src/agent.ts`.

## Local test agent

`pnpm local-agent` starts a Node issuer/verifier agent with a WS inbound transport, a control HTTP API on `http://localhost:9202` to drive flows (invitation, basic messages, JSON-LD and AnonCreds offers, PEX and AnonCreds proof requests) and a fake indy-vdr-proxy on port 8080 backed by its in-memory AnonCreds registry. See `e2e/local-agent.ts` for the endpoints.

## Real ledger proxy

The fake proxy above only knows the objects the local agent created. To accept credentials from a real issuer, run `pnpm indy-vdr-proxy` instead. It opens a pool against the BCovrin test ledger and serves the same routes on `http://localhost:8081`, so point the wallet's proxy base url there (port 8081, not 8080).

Genesis is fetched from `http://test.bcovrin.vonx.io/genesis` at startup. Override with `INDY_VDR_PROXY_GENESIS_URL`, `INDY_VDR_PROXY_GENESIS_FILE` (fallback when the fetch fails) and `INDY_VDR_PROXY_PORT`.

## Build

```
pnpm install
pnpm --filter credo-demo-extension build
```

## Load in Chrome

1. Open `chrome://extensions`
2. Enable Developer mode
3. "Load unpacked" and select `demo-extension/dist`
4. Click the extension icon, then "Open wallet"

## Notes

- The issuer/verifier agent you test against must support issue-credential/present-proof v2 with the `ldp_vc` / DIF PEX formats (for example a Credo node agent configured with `DidCommJsonLdCredentialFormatService` and `DidCommDifPresentationExchangeProofFormatService`).
- Without a mediator, flows still work against agents reachable over WebSocket (return routing on the outbound socket).
- `allowInsecureHttpUrls` is enabled for local testing against `http://` and `ws://` endpoints.
