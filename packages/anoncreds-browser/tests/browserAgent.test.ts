import 'fake-indexeddb/auto'

import { readFileSync } from 'node:fs'
import {
  AnonCredsDidCommCredentialFormatService,
  AnonCredsDidCommProofFormatService,
  AnonCredsModule,
  DidCommCredentialV1Protocol,
  DidCommProofV1Protocol,
  LegacyIndyDidCommCredentialFormatService,
  LegacyIndyDidCommProofFormatService,
} from '@credo-ts/anoncreds'
import { Agent, utils } from '@credo-ts/core'
import { agentDependencies, BrowserWalletModule } from '../../browser/src'
import {
  DidCommAutoAcceptCredential,
  DidCommAutoAcceptProof,
  DidCommCredentialV2Protocol,
  DidCommDifPresentationExchangeProofFormatService,
  DidCommJsonLdCredentialFormatService,
  DidCommModule,
  DidCommProofV2Protocol,
} from '../../didcomm/src'
import { IndyVdrProxyAnonCredsRegistry, loadAnoncredsWasm } from '../src'

describe('browser agent with anoncreds wasm and didcomm v1+v2', () => {
  it('initializes', async () => {
    const wasm = readFileSync(new URL('../wasm/pkg/anoncreds_wasm_bg.wasm', import.meta.url))
    const anoncreds = await loadAnoncredsWasm({ wasm })

    const legacyIndyCredentialFormatService = new LegacyIndyDidCommCredentialFormatService()
    const legacyIndyProofFormatService = new LegacyIndyDidCommProofFormatService()

    const agent = new Agent({
      dependencies: agentDependencies,
      modules: {
        wallet: new BrowserWalletModule({ databaseName: `repro-${utils.uuid()}` }),
        anoncreds: new AnonCredsModule({
          anoncreds,
          registries: [new IndyVdrProxyAnonCredsRegistry({ proxyBaseUrl: 'http://localhost:8080' })],
        }),
        didcomm: new DidCommModule({
          connections: { autoAcceptConnections: true },
          credentials: {
            autoAcceptCredentials: DidCommAutoAcceptCredential.ContentApproved,
            credentialProtocols: [
              new DidCommCredentialV1Protocol({ indyCredentialFormat: legacyIndyCredentialFormatService }),
              new DidCommCredentialV2Protocol({
                credentialFormats: [
                  legacyIndyCredentialFormatService,
                  new AnonCredsDidCommCredentialFormatService(),
                  new DidCommJsonLdCredentialFormatService(),
                ],
              }),
            ],
          },
          proofs: {
            autoAcceptProofs: DidCommAutoAcceptProof.ContentApproved,
            proofProtocols: [
              new DidCommProofV1Protocol({ indyProofFormat: legacyIndyProofFormatService }),
              new DidCommProofV2Protocol({
                proofFormats: [
                  legacyIndyProofFormatService,
                  new AnonCredsDidCommProofFormatService(),
                  new DidCommDifPresentationExchangeProofFormatService(),
                ],
              }),
            ],
          },
          mediationRecipient: true,
        }),
      },
    })

    await agent.initialize()

    await agent.shutdown()
  }, 30000)
})
