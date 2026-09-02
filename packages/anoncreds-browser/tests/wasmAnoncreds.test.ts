import { readFileSync } from 'node:fs'

import type { Anoncreds } from '@hyperledger/anoncreds-shared'
import { loadAnoncredsWasm } from '../src'

const issuerId = 'TL1EaPFCZ8Si5aUrqScBDt'
const schemaId = `${issuerId}:2:test:1.0`
const credentialDefinitionId = `${issuerId}:3:CL:1:TAG`
const revocationRegistryDefinitionId = `${issuerId}:4:${issuerId}:3:CL:1:TAG:CL_ACCUM:tag`

describe('WasmAnoncreds', () => {
  let anoncreds: Anoncreds

  beforeAll(async () => {
    const wasm = readFileSync(new URL('../wasm/pkg/anoncreds_wasm_bg.wasm', import.meta.url))
    anoncreds = await loadAnoncredsWasm({ wasm })
  })

  test('reports the anoncreds version', () => {
    expect(anoncreds.version()).toBe('0.2.3')
  })

  test('encodes credential attributes', () => {
    const [encoded] = anoncreds.encodeCredentialAttributes({ attributeRawValues: ['101'] })
    expect(encoded).toBe('101')
  })

  test('full issuance, presentation and w3c conversion flow', () => {
    const schema = anoncreds.createSchema({
      name: 'test',
      version: '1.0',
      issuerId,
      attributeNames: ['name', 'age'],
    })
    expect(JSON.parse(anoncreds.getJson({ objectHandle: schema }))).toMatchObject({
      name: 'test',
      attrNames: expect.arrayContaining(['name', 'age']),
    })

    const { credentialDefinition, credentialDefinitionPrivate, keyCorrectnessProof } =
      anoncreds.createCredentialDefinition({
        schemaId,
        schema,
        tag: 'TAG',
        issuerId,
        signatureType: 'CL',
        supportRevocation: false,
      })

    const credentialOffer = anoncreds.createCredentialOffer({
      schemaId,
      credentialDefinitionId,
      keyCorrectnessProof,
    })

    const linkSecret = anoncreds.createLinkSecret()

    const { credentialRequest, credentialRequestMetadata } = anoncreds.createCredentialRequest({
      entropy: 'entropy',
      credentialDefinition,
      linkSecret,
      linkSecretId: 'link-secret-id',
      credentialOffer,
    })

    const issuedCredential = anoncreds.createCredential({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeRawValues: { name: 'Alice', age: '28' },
    })

    const credential = anoncreds.processCredential({
      credential: issuedCredential,
      credentialRequestMetadata,
      linkSecret,
      credentialDefinition,
    })

    expect(anoncreds.credentialGetAttribute({ objectHandle: credential, name: 'schema_id' })).toBe(schemaId)
    expect(anoncreds.credentialGetAttribute({ objectHandle: credential, name: 'rev_reg_id' })).toBeNull()

    const presentationRequest = anoncreds.presentationRequestFromJson({
      json: JSON.stringify({
        nonce: anoncreds.generateNonce(),
        name: 'presentation-request',
        version: '1.0',
        requested_attributes: {
          attr1_referent: { name: 'name' },
        },
        requested_predicates: {
          predicate1_referent: { name: 'age', p_type: '>=', p_value: 18 },
        },
      }),
    })

    const presentation = anoncreds.createPresentation({
      presentationRequest,
      credentials: [{ credential }],
      credentialsProve: [
        { entryIndex: 0, referent: 'attr1_referent', isPredicate: false, reveal: true },
        { entryIndex: 0, referent: 'predicate1_referent', isPredicate: true, reveal: true },
      ],
      selfAttest: {},
      linkSecret,
      schemas: { [schemaId]: schema },
      credentialDefinitions: { [credentialDefinitionId]: credentialDefinition },
    })

    const verified = anoncreds.verifyPresentation({
      presentation,
      presentationRequest,
      schemas: [schema],
      schemaIds: [schemaId],
      credentialDefinitions: [credentialDefinition],
      credentialDefinitionIds: [credentialDefinitionId],
    })
    expect(verified).toBe(true)

    const w3cCredential = anoncreds.credentialToW3c({ objectHandle: credential, issuerId })
    const proofDetails = anoncreds.w3cCredentialGetIntegrityProofDetails({ objectHandle: w3cCredential })
    expect(anoncreds.w3cCredentialProofGetAttribute({ objectHandle: proofDetails, name: 'schema_id' })).toBe(schemaId)
    expect(anoncreds.w3cCredentialProofGetAttribute({ objectHandle: proofDetails, name: 'rev_reg_id' })).toBeNull()

    const legacyCredential = anoncreds.credentialFromW3c({ objectHandle: w3cCredential })
    expect(JSON.parse(anoncreds.getJson({ objectHandle: legacyCredential }))).toMatchObject({
      schema_id: schemaId,
      cred_def_id: credentialDefinitionId,
    })

    // objects can be serialized and parsed again
    const roundTripped = anoncreds.credentialFromJson({ json: anoncreds.getJson({ objectHandle: credential }) })
    expect(anoncreds.getTypeName({ objectHandle: roundTripped })).toBe('Credential')
  })

  test('revocation flow with in-memory tails store', () => {
    const schema = anoncreds.createSchema({
      name: 'revocable',
      version: '1.0',
      issuerId,
      attributeNames: ['name'],
    })

    const { credentialDefinition, credentialDefinitionPrivate, keyCorrectnessProof } =
      anoncreds.createCredentialDefinition({
        schemaId,
        schema,
        tag: 'TAG',
        issuerId,
        signatureType: 'CL',
        supportRevocation: true,
      })

    const { revocationRegistryDefinition, revocationRegistryDefinitionPrivate } =
      anoncreds.createRevocationRegistryDefinition({
        credentialDefinition,
        credentialDefinitionId,
        issuerId,
        tag: 'tag',
        revocationRegistryType: 'CL_ACCUM',
        maximumCredentialNumber: 10,
      })

    const tailsHash = anoncreds.revocationRegistryDefinitionGetAttribute({
      objectHandle: revocationRegistryDefinition,
      name: 'tails_hash',
    })
    expect(tailsHash).toBeTruthy()

    const revocationStatusList = anoncreds.createRevocationStatusList({
      credentialDefinition,
      revocationRegistryDefinitionId,
      revocationRegistryDefinition,
      revocationRegistryDefinitionPrivate,
      issuerId,
      issuanceByDefault: true,
      timestamp: 12,
    })

    const credentialOffer = anoncreds.createCredentialOffer({
      schemaId,
      credentialDefinitionId,
      keyCorrectnessProof,
    })
    const linkSecret = anoncreds.createLinkSecret()
    const { credentialRequest, credentialRequestMetadata } = anoncreds.createCredentialRequest({
      entropy: 'entropy',
      credentialDefinition,
      linkSecret,
      linkSecretId: 'link-secret-id',
      credentialOffer,
    })

    const issuedCredential = anoncreds.createCredential({
      credentialDefinition,
      credentialDefinitionPrivate,
      credentialOffer,
      credentialRequest,
      attributeRawValues: { name: 'Alice' },
      revocationConfiguration: {
        revocationRegistryDefinition,
        revocationRegistryDefinitionPrivate,
        revocationStatusList,
        registryIndex: 9,
      },
    })

    const credential = anoncreds.processCredential({
      credential: issuedCredential,
      credentialRequestMetadata,
      linkSecret,
      credentialDefinition,
      revocationRegistryDefinition,
    })

    expect(anoncreds.credentialGetAttribute({ objectHandle: credential, name: 'rev_reg_index' })).toBe('9')

    // tails bytes are resolved from the in-memory store written by
    // createRevocationRegistryDefinition, no tails file needed
    const revocationState = anoncreds.createOrUpdateRevocationState({
      revocationRegistryDefinition,
      revocationStatusList,
      revocationRegistryIndex: 9,
      tailsPath: tailsHash,
    })

    const presentationRequest = anoncreds.presentationRequestFromJson({
      json: JSON.stringify({
        nonce: anoncreds.generateNonce(),
        name: 'presentation-request',
        version: '1.0',
        requested_attributes: {
          attr1_referent: { name: 'name' },
        },
        non_revoked: { from: 10, to: 200 },
      }),
    })

    const presentation = anoncreds.createPresentation({
      presentationRequest,
      credentials: [{ credential, timestamp: 12, revocationState }],
      credentialsProve: [{ entryIndex: 0, referent: 'attr1_referent', isPredicate: false, reveal: true }],
      selfAttest: {},
      linkSecret,
      schemas: { [schemaId]: schema },
      credentialDefinitions: { [credentialDefinitionId]: credentialDefinition },
    })

    const verified = anoncreds.verifyPresentation({
      presentation,
      presentationRequest,
      schemas: [schema],
      schemaIds: [schemaId],
      credentialDefinitions: [credentialDefinition],
      credentialDefinitionIds: [credentialDefinitionId],
      revocationRegistryDefinitions: [revocationRegistryDefinition],
      revocationRegistryDefinitionIds: [revocationRegistryDefinitionId],
      revocationStatusLists: [revocationStatusList],
    })
    expect(verified).toBe(true)
  })
})
