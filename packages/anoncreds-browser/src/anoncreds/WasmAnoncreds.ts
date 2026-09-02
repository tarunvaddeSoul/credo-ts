import type {
  Anoncreds,
  AnoncredsErrorObject,
  NativeCredentialEntry,
  NativeCredentialProve,
  NativeCredentialRevocationConfig,
  NativeNonRevokedIntervalOverride,
} from '@hyperledger/anoncreds-shared'
import { ObjectHandle } from '@hyperledger/anoncreds-shared'

import * as wasm from '../../wasm/pkg/anoncreds_wasm.js'

export type ResolveTailsFile = (tailsPath: string) => Uint8Array | undefined

interface StoredObject {
  typeName: string
  json: string
}

/**
 * Implements the Anoncreds interface from @hyperledger/anoncreds-shared on top of the
 * anoncreds-rs WASM build. Objects are stored as JSON strings in a handle registry on the
 * JS side, the WASM functions are stateless JSON-in/JSON-out.
 */
export class WasmAnoncreds implements Anoncreds {
  private objects = new Map<number, StoredObject>()
  private nextHandle = 1
  private lastError?: Error

  public constructor(private options: { resolveTailsFile?: ResolveTailsFile } = {}) {}

  private insert(typeName: string, json: string): ObjectHandle {
    const handle = this.nextHandle++
    this.objects.set(handle, { typeName, json })
    return new ObjectHandle(handle)
  }

  private stored(objectHandle: ObjectHandle | number): StoredObject {
    const handle = typeof objectHandle === 'number' ? objectHandle : objectHandle.handle
    const stored = this.objects.get(handle)
    if (!stored) throw new Error(`Invalid object handle: ${handle}`)
    return stored
  }

  private json(objectHandle: ObjectHandle | number): string {
    return this.stored(objectHandle).json
  }

  private jsonOptional(objectHandle?: ObjectHandle): string | undefined {
    return objectHandle ? this.json(objectHandle) : undefined
  }

  private handleMapToJson(map: Record<string, ObjectHandle>): string {
    return JSON.stringify(Object.fromEntries(Object.entries(map).map(([id, handle]) => [id, this.json(handle)])))
  }

  private zippedMapToJson(ids: string[], handles: ObjectHandle[]): string {
    if (ids.length !== handles.length) {
      throw new Error('Inconsistent lengths for object ids and handles')
    }
    return JSON.stringify(Object.fromEntries(ids.map((id, index) => [id, this.json(handles[index])])))
  }

  private credentialEntriesToJson(entries: NativeCredentialEntry[]): string {
    return JSON.stringify(
      entries.map((entry) => ({
        credential: this.json(entry.credential),
        timestamp: entry.timestamp,
        revocationState: this.jsonOptional(entry.revocationState),
      }))
    )
  }

  private call<T>(fn: () => T): T {
    try {
      return fn()
    } catch (error) {
      this.lastError = error instanceof Error ? error : new Error(String(error))
      throw error
    }
  }

  private fromJson(typeName: string, json: string): ObjectHandle {
    return this.call(() => this.insert(typeName, wasm.object_from_json(typeName, json)))
  }

  public version(): string {
    return wasm.version()
  }

  public getCurrentError(): AnoncredsErrorObject {
    return { code: 100, message: this.lastError?.message ?? '' }
  }

  public setDefaultLogger(): void {
    // logging from the wasm module goes through console via panic hook only
  }

  public generateNonce(): string {
    return this.call(() => wasm.generate_nonce())
  }

  public createLinkSecret(): string {
    return this.call(() => wasm.create_link_secret())
  }

  public encodeCredentialAttributes(options: { attributeRawValues: string[] }): string[] {
    return this.call(() => wasm.encode_credential_attributes(options.attributeRawValues))
  }

  public createSchema(options: {
    name: string
    version: string
    issuerId: string
    attributeNames: string[]
  }): ObjectHandle {
    return this.call(() =>
      this.insert('Schema', wasm.create_schema(options.name, options.version, options.issuerId, options.attributeNames))
    )
  }

  public createCredentialDefinition(options: {
    schemaId: string
    schema: ObjectHandle
    tag: string
    issuerId: string
    signatureType: string
    supportRevocation: boolean
  }): {
    credentialDefinition: ObjectHandle
    credentialDefinitionPrivate: ObjectHandle
    keyCorrectnessProof: ObjectHandle
  } {
    return this.call(() => {
      const result: Record<string, string> = JSON.parse(
        wasm.create_credential_definition(
          options.schemaId,
          this.json(options.schema),
          options.tag,
          options.issuerId,
          options.signatureType,
          options.supportRevocation
        )
      )
      return {
        credentialDefinition: this.insert('CredentialDefinition', result.credentialDefinition),
        credentialDefinitionPrivate: this.insert('CredentialDefinitionPrivate', result.credentialDefinitionPrivate),
        keyCorrectnessProof: this.insert('KeyCorrectnessProof', result.keyCorrectnessProof),
      }
    })
  }

  public createCredentialOffer(options: {
    schemaId: string
    credentialDefinitionId: string
    keyCorrectnessProof: ObjectHandle
  }): ObjectHandle {
    return this.call(() =>
      this.insert(
        'CredentialOffer',
        wasm.create_credential_offer(
          options.schemaId,
          options.credentialDefinitionId,
          this.json(options.keyCorrectnessProof)
        )
      )
    )
  }

  public createCredentialRequest(options: {
    entropy?: string
    proverDid?: string
    credentialDefinition: ObjectHandle
    linkSecret: string
    linkSecretId: string
    credentialOffer: ObjectHandle
  }): { credentialRequest: ObjectHandle; credentialRequestMetadata: ObjectHandle } {
    return this.call(() => {
      const result: Record<string, string> = JSON.parse(
        wasm.create_credential_request(
          options.entropy,
          options.proverDid,
          this.json(options.credentialDefinition),
          options.linkSecret,
          options.linkSecretId,
          this.json(options.credentialOffer)
        )
      )
      return {
        credentialRequest: this.insert('CredentialRequest', result.credentialRequest),
        credentialRequestMetadata: this.insert('CredentialRequestMetadata', result.credentialRequestMetadata),
      }
    })
  }

  public createCredential(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionPrivate: ObjectHandle
    credentialOffer: ObjectHandle
    credentialRequest: ObjectHandle
    attributeRawValues: Record<string, string>
    attributeEncodedValues?: Record<string, string>
    revocationConfiguration?: NativeCredentialRevocationConfig
  }): ObjectHandle {
    return this.call(() =>
      this.insert(
        'Credential',
        wasm.create_credential(
          this.json(options.credentialDefinition),
          this.json(options.credentialDefinitionPrivate),
          this.json(options.credentialOffer),
          this.json(options.credentialRequest),
          JSON.stringify(options.attributeRawValues),
          options.attributeEncodedValues ? JSON.stringify(options.attributeEncodedValues) : undefined,
          this.jsonOptional(options.revocationConfiguration?.revocationRegistryDefinition),
          this.jsonOptional(options.revocationConfiguration?.revocationRegistryDefinitionPrivate),
          this.jsonOptional(options.revocationConfiguration?.revocationStatusList),
          options.revocationConfiguration?.registryIndex
        )
      )
    )
  }

  public processCredential(options: {
    credential: ObjectHandle
    credentialRequestMetadata: ObjectHandle
    linkSecret: string
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition?: ObjectHandle
  }): ObjectHandle {
    return this.call(() =>
      this.insert(
        'Credential',
        wasm.process_credential(
          this.json(options.credential),
          this.json(options.credentialRequestMetadata),
          options.linkSecret,
          this.json(options.credentialDefinition),
          this.jsonOptional(options.revocationRegistryDefinition)
        )
      )
    )
  }

  public createPresentation(options: {
    presentationRequest: ObjectHandle
    credentials: NativeCredentialEntry[]
    credentialsProve: NativeCredentialProve[]
    selfAttest: Record<string, string>
    linkSecret: string
    schemas: Record<string, ObjectHandle>
    credentialDefinitions: Record<string, ObjectHandle>
  }): ObjectHandle {
    return this.call(() =>
      this.insert(
        'Presentation',
        wasm.create_presentation(
          this.json(options.presentationRequest),
          this.credentialEntriesToJson(options.credentials),
          JSON.stringify(options.credentialsProve),
          JSON.stringify(options.selfAttest),
          options.linkSecret,
          this.handleMapToJson(options.schemas),
          this.handleMapToJson(options.credentialDefinitions)
        )
      )
    )
  }

  public verifyPresentation(options: {
    presentation: ObjectHandle
    presentationRequest: ObjectHandle
    schemas: ObjectHandle[]
    schemaIds: string[]
    credentialDefinitions: ObjectHandle[]
    credentialDefinitionIds: string[]
    revocationRegistryDefinitions?: ObjectHandle[]
    revocationRegistryDefinitionIds?: string[]
    revocationStatusLists?: ObjectHandle[]
    nonRevokedIntervalOverrides?: NativeNonRevokedIntervalOverride[]
  }): boolean {
    return this.call(() =>
      wasm.verify_presentation(
        this.json(options.presentation),
        this.json(options.presentationRequest),
        this.zippedMapToJson(options.schemaIds, options.schemas),
        this.zippedMapToJson(options.credentialDefinitionIds, options.credentialDefinitions),
        options.revocationRegistryDefinitions && options.revocationRegistryDefinitionIds
          ? this.zippedMapToJson(options.revocationRegistryDefinitionIds, options.revocationRegistryDefinitions)
          : undefined,
        options.revocationStatusLists
          ? JSON.stringify(options.revocationStatusLists.map((list) => this.json(list)))
          : undefined,
        options.nonRevokedIntervalOverrides ? JSON.stringify(options.nonRevokedIntervalOverrides) : undefined
      )
    )
  }

  public createRevocationRegistryDefinition(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionId: string
    issuerId: string
    tag: string
    revocationRegistryType: string
    maximumCredentialNumber: number
    tailsDirectoryPath?: string
  }): { revocationRegistryDefinition: ObjectHandle; revocationRegistryDefinitionPrivate: ObjectHandle } {
    return this.call(() => {
      const result: Record<string, string> = JSON.parse(
        wasm.create_revocation_registry_definition(
          this.json(options.credentialDefinition),
          options.credentialDefinitionId,
          options.tag,
          options.revocationRegistryType,
          options.maximumCredentialNumber
        )
      )
      return {
        revocationRegistryDefinition: this.insert('RevocationRegistryDefinition', result.revocationRegistryDefinition),
        revocationRegistryDefinitionPrivate: this.insert(
          'RevocationRegistryDefinitionPrivate',
          result.revocationRegistryDefinitionPrivate
        ),
      }
    })
  }

  public createRevocationStatusList(options: {
    credentialDefinition: ObjectHandle
    revocationRegistryDefinitionId: string
    revocationRegistryDefinition: ObjectHandle
    revocationRegistryDefinitionPrivate: ObjectHandle
    issuerId: string
    issuanceByDefault: boolean
    timestamp?: number
  }): ObjectHandle {
    return this.call(() =>
      this.insert(
        'RevocationStatusList',
        wasm.create_revocation_status_list(
          this.json(options.credentialDefinition),
          options.revocationRegistryDefinitionId,
          this.json(options.revocationRegistryDefinition),
          this.json(options.revocationRegistryDefinitionPrivate),
          options.issuanceByDefault,
          options.timestamp !== undefined ? BigInt(options.timestamp) : undefined
        )
      )
    )
  }

  public updateRevocationStatusListTimestampOnly(options: {
    timestamp: number
    currentRevocationStatusList: ObjectHandle
  }): ObjectHandle {
    return this.call(() =>
      this.insert(
        'RevocationStatusList',
        wasm.update_revocation_status_list_timestamp_only(
          BigInt(options.timestamp),
          this.json(options.currentRevocationStatusList)
        )
      )
    )
  }

  public updateRevocationStatusList(options: {
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition: ObjectHandle
    revocationRegistryDefinitionPrivate: ObjectHandle
    currentRevocationStatusList: ObjectHandle
    issued?: number[]
    revoked?: number[]
    timestamp?: number
  }): ObjectHandle {
    return this.call(() =>
      this.insert(
        'RevocationStatusList',
        wasm.update_revocation_status_list(
          this.json(options.credentialDefinition),
          this.json(options.revocationRegistryDefinition),
          this.json(options.revocationRegistryDefinitionPrivate),
          this.json(options.currentRevocationStatusList),
          options.issued ? new Uint32Array(options.issued) : undefined,
          options.revoked ? new Uint32Array(options.revoked) : undefined,
          options.timestamp !== undefined ? BigInt(options.timestamp) : undefined
        )
      )
    )
  }

  public createOrUpdateRevocationState(options: {
    revocationRegistryDefinition: ObjectHandle
    revocationStatusList: ObjectHandle
    revocationRegistryIndex: number
    tailsPath: string
    oldRevocationState?: ObjectHandle
    oldRevocationStatusList?: ObjectHandle
  }): ObjectHandle {
    return this.call(() =>
      this.insert(
        'CredentialRevocationState',
        wasm.create_or_update_revocation_state(
          this.json(options.revocationRegistryDefinition),
          this.json(options.revocationStatusList),
          options.revocationRegistryIndex,
          this.options.resolveTailsFile?.(options.tailsPath),
          options.tailsPath,
          this.jsonOptional(options.oldRevocationState),
          this.jsonOptional(options.oldRevocationStatusList)
        )
      )
    )
  }

  public credentialGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string | null {
    return this.call(() => wasm.credential_get_attribute(this.json(options.objectHandle), options.name) ?? null)
  }

  public revocationRegistryDefinitionGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string {
    return this.call(() =>
      wasm.revocation_registry_definition_get_attribute(this.json(options.objectHandle), options.name)
    )
  }

  public createW3cCredential(options: {
    credentialDefinition: ObjectHandle
    credentialDefinitionPrivate: ObjectHandle
    credentialOffer: ObjectHandle
    credentialRequest: ObjectHandle
    attributeRawValues: Record<string, string>
    revocationConfiguration?: NativeCredentialRevocationConfig
    w3cVersion?: string
  }): ObjectHandle {
    return this.call(() =>
      this.insert(
        'W3CCredential',
        wasm.create_w3c_credential(
          this.json(options.credentialDefinition),
          this.json(options.credentialDefinitionPrivate),
          this.json(options.credentialOffer),
          this.json(options.credentialRequest),
          JSON.stringify(options.attributeRawValues),
          this.jsonOptional(options.revocationConfiguration?.revocationRegistryDefinition),
          this.jsonOptional(options.revocationConfiguration?.revocationRegistryDefinitionPrivate),
          this.jsonOptional(options.revocationConfiguration?.revocationStatusList),
          options.revocationConfiguration?.registryIndex,
          options.w3cVersion
        )
      )
    )
  }

  public processW3cCredential(options: {
    credential: ObjectHandle
    credentialRequestMetadata: ObjectHandle
    linkSecret: string
    credentialDefinition: ObjectHandle
    revocationRegistryDefinition?: ObjectHandle
  }): ObjectHandle {
    return this.call(() =>
      this.insert(
        'W3CCredential',
        wasm.process_w3c_credential(
          this.json(options.credential),
          this.json(options.credentialRequestMetadata),
          options.linkSecret,
          this.json(options.credentialDefinition),
          this.jsonOptional(options.revocationRegistryDefinition)
        )
      )
    )
  }

  public createW3cPresentation(options: {
    presentationRequest: ObjectHandle
    credentials: NativeCredentialEntry[]
    credentialsProve: NativeCredentialProve[]
    linkSecret: string
    schemas: Record<string, ObjectHandle>
    credentialDefinitions: Record<string, ObjectHandle>
    w3cVersion?: string
  }): ObjectHandle {
    return this.call(() =>
      this.insert(
        'W3CPresentation',
        wasm.create_w3c_presentation(
          this.json(options.presentationRequest),
          this.credentialEntriesToJson(options.credentials),
          JSON.stringify(options.credentialsProve),
          options.linkSecret,
          this.handleMapToJson(options.schemas),
          this.handleMapToJson(options.credentialDefinitions),
          options.w3cVersion
        )
      )
    )
  }

  public verifyW3cPresentation(options: {
    presentation: ObjectHandle
    presentationRequest: ObjectHandle
    schemas: ObjectHandle[]
    schemaIds: string[]
    credentialDefinitions: ObjectHandle[]
    credentialDefinitionIds: string[]
    revocationRegistryDefinitions?: ObjectHandle[]
    revocationRegistryDefinitionIds?: string[]
    revocationStatusLists?: ObjectHandle[]
    nonRevokedIntervalOverrides?: NativeNonRevokedIntervalOverride[]
  }): boolean {
    return this.call(() =>
      wasm.verify_w3c_presentation(
        this.json(options.presentation),
        this.json(options.presentationRequest),
        this.zippedMapToJson(options.schemaIds, options.schemas),
        this.zippedMapToJson(options.credentialDefinitionIds, options.credentialDefinitions),
        options.revocationRegistryDefinitions && options.revocationRegistryDefinitionIds
          ? this.zippedMapToJson(options.revocationRegistryDefinitionIds, options.revocationRegistryDefinitions)
          : undefined,
        options.revocationStatusLists
          ? JSON.stringify(options.revocationStatusLists.map((list) => this.json(list)))
          : undefined,
        options.nonRevokedIntervalOverrides ? JSON.stringify(options.nonRevokedIntervalOverrides) : undefined
      )
    )
  }

  public credentialToW3c(options: { objectHandle: ObjectHandle; issuerId: string; w3cVersion?: string }): ObjectHandle {
    return this.call(() =>
      this.insert(
        'W3CCredential',
        wasm.credential_to_w3c(this.json(options.objectHandle), options.issuerId, options.w3cVersion)
      )
    )
  }

  public credentialFromW3c(options: { objectHandle: ObjectHandle }): ObjectHandle {
    return this.call(() => this.insert('Credential', wasm.credential_from_w3c(this.json(options.objectHandle))))
  }

  public w3cCredentialGetIntegrityProofDetails(options: { objectHandle: ObjectHandle }): ObjectHandle {
    return this.call(() =>
      this.insert(
        'CredentialProofInfo',
        wasm.w3c_credential_get_integrity_proof_details(this.json(options.objectHandle))
      )
    )
  }

  public w3cCredentialProofGetAttribute(options: { objectHandle: ObjectHandle; name: string }): string | null {
    return this.call(() => {
      const details = JSON.parse(this.json(options.objectHandle))
      const value = details[options.name]
      if (value === undefined || value === null) {
        if (['schema_id', 'cred_def_id', 'rev_reg_id', 'rev_reg_index', 'timestamp'].includes(options.name)) {
          return null
        }
        throw new Error(`Unsupported attribute: ${options.name}`)
      }
      return String(value)
    })
  }

  public presentationRequestFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('PresentationRequest', options.json)
  }

  public presentationFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('Presentation', options.json)
  }

  public w3cPresentationFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('W3CPresentation', options.json)
  }

  public schemaFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('Schema', options.json)
  }

  public credentialDefinitionFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('CredentialDefinition', options.json)
  }

  public credentialDefinitionPrivateFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('CredentialDefinitionPrivate', options.json)
  }

  public keyCorrectnessProofFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('KeyCorrectnessProof', options.json)
  }

  public credentialOfferFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('CredentialOffer', options.json)
  }

  public credentialRequestFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('CredentialRequest', options.json)
  }

  public credentialRequestMetadataFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('CredentialRequestMetadata', options.json)
  }

  public credentialFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('Credential', options.json)
  }

  public w3cCredentialFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('W3CCredential', options.json)
  }

  public revocationRegistryDefinitionFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('RevocationRegistryDefinition', options.json)
  }

  public revocationRegistryDefinitionPrivateFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('RevocationRegistryDefinitionPrivate', options.json)
  }

  public revocationRegistryFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('RevocationRegistry', options.json)
  }

  public revocationStatusListFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('RevocationStatusList', options.json)
  }

  public revocationStateFromJson(options: { json: string }): ObjectHandle {
    return this.fromJson('CredentialRevocationState', options.json)
  }

  public getJson(options: { objectHandle: ObjectHandle }): string {
    return this.json(options.objectHandle)
  }

  public getTypeName(options: { objectHandle: ObjectHandle }): string {
    return this.stored(options.objectHandle).typeName
  }

  public objectFree(options: { objectHandle: ObjectHandle }): void {
    this.objects.delete(options.objectHandle.handle)
  }
}
