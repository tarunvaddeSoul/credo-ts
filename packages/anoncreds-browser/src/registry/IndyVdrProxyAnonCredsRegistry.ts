import type {
  AnonCredsRegistry,
  AnonCredsRevocationRegistryDefinition,
  AnonCredsRevocationStatusList,
  GetCredentialDefinitionReturn,
  GetRevocationRegistryDefinitionReturn,
  GetRevocationStatusListReturn,
  GetSchemaReturn,
  RegisterCredentialDefinitionOptions,
  RegisterCredentialDefinitionReturn,
  RegisterRevocationRegistryDefinitionOptions,
  RegisterRevocationRegistryDefinitionReturn,
  RegisterRevocationStatusListOptions,
  RegisterRevocationStatusListReturn,
  RegisterSchemaOptions,
  RegisterSchemaReturn,
} from '@credo-ts/anoncreds'
import {
  didIndyCredentialDefinitionIdRegex,
  didIndyRegex,
  didIndyRevocationRegistryIdRegex,
  didIndySchemaIdRegex,
  getUnqualifiedCredentialDefinitionId,
  getUnqualifiedRevocationRegistryDefinitionId,
  getUnqualifiedSchemaId,
  parseIndyCredentialDefinitionId,
  parseIndyRevocationRegistryId,
  parseIndySchemaId,
  unqualifiedCredentialDefinitionIdRegex,
  unqualifiedRevocationRegistryIdRegex,
  unqualifiedSchemaIdRegex,
} from '@credo-ts/anoncreds'
import type { AgentContext } from '@credo-ts/core'
import { CredoError } from '@credo-ts/core'

const indyVdrProxyAnonCredsRegistryIdentifierRegex = new RegExp(
  [
    didIndyRegex,
    didIndySchemaIdRegex,
    unqualifiedSchemaIdRegex,
    didIndyCredentialDefinitionIdRegex,
    unqualifiedCredentialDefinitionIdRegex,
    unqualifiedRevocationRegistryIdRegex,
    didIndyRevocationRegistryIdRegex,
  ]
    .map((r) => r.source)
    .join('|')
)

// same shape as @credo-ts/indy-vdr's getDidIndySchemaId/getDidIndyCredentialDefinitionId
function getDidIndySchemaId(namespace: string, unqualifiedDid: string, name: string, version: string) {
  return `did:indy:${namespace}:${unqualifiedDid}/anoncreds/v0/SCHEMA/${name}/${version}`
}

function getDidIndyCredentialDefinitionId(
  namespace: string,
  unqualifiedDid: string,
  schemaSeqNo: string | number,
  tag: string
) {
  return `did:indy:${namespace}:${unqualifiedDid}/anoncreds/v0/CLAIM_DEF/${schemaSeqNo}/${tag}`
}

type RevocationRegistryDelta = {
  accum: string
  issued: number[]
  revoked: number[]
  txnTime: number
}

// biome-ignore lint/suspicious/noExplicitAny: untyped ledger reply envelope
type LedgerReply = { op?: string; result?: any }

export interface IndyVdrProxyAnonCredsRegistryOptions {
  /**
   * Base url of the indy-vdr-proxy server, e.g. https://proxy.example.com
   */
  proxyBaseUrl: string

  /**
   * Indy namespace to use as path prefix for proxies running in multi-ledger mode
   * (e.g. 'bcovrin:test'). Used for legacy unqualified identifiers. For did:indy
   * identifiers the namespace from the identifier takes precedence. Leave unset for
   * proxies serving a single ledger.
   */
  indyNamespace?: string
}

/**
 * AnonCredsRegistry that resolves Indy ledger objects over HTTP via an indy-vdr-proxy
 * server (https://github.com/hyperledger-indy/indy-vdr/tree/main/indy-vdr-proxy),
 * so it can run on platforms where native indy-vdr is not available (e.g. browsers).
 *
 * Resolution only, registration is not supported.
 */
export class IndyVdrProxyAnonCredsRegistry implements AnonCredsRegistry {
  public readonly methodName = 'indy'
  public readonly supportedIdentifier = indyVdrProxyAnonCredsRegistryIdentifierRegex
  public readonly allowsCaching = true
  public readonly allowsLocalRecord = true

  private readonly proxyBaseUrl: string
  private readonly indyNamespace?: string

  public constructor(options: IndyVdrProxyAnonCredsRegistryOptions) {
    this.proxyBaseUrl = options.proxyBaseUrl.replace(/\/+$/, '')
    this.indyNamespace = options.indyNamespace
  }

  private baseUrl(namespace?: string): string {
    const ns = namespace ?? this.indyNamespace
    return ns ? `${this.proxyBaseUrl}/${ns}` : this.proxyBaseUrl
  }

  private async get(agentContext: AgentContext, url: string): Promise<LedgerReply> {
    const fetch = agentContext.config.agentDependencies.fetch
    const response = await fetch(url, { headers: { Accept: 'application/json' } })
    if (!response.ok) {
      throw new CredoError(`indy-vdr-proxy request to ${url} failed with status ${response.status}`)
    }
    return (await response.json()) as LedgerReply
  }

  private async submit(
    agentContext: AgentContext,
    namespace: string | undefined,
    operation: Record<string, unknown>,
    submitterDid: string
  ): Promise<LedgerReply> {
    const fetch = agentContext.config.agentDependencies.fetch
    const url = `${this.baseUrl(namespace)}/submit`
    const response = await fetch(url, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        operation,
        identifier: submitterDid,
        reqId: Date.now(),
        protocolVersion: 2,
      }),
    })
    if (!response.ok) {
      throw new CredoError(`indy-vdr-proxy request to ${url} failed with status ${response.status}`)
    }
    return (await response.json()) as LedgerReply
  }

  public async getSchema(agentContext: AgentContext, schemaId: string): Promise<GetSchemaReturn> {
    try {
      const { did, namespaceIdentifier, schemaName, schemaVersion, namespace } = parseIndySchemaId(schemaId)
      const legacySchemaId = getUnqualifiedSchemaId(namespaceIdentifier, schemaName, schemaVersion)

      agentContext.config.logger.trace(`Getting schema '${schemaId}' from indy-vdr-proxy`)

      const response = await this.get(
        agentContext,
        `${this.baseUrl(namespace)}/schema/${encodeURIComponent(legacySchemaId)}`
      )
      const result = response.result

      if (!result?.data || !('attr_names' in result.data)) {
        agentContext.config.logger.error(`Schema '${schemaId}' not found on proxied ledger`)
        return {
          schemaId,
          resolutionMetadata: {
            error: 'notFound',
            message: `unable to find schema with id ${schemaId} on indy-vdr-proxy ${this.baseUrl(namespace)}`,
          },
          schemaMetadata: {},
        }
      }

      return {
        schema: {
          attrNames: result.data.attr_names,
          name: result.data.name,
          version: result.data.version,
          issuerId: did,
        },
        schemaId,
        resolutionMetadata: {},
        schemaMetadata: {
          didIndyNamespace: namespace ?? this.indyNamespace,
          // NOTE: the seqNo is required by the cred def lookup and registration
          indyLedgerSeqNo: result.seqNo,
        },
      }
    } catch (error) {
      agentContext.config.logger.error(`Error retrieving schema '${schemaId}'`, { error, schemaId })
      return {
        schemaId,
        resolutionMetadata: {
          error: 'notFound',
          message: `unable to resolve schema: ${(error as Error).message}`,
        },
        schemaMetadata: {},
      }
    }
  }

  public async getCredentialDefinition(
    agentContext: AgentContext,
    credentialDefinitionId: string
  ): Promise<GetCredentialDefinitionReturn> {
    try {
      const { did, namespaceIdentifier, schemaSeqNo, tag, namespace } =
        parseIndyCredentialDefinitionId(credentialDefinitionId)
      const legacyCredentialDefinitionId = getUnqualifiedCredentialDefinitionId(namespaceIdentifier, schemaSeqNo, tag)

      agentContext.config.logger.trace(`Getting credential definition '${credentialDefinitionId}' from indy-vdr-proxy`)

      const response = await this.get(
        agentContext,
        `${this.baseUrl(namespace)}/cred_def/${encodeURIComponent(legacyCredentialDefinitionId)}`
      )
      const result = response.result

      const notFound = (): GetCredentialDefinitionReturn => {
        agentContext.config.logger.error(
          `Credential definition '${credentialDefinitionId}' not found on proxied ledger`
        )
        return {
          credentialDefinitionId,
          credentialDefinitionMetadata: {},
          resolutionMetadata: {
            error: 'notFound',
            message: `unable to resolve credential definition with id ${credentialDefinitionId} on indy-vdr-proxy ${this.baseUrl(namespace)}`,
          },
        }
      }

      if (!result?.data || !('primary' in result.data)) return notFound()

      const schema = await this.fetchIndySchemaWithSeqNo(agentContext, namespace, result.ref)
      if (!schema) return notFound()

      const schemaId = credentialDefinitionId.startsWith('did:indy:')
        ? // namespace is always defined for did:indy identifiers
          getDidIndySchemaId(namespace as string, schema.schemaDid, schema.name, schema.version)
        : getUnqualifiedSchemaId(schema.schemaDid, schema.name, schema.version)

      return {
        credentialDefinitionId,
        credentialDefinition: {
          issuerId: did,
          schemaId,
          tag: result.tag,
          type: 'CL',
          value: result.data,
        },
        credentialDefinitionMetadata: {
          didIndyNamespace: namespace ?? this.indyNamespace,
        },
        resolutionMetadata: {},
      }
    } catch (error) {
      agentContext.config.logger.error(`Error retrieving credential definition '${credentialDefinitionId}'`, {
        error,
        credentialDefinitionId,
      })
      return {
        credentialDefinitionId,
        credentialDefinitionMetadata: {},
        resolutionMetadata: {
          error: 'notFound',
          message: `unable to resolve credential definition: ${(error as Error).message}`,
        },
      }
    }
  }

  public async getRevocationRegistryDefinition(
    agentContext: AgentContext,
    revocationRegistryDefinitionId: string
  ): Promise<GetRevocationRegistryDefinitionReturn> {
    try {
      const { did, namespaceIdentifier, schemaSeqNo, credentialDefinitionTag, revocationRegistryTag, namespace } =
        parseIndyRevocationRegistryId(revocationRegistryDefinitionId)
      const legacyRevocationRegistryId = getUnqualifiedRevocationRegistryDefinitionId(
        namespaceIdentifier,
        schemaSeqNo,
        credentialDefinitionTag,
        revocationRegistryTag
      )

      agentContext.config.logger.trace(
        `Getting revocation registry definition '${revocationRegistryDefinitionId}' from indy-vdr-proxy`
      )

      const response = await this.get(
        agentContext,
        `${this.baseUrl(namespace)}/rev_reg_def/${encodeURIComponent(legacyRevocationRegistryId)}`
      )
      const result = response.result

      if (!result?.data || !('value' in result.data)) {
        agentContext.config.logger.error(
          `Revocation registry definition '${revocationRegistryDefinitionId}' not found on proxied ledger`
        )
        return {
          revocationRegistryDefinitionId,
          revocationRegistryDefinitionMetadata: {},
          resolutionMetadata: {
            error: 'notFound',
            message: `unable to resolve revocation registry definition with id ${revocationRegistryDefinitionId} on indy-vdr-proxy ${this.baseUrl(namespace)}`,
          },
        }
      }

      const credentialDefinitionId = revocationRegistryDefinitionId.startsWith('did:indy:')
        ? getDidIndyCredentialDefinitionId(
            namespace as string,
            namespaceIdentifier,
            schemaSeqNo,
            credentialDefinitionTag
          )
        : getUnqualifiedCredentialDefinitionId(namespaceIdentifier, schemaSeqNo, credentialDefinitionTag)

      const revocationRegistryDefinition: AnonCredsRevocationRegistryDefinition = {
        issuerId: did,
        revocDefType: result.data.revocDefType,
        value: {
          maxCredNum: result.data.value.maxCredNum,
          tailsHash: result.data.value.tailsHash,
          tailsLocation: result.data.value.tailsLocation,
          publicKeys: {
            accumKey: {
              z: result.data.value.publicKeys.accumKey.z,
            },
          },
        },
        tag: result.data.tag,
        credDefId: credentialDefinitionId,
      }

      return {
        revocationRegistryDefinitionId,
        revocationRegistryDefinition,
        revocationRegistryDefinitionMetadata: {
          issuanceType: result.data.value.issuanceType,
          didIndyNamespace: namespace ?? this.indyNamespace,
        },
        resolutionMetadata: {},
      }
    } catch (error) {
      agentContext.config.logger.error(
        `Error retrieving revocation registry definition '${revocationRegistryDefinitionId}'`,
        { error, revocationRegistryDefinitionId }
      )
      return {
        revocationRegistryDefinitionId,
        revocationRegistryDefinitionMetadata: {},
        resolutionMetadata: {
          error: 'notFound',
          message: `unable to resolve revocation registry definition: ${(error as Error).message}`,
        },
      }
    }
  }

  public async getRevocationStatusList(
    agentContext: AgentContext,
    revocationRegistryId: string,
    timestamp: number
  ): Promise<GetRevocationStatusListReturn> {
    try {
      const { namespaceIdentifier, schemaSeqNo, credentialDefinitionTag, revocationRegistryTag, namespace } =
        parseIndyRevocationRegistryId(revocationRegistryId)
      const legacyRevocationRegistryId = getUnqualifiedRevocationRegistryDefinitionId(
        namespaceIdentifier,
        schemaSeqNo,
        credentialDefinitionTag,
        revocationRegistryTag
      )

      agentContext.config.logger.trace(
        `Getting revocation status list for '${revocationRegistryId}' at ${timestamp} from indy-vdr-proxy`
      )

      // the proxy GET rev_reg_delta route always uses `to = now`, so submit a prepared
      // GET_REVOC_REG_DELTA request to resolve at the requested timestamp
      const response = await this.submit(
        agentContext,
        namespace,
        {
          type: '117',
          revocRegDefId: legacyRevocationRegistryId,
          to: timestamp,
        },
        namespaceIdentifier
      )
      const result = response.result

      if (result?.type !== '117' || !result?.data?.value?.accum_to || !result?.txnTime) {
        agentContext.config.logger.error(
          `Error retrieving revocation registry delta '${revocationRegistryId}' from proxied ledger, potentially revocation interval ends before revocation registry creation`
        )
        return {
          resolutionMetadata: {
            error: 'notFound',
            message: `Error retrieving revocation registry delta '${revocationRegistryId}' from ledger, potentially revocation interval ends before revocation registry creation`,
          },
          revocationStatusListMetadata: {},
        }
      }

      const delta: RevocationRegistryDelta = {
        revoked: result.data.value.revoked ?? [],
        issued: result.data.value.issued ?? [],
        accum: result.data.value.accum_to.value.accum,
        txnTime: result.txnTime,
      }

      const { revocationRegistryDefinition, revocationRegistryDefinitionMetadata, resolutionMetadata } =
        await this.getRevocationRegistryDefinition(agentContext, revocationRegistryId)

      if (
        !revocationRegistryDefinition ||
        !revocationRegistryDefinitionMetadata.issuanceType ||
        typeof revocationRegistryDefinitionMetadata.issuanceType !== 'string'
      ) {
        return {
          resolutionMetadata: {
            error: 'notFound',
            message: `error resolving revocation registry definition with id ${revocationRegistryId}: ${resolutionMetadata.error} ${resolutionMetadata.message}`,
          },
          revocationStatusListMetadata: {},
        }
      }

      const isIssuanceByDefault = revocationRegistryDefinitionMetadata.issuanceType === 'ISSUANCE_BY_DEFAULT'

      return {
        resolutionMetadata: {},
        revocationStatusList: anonCredsRevocationStatusListFromIndyVdr(
          revocationRegistryId,
          revocationRegistryDefinition,
          delta,
          isIssuanceByDefault
        ),
        revocationStatusListMetadata: {
          didIndyNamespace: namespace ?? this.indyNamespace,
        },
      }
    } catch (error) {
      agentContext.config.logger.error(`Error retrieving revocation registry status list '${revocationRegistryId}'`, {
        error,
        revocationRegistryId,
      })
      return {
        resolutionMetadata: {
          error: 'notFound',
          message: `unable to resolve revocation status list: ${(error as Error).message}`,
        },
        revocationStatusListMetadata: {},
      }
    }
  }

  public async registerSchema(
    _agentContext: AgentContext,
    options: RegisterSchemaOptions
  ): Promise<RegisterSchemaReturn> {
    return {
      schemaMetadata: {},
      registrationMetadata: {},
      schemaState: {
        state: 'failed',
        schema: options.schema,
        reason: 'registration is not supported by IndyVdrProxyAnonCredsRegistry',
      },
    }
  }

  public async registerCredentialDefinition(
    _agentContext: AgentContext,
    options: RegisterCredentialDefinitionOptions
  ): Promise<RegisterCredentialDefinitionReturn> {
    return {
      credentialDefinitionMetadata: {},
      registrationMetadata: {},
      credentialDefinitionState: {
        state: 'failed',
        credentialDefinition: options.credentialDefinition,
        reason: 'registration is not supported by IndyVdrProxyAnonCredsRegistry',
      },
    }
  }

  public async registerRevocationRegistryDefinition(
    _agentContext: AgentContext,
    options: RegisterRevocationRegistryDefinitionOptions
  ): Promise<RegisterRevocationRegistryDefinitionReturn> {
    return {
      revocationRegistryDefinitionMetadata: {},
      registrationMetadata: {},
      revocationRegistryDefinitionState: {
        state: 'failed',
        revocationRegistryDefinition: options.revocationRegistryDefinition,
        reason: 'registration is not supported by IndyVdrProxyAnonCredsRegistry',
      },
    }
  }

  public async registerRevocationStatusList(
    _agentContext: AgentContext,
    options: RegisterRevocationStatusListOptions
  ): Promise<RegisterRevocationStatusListReturn> {
    return {
      revocationStatusListMetadata: {},
      registrationMetadata: {},
      revocationStatusListState: {
        state: 'failed',
        revocationStatusList: options.revocationStatusList,
        reason: 'registration is not supported by IndyVdrProxyAnonCredsRegistry',
      },
    }
  }

  private async fetchIndySchemaWithSeqNo(
    agentContext: AgentContext,
    namespace: string | undefined,
    seqNo: number
  ): Promise<{ schemaDid: string; name: string; version: string } | undefined> {
    const response = await this.get(agentContext, `${this.baseUrl(namespace)}/txn/DOMAIN/${seqNo}`)
    const data = response.result?.data
    const schema = data?.txn?.data?.data

    // '101' is the transaction type for schemas
    if (data?.txn?.type !== '101' || !data.txn.metadata?.from || !schema?.name || !schema.version) {
      agentContext.config.logger.error(`Could not get schema from ledger for seq no ${seqNo}`)
      return undefined
    }

    return {
      schemaDid: data.txn.metadata.from,
      name: schema.name,
      version: schema.version,
    }
  }
}

function anonCredsRevocationStatusListFromIndyVdr(
  revocationRegistryDefinitionId: string,
  revocationRegistryDefinition: AnonCredsRevocationRegistryDefinition,
  delta: RevocationRegistryDelta,
  isIssuanceByDefault: boolean
): AnonCredsRevocationStatusList {
  if (Math.max(...delta.issued, ...delta.revoked) > revocationRegistryDefinition.value.maxCredNum) {
    throw new CredoError(
      `Highest delta index '${Math.max(
        ...delta.issued,
        ...delta.revoked
      )}' is too large for the Revocation registry maxCredNum '${revocationRegistryDefinition.value.maxCredNum}'`
    )
  }

  // 0 means unrevoked, 1 means revoked
  const defaultState = isIssuanceByDefault ? 0 : 1
  const revocationList = new Array(revocationRegistryDefinition.value.maxCredNum).fill(defaultState)

  for (const issued of delta.issued) {
    revocationList[issued] = 0
  }
  for (const revoked of delta.revoked) {
    revocationList[revoked] = 1
  }

  return {
    issuerId: revocationRegistryDefinition.issuerId,
    currentAccumulator: delta.accum,
    revRegDefId: revocationRegistryDefinitionId,
    revocationList,
    timestamp: delta.txnTime,
  }
}
