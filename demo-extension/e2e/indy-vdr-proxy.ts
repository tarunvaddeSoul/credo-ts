/**
 * indy-vdr-proxy lookalike backed by the real BCovrin test ledger.
 *
 * The demo issuer in local-agent.ts serves a fake proxy on port 8080 from its in-memory
 * registry, which cannot resolve AnonCreds objects that were written to a public ledger.
 * This server speaks the same subset of the indy-vdr-proxy REST API that
 * IndyVdrProxyAnonCredsRegistry calls, but answers from indy-vdr:
 *
 *   GET  /schema/{legacySchemaId}
 *   GET  /cred_def/{legacyCredentialDefinitionId}
 *   GET  /rev_reg_def/{legacyRevocationRegistryId}
 *   GET  /txn/DOMAIN/{seqNo}
 *   POST /submit
 *
 * Every route is also served under an arbitrary namespace prefix (/bcovrin:test/cred_def/...)
 * because the registry prefixes the path when an indyNamespace is configured.
 */
import { existsSync, readFileSync } from 'node:fs'
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const indyVdrRequire = createRequire(join(dirname(fileURLToPath(import.meta.url)), '../../packages/indy-vdr/'))
const {
  PoolCreate,
  GetSchemaRequest,
  GetCredentialDefinitionRequest,
  GetRevocationRegistryDefinitionRequest,
  GetRevocationRegistryDeltaRequest,
  GetTransactionRequest,
  CustomRequest,
  // biome-ignore lint/suspicious/noExplicitAny: native module loaded outside this package's dependency graph
} = indyVdrRequire('@hyperledger/indy-vdr-nodejs') as any

const PORT = Number(process.env.INDY_VDR_PROXY_PORT ?? 8081)
const GENESIS_URL = process.env.INDY_VDR_PROXY_GENESIS_URL ?? 'http://test.bcovrin.vonx.io/genesis'
const GENESIS_FILE =
  process.env.INDY_VDR_PROXY_GENESIS_FILE ??
  '/Users/tarunvadde/Development/Soulverse/soulwallet/src/providers/AriesAgent/networks/indy/bcovrin-test/genesisTransactions.ts'

const ROUTES = ['schema', 'cred_def', 'rev_reg_def', 'txn', 'submit']

function log(message: string) {
  process.stdout.write(`[indy-vdr-proxy] ${message}\n`)
}

// biome-ignore lint/suspicious/noExplicitAny: untyped ledger reply envelope
type LedgerReply = { op?: string; result?: any }

// biome-ignore lint/suspicious/noExplicitAny: indy-vdr pool handle is untyped here
let pool: any

async function loadGenesis(): Promise<string> {
  try {
    const response = await fetch(GENESIS_URL)
    if (!response.ok) throw new Error(`status ${response.status}`)
    const transactions = await response.text()
    if (!transactions.trim()) throw new Error('empty body')
    log(`genesis loaded from ${GENESIS_URL}`)
    return transactions
  } catch (error) {
    log(`genesis fetch from ${GENESIS_URL} failed (${(error as Error).message})`)
  }

  if (!existsSync(GENESIS_FILE)) {
    throw new Error(
      `unable to fetch genesis from ${GENESIS_URL} and no fallback at ${GENESIS_FILE}, set INDY_VDR_PROXY_GENESIS_FILE`
    )
  }

  const transactions = extractGenesisTemplateLiteral(readFileSync(GENESIS_FILE, 'utf8'))
  log(`genesis loaded from fallback file ${GENESIS_FILE}`)
  return transactions
}

/** The mobile wallet keeps its genesis in a .ts file as a single exported template literal. */
function extractGenesisTemplateLiteral(source: string): string {
  const open = source.indexOf('`')
  const close = source.indexOf('`', open + 1)
  if (open === -1 || close === -1) throw new Error(`no template literal found in ${GENESIS_FILE}`)
  return source.slice(open + 1, close)
}

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Accept, Content-Type',
  })
  res.end(JSON.stringify(body))
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = ''
    req.on('data', (chunk) => {
      data += chunk
    })
    req.on('end', () => resolve(data))
    req.on('error', reject)
  })
}

// biome-ignore lint/suspicious/noExplicitAny: indy-vdr request objects are untyped here
async function submitRequest(request: any): Promise<LedgerReply> {
  return (await pool.submitRequest(request)) as LedgerReply
}

// biome-ignore lint/suspicious/noExplicitAny: raw request body from the registry
function buildSubmittedRequest(body: any) {
  const operation = body?.operation
  if (operation?.type === '117') {
    return new GetRevocationRegistryDeltaRequest({
      submitterDid: body.identifier,
      revocationRegistryId: operation.revocRegDefId,
      fromTs: operation.from,
      toTs: operation.to,
    })
  }

  return new CustomRequest({ customRequest: body })
}

async function handleRequest(req: IncomingMessage, res: ServerResponse) {
  const url = new URL(req.url ?? '/', `http://localhost:${PORT}`)

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Accept, Content-Type',
    })
    res.end()
    return
  }

  let segments = url.pathname.split('/').filter(Boolean).map(decodeURIComponent)
  if (segments.length > 0 && !ROUTES.includes(segments[0])) {
    segments = segments.slice(1)
  }

  try {
    if (req.method === 'GET' && segments[0] === 'schema' && segments[1]) {
      return sendJson(res, 200, await submitRequest(new GetSchemaRequest({ schemaId: segments[1] })))
    }

    if (req.method === 'GET' && segments[0] === 'cred_def' && segments[1]) {
      return sendJson(
        res,
        200,
        await submitRequest(new GetCredentialDefinitionRequest({ credentialDefinitionId: segments[1] }))
      )
    }

    if (req.method === 'GET' && segments[0] === 'rev_reg_def' && segments[1]) {
      return sendJson(
        res,
        200,
        await submitRequest(new GetRevocationRegistryDefinitionRequest({ revocationRegistryId: segments[1] }))
      )
    }

    if (req.method === 'GET' && segments[0] === 'txn' && segments[1] === 'DOMAIN' && segments[2]) {
      if (!/^\d+$/.test(segments[2])) return sendJson(res, 400, { error: `Invalid seqNo ${segments[2]}` })

      return sendJson(
        res,
        200,
        await submitRequest(new GetTransactionRequest({ ledgerType: 1, seqNo: Number(segments[2]) }))
      )
    }

    if (req.method === 'POST' && segments[0] === 'submit') {
      const body = JSON.parse((await readBody(req)) || '{}')
      let request: unknown
      try {
        request = buildSubmittedRequest(body)
      } catch (error) {
        return sendJson(res, 400, {
          error: `Unable to build indy-vdr request for operation type ${body?.operation?.type}: ${(error as Error).message}`,
        })
      }

      return sendJson(res, 200, await submitRequest(request))
    }

    return sendJson(res, 404, { error: `Unknown proxy path ${url.pathname}` })
  } catch (error) {
    return sendJson(res, 502, { error: `Ledger request failed: ${(error as Error).message}` })
  }
}

async function main() {
  const transactions = await loadGenesis()
  pool = new PoolCreate({ parameters: { transactions } })

  await new Promise<void>((resolve) => {
    createServer(handleRequest).listen(PORT, resolve)
  })

  const baseUrl = `http://localhost:${PORT}`
  log(`listening on ${baseUrl}`)
  log(`namespace-prefixed paths work too, e.g. ${baseUrl}/bcovrin:test/cred_def/{id}`)
  log(`try: curl -s "${baseUrl}/cred_def/JM9L6HL2QCexjbn9WB46h9%3A3%3ACL%3A2921997%3AGloberacers%7CEvents%7CSoulVerse"`)
}

await main()
