import 'reflect-metadata'

import type { KeyDidCreateOptions } from '@credo-ts/core'
import type {
  DidCommBasicMessageStateChangedEvent,
  DidCommConnectionRecord,
  DidCommCredentialExchangeRecord,
  DidCommCredentialStateChangedEvent,
  DidCommProofExchangeRecord,
  DidCommProofStateChangedEvent,
} from '@credo-ts/didcomm'
import {
  DidCommBasicMessageEventTypes,
  DidCommBasicMessageRole,
  DidCommConnectionEventTypes,
  DidCommCredentialEventTypes,
  DidCommCredentialState,
  DidCommProofEventTypes,
  DidCommProofState,
} from '@credo-ts/didcomm'
import { createWalletAgent, type WalletAgent } from './agent'

let agent: WalletAgent | undefined

const element = <T extends HTMLElement>(id: string): T => {
  const found = document.getElementById(id)
  if (!found) throw new Error(`Element ${id} not found`)
  return found as T
}

const statusPill = element<HTMLSpanElement>('status')
const logOutput = element<HTMLPreElement>('log')

function log(message: string) {
  const time = new Date().toLocaleTimeString()
  logOutput.textContent += `[${time}] ${message}\n`
  logOutput.scrollTop = logOutput.scrollHeight
}

function setStatus(text: string, kind: 'gray' | 'green' | 'yellow') {
  statusPill.textContent = text
  statusPill.className = `pill pill-${kind}`
}

function show(id: string) {
  element(id).classList.remove('hidden')
}

function statePill(state: string): string {
  const done = ['completed', 'done', DidCommCredentialState.Done, DidCommProofState.Done].includes(state)
  return `<span class="pill ${done ? 'pill-green' : 'pill-blue'}">${state}</span>`
}

async function refreshConnections() {
  if (!agent) return
  const connections = await agent.didcomm.connections.getAll()
  const list = element<HTMLUListElement>('connections-list')
  const select = element<HTMLSelectElement>('message-connection')

  list.innerHTML = connections.length ? '' : '<li class="empty">No connections yet</li>'
  const previousSelection = select.value
  select.innerHTML = ''

  for (const connection of connections) {
    const item = document.createElement('li')
    item.innerHTML = `<span>${connection.theirLabel ?? 'Unknown agent'} <span class="mono">${connection.id}</span></span>${statePill(connection.state)}`
    list.appendChild(item)

    const option = document.createElement('option')
    option.value = connection.id
    option.textContent = connection.theirLabel ?? connection.id
    select.appendChild(option)
  }

  if (previousSelection) select.value = previousSelection
}

async function refreshCredentials() {
  if (!agent) return
  const exchanges = await agent.didcomm.credentials.getAll()
  const list = element<HTMLUListElement>('credentials-list')
  list.innerHTML = exchanges.length ? '' : '<li class="empty">No credential exchanges yet</li>'

  for (const exchange of exchanges) {
    const item = document.createElement('li')
    const attributes = (exchange.credentialAttributes ?? [])
      .map((attribute) => `${attribute.name}: ${attribute.value}`)
      .join(', ')
    item.innerHTML = `<span>${attributes || 'Credential'} <span class="mono">${exchange.id}</span></span>${statePill(exchange.state)}`

    if (exchange.state === DidCommCredentialState.OfferReceived) {
      const accept = document.createElement('button')
      accept.className = 'small'
      accept.textContent = 'Accept offer'
      accept.onclick = () => acceptCredentialOffer(exchange)
      item.appendChild(accept)
    }

    list.appendChild(item)
  }

  const stored = await agent.w3cCredentials.getAll()
  const storedList = element<HTMLUListElement>('stored-credentials-list')
  storedList.innerHTML = stored.length ? '' : '<li class="empty">No stored credentials</li>'
  for (const record of stored) {
    const item = document.createElement('li')
    const credentialType = record.firstCredential.type
    const types = Array.isArray(credentialType) ? credentialType.join(', ') : `${credentialType}`
    item.innerHTML = `<span>${types} <span class="mono">${record.id}</span></span><span class="pill pill-green">stored</span>`
    storedList.appendChild(item)
  }
}

async function refreshProofs() {
  if (!agent) return
  const exchanges = await agent.didcomm.proofs.getAll()
  const list = element<HTMLUListElement>('proofs-list')
  list.innerHTML = exchanges.length ? '' : '<li class="empty">No proof exchanges yet</li>'

  for (const exchange of exchanges) {
    const item = document.createElement('li')
    item.innerHTML = `<span>Proof <span class="mono">${exchange.id}</span></span>${statePill(exchange.state)}`

    if (exchange.state === DidCommProofState.RequestReceived) {
      const accept = document.createElement('button')
      accept.className = 'small'
      accept.textContent = 'Accept request'
      accept.onclick = () => acceptProofRequest(exchange)
      item.appendChild(accept)
    }

    list.appendChild(item)
  }
}

async function refreshAll() {
  await Promise.all([refreshConnections(), refreshCredentials(), refreshProofs()])
}

async function acceptCredentialOffer(exchange: DidCommCredentialExchangeRecord) {
  if (!agent) return
  try {
    log(`Accepting credential offer ${exchange.id}`)
    await agent.didcomm.credentials.acceptOffer({ credentialExchangeRecordId: exchange.id })
  } catch (error) {
    log(`Error accepting credential offer: ${error}`)
  }
}

async function acceptProofRequest(exchange: DidCommProofExchangeRecord) {
  if (!agent) return
  try {
    log(`Selecting credentials for proof request ${exchange.id}`)
    const credentials = await agent.didcomm.proofs.selectCredentialsForRequest({
      proofExchangeRecordId: exchange.id,
    })
    await agent.didcomm.proofs.acceptRequest({
      proofExchangeRecordId: exchange.id,
      proofFormats: credentials.proofFormats,
    })
    log('Proof request accepted')
  } catch (error) {
    log(`Error accepting proof request: ${error}`)
  }
}

function subscribeToEvents(walletAgent: WalletAgent) {
  walletAgent.events.on(DidCommConnectionEventTypes.DidCommConnectionStateChanged, async (event) => {
    const record = (event.payload as { connectionRecord: DidCommConnectionRecord }).connectionRecord
    log(`Connection ${record.id} -> ${record.state}`)
    await refreshConnections()
  })

  walletAgent.events.on<DidCommCredentialStateChangedEvent>(
    DidCommCredentialEventTypes.DidCommCredentialStateChanged,
    async (event) => {
      log(
        `Credential exchange ${event.payload.credentialExchangeRecord.id} -> ${event.payload.credentialExchangeRecord.state}`
      )
      await refreshCredentials()
    }
  )

  walletAgent.events.on<DidCommProofStateChangedEvent>(DidCommProofEventTypes.ProofStateChanged, async (event) => {
    log(`Proof exchange ${event.payload.proofRecord.id} -> ${event.payload.proofRecord.state}`)
    await refreshProofs()
  })

  walletAgent.events.on<DidCommBasicMessageStateChangedEvent>(
    DidCommBasicMessageEventTypes.DidCommBasicMessageStateChanged,
    (event) => {
      if (event.payload.basicMessageRecord.role === DidCommBasicMessageRole.Receiver) {
        log(`Received message: ${event.payload.message.content}`)
      }
    }
  )
}

/**
 * The wallet needs its own did so issuers can bind credentials to it
 * (credentialSubject.id), which is required for signing presentations.
 */
async function ensureWalletDid(walletAgent: WalletAgent): Promise<string> {
  const [existingDid] = await walletAgent.dids.getCreatedDids({ method: 'key' })
  if (existingDid) return existingDid.did

  const result = await walletAgent.dids.create<KeyDidCreateOptions>({
    method: 'key',
    options: { createKey: { type: { kty: 'OKP', crv: 'Ed25519' } } },
  })
  if (result.didState.state !== 'finished') {
    throw new Error(`Error creating wallet did: ${JSON.stringify(result.didState)}`)
  }

  return result.didState.did
}

async function initializeWallet() {
  const initButton = element<HTMLButtonElement>('init-button')
  initButton.disabled = true
  setStatus('initializing...', 'yellow')

  const mediatorInvitationUrl = element<HTMLInputElement>('mediator-url').value.trim() || undefined
  localStorage.setItem('mediatorInvitationUrl', mediatorInvitationUrl ?? '')
  const databaseName = element<HTMLInputElement>('database-name').value.trim() || undefined
  localStorage.setItem('databaseName', databaseName ?? '')

  try {
    agent = await createWalletAgent({ mediatorInvitationUrl, databaseName })
    subscribeToEvents(agent)
    await agent.initialize()

    setStatus('wallet open', 'green')
    log('Wallet initialized. Records are stored in IndexedDB, keys in the browser KMS.')
    if (mediatorInvitationUrl) log('Connected to mediator for inbound DIDComm.')

    const walletDid = await ensureWalletDid(agent)
    element<HTMLElement>('my-did').textContent = walletDid
    log(`Wallet did: ${walletDid}`)

    show('invitation-card')
    show('connections-card')
    show('credentials-card')
    show('proofs-card')
    await refreshAll()
  } catch (error) {
    setStatus('failed', 'gray')
    log(`Initialization failed: ${error}`)
    initButton.disabled = false
  }
}

async function receiveInvitation() {
  if (!agent) return
  const input = element<HTMLTextAreaElement>('invitation-url')
  const invitationUrl = input.value.trim()
  if (!invitationUrl) return

  try {
    log('Receiving invitation...')
    const { connectionRecord, outOfBandRecord } = await agent.didcomm.oob.receiveInvitationFromUrl(invitationUrl, {
      label: 'Credo demo extension',
    })
    log(`Invitation received (out-of-band ${outOfBandRecord.id})`)
    if (connectionRecord) log(`Connection ${connectionRecord.id} created`)
    input.value = ''
    await refreshAll()
  } catch (error) {
    log(`Error receiving invitation: ${error}`)
  }
}

async function sendBasicMessage() {
  if (!agent) return
  const connectionId = element<HTMLSelectElement>('message-connection').value
  const messageInput = element<HTMLInputElement>('message-text')
  if (!connectionId || !messageInput.value.trim()) return

  try {
    await agent.didcomm.basicMessages.sendMessage(connectionId, messageInput.value.trim())
    log(`Sent message: ${messageInput.value.trim()}`)
    messageInput.value = ''
  } catch (error) {
    log(`Error sending message: ${error}`)
  }
}

element<HTMLInputElement>('mediator-url').value = localStorage.getItem('mediatorInvitationUrl') ?? ''
element<HTMLInputElement>('database-name').value = localStorage.getItem('databaseName') ?? ''
element<HTMLButtonElement>('init-button').onclick = initializeWallet
element<HTMLButtonElement>('receive-invitation-button').onclick = receiveInvitation
element<HTMLButtonElement>('send-message-button').onclick = sendBasicMessage

log('Ready. Create or open the wallet to get started.')
