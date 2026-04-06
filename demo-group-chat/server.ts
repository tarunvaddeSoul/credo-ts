import type { DemoAgent } from './agent-setup'
import { createAgent, makeV2Connection } from './agent-setup'
import { GroupMessagingEventTypes } from '@credo-ts/didcomm'
import type { GroupMessageReceivedEvent, GroupCreatedEvent } from '@credo-ts/didcomm'
import express from 'express'
import { createServer } from 'http'
import { WebSocketServer, type WebSocket } from 'ws'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const DEMO_PORT = 4000

interface ClientSocket {
  ws: WebSocket
  agentName: string | null
}

// ─── State ───────────────────────────────────────────────────────────

const agents: Record<string, DemoAgent> = {}
const connections: { aliceBobConnId: string; aliceCarolConnId: string } = {
  aliceBobConnId: '',
  aliceCarolConnId: '',
}
const clients: Set<ClientSocket> = new Set()

// ─── Agent Setup ─────────────────────────────────────────────────────

async function setup() {
  console.log('Starting Group Chat Demo...\n')
  console.log('Creating agents...')

  const alice = await createAgent('Alice', 4001)
  const bob = await createAgent('Bob', 4002)
  const carol = await createAgent('Carol', 4003)

  agents.alice = alice.agent
  agents.bob = bob.agent
  agents.carol = carol.agent

  console.log('\nEstablishing DIDComm v2 connections...')
  const [aliceBobId] = await makeV2Connection(alice.agent, bob.agent)
  console.log('  Alice <-> Bob connected')
  const [aliceCarolId] = await makeV2Connection(alice.agent, carol.agent)
  console.log('  Alice <-> Carol connected')

  connections.aliceBobConnId = aliceBobId
  connections.aliceCarolConnId = aliceCarolId

  // Let connections settle
  await new Promise((r) => setTimeout(r, 1000))

  // Subscribe to events on all agents
  for (const [name, agent] of Object.entries(agents)) {
    agent.events.on(GroupMessagingEventTypes.GroupMessageReceived, (event: GroupMessageReceivedEvent) => {
      const { messageRecord } = event.payload
      broadcast(name, {
        type: 'messageReceived',
        groupId: messageRecord.groupId,
        message: {
          id: messageRecord.id,
          content: messageRecord.content,
          senderDid: messageRecord.senderDid,
          sentTime: messageRecord.sentTime,
          epoch: messageRecord.epoch,
        },
      })
    })

    agent.events.on(GroupMessagingEventTypes.GroupCreated, (event: GroupCreatedEvent) => {
      const { groupRecord } = event.payload
      broadcast(name, {
        type: 'groupCreated',
        group: {
          groupId: groupRecord.groupId,
          name: groupRecord.name,
          members: groupRecord.members,
          epoch: groupRecord.epoch,
        },
      })
    })
  }

  console.log('\nAgents ready!\n')
}

// ─── Broadcast to WebSocket clients ──────────────────────────────────

function broadcast(agentName: string, message: Record<string, unknown>) {
  for (const client of clients) {
    if (client.agentName === agentName && client.ws.readyState === 1) {
      client.ws.send(JSON.stringify(message))
    }
  }
}

function sendTo(client: ClientSocket, message: Record<string, unknown>) {
  if (client.ws.readyState === 1) {
    client.ws.send(JSON.stringify(message))
  }
}

// ─── WebSocket Message Handler ───────────────────────────────────────

async function handleMessage(client: ClientSocket, data: string) {
  let msg: Record<string, unknown>
  try {
    msg = JSON.parse(data)
  } catch {
    return
  }

  const type = msg.type as string

  if (type === 'login') {
    const name = (msg.agent as string)?.toLowerCase()
    if (!agents[name]) {
      sendTo(client, { type: 'error', message: `Unknown agent: ${name}` })
      return
    }
    client.agentName = name

    // Get the agent's DID from its first connection
    const allConns = await agents[name].didcomm.connections.getAll()
    const did = allConns[0]?.did ?? 'unknown'

    sendTo(client, { type: 'loggedIn', agent: name, did })

    // Auto-send current groups
    const groups = await agents[name].modules.groupMessaging.getGroups()
    sendTo(client, {
      type: 'groups',
      groups: groups.map((g: Record<string, unknown>) => ({
        groupId: (g as any).groupId,
        name: (g as any).name,
        members: (g as any).members,
        epoch: (g as any).epoch,
        state: (g as any).state,
      })),
    })
    return
  }

  if (!client.agentName) {
    sendTo(client, { type: 'error', message: 'Not logged in' })
    return
  }

  const agent = agents[client.agentName]

  if (type === 'createGroup') {
    if (client.agentName !== 'alice') {
      sendTo(client, { type: 'error', message: 'Only Alice (admin) can create groups' })
      return
    }
    try {
      const group = await agent.modules.groupMessaging.createGroup({
        name: (msg.name as string) || 'Group Chat',
        memberConnectionIds: [connections.aliceBobConnId, connections.aliceCarolConnId],
      })
      sendTo(client, {
        type: 'groupCreated',
        group: {
          groupId: group.groupId,
          name: group.name,
          members: group.members,
          epoch: group.epoch,
        },
      })
    } catch (error) {
      sendTo(client, { type: 'error', message: `Failed to create group: ${error}` })
    }
    return
  }

  if (type === 'sendMessage') {
    try {
      const record = await agent.modules.groupMessaging.sendMessage(
        msg.groupId as string,
        msg.content as string
      )
      // Send confirmation back to the sender (they don't get their own event)
      sendTo(client, {
        type: 'messageSent',
        groupId: record.groupId,
        message: {
          id: record.id,
          content: record.content,
          senderDid: record.senderDid,
          sentTime: record.sentTime,
          epoch: record.epoch,
        },
      })
    } catch (error) {
      sendTo(client, { type: 'error', message: `Failed to send: ${error}` })
    }
    return
  }

  if (type === 'getGroups') {
    const groups = await agent.modules.groupMessaging.getGroups()
    sendTo(client, {
      type: 'groups',
      groups: groups.map((g: Record<string, unknown>) => ({
        groupId: (g as any).groupId,
        name: (g as any).name,
        members: (g as any).members,
        epoch: (g as any).epoch,
        state: (g as any).state,
      })),
    })
    return
  }

  if (type === 'getMessages') {
    const messages = await agent.modules.groupMessaging.getMessages(msg.groupId as string)
    sendTo(client, {
      type: 'messages',
      groupId: msg.groupId,
      messages: messages.map((m: Record<string, unknown>) => ({
        id: (m as any).id,
        content: (m as any).content,
        senderDid: (m as any).senderDid,
        sentTime: (m as any).sentTime,
        epoch: (m as any).epoch,
      })),
    })
    return
  }
}

// ─── HTTP + WebSocket Server ─────────────────────────────────────────

const app = express()
app.use(express.static(path.join(__dirname, 'public')))

const server = createServer(app)
const wss = new WebSocketServer({ server })

wss.on('connection', (ws: WebSocket) => {
  const client: ClientSocket = { ws, agentName: null }
  clients.add(client)
  console.log('Browser tab connected')

  ws.on('message', (data: Buffer) => {
    handleMessage(client, data.toString()).catch((err) =>
      console.error('WS handler error:', err)
    )
  })

  ws.on('close', () => {
    clients.delete(client)
    console.log('Browser tab disconnected')
  })
})

// ─── Start ───────────────────────────────────────────────────────────

await setup()

server.listen(DEMO_PORT, () => {
  console.log('='.repeat(60))
  console.log('  Group Chat Demo running!')
  console.log('')
  console.log('  Open these URLs in separate browser tabs:')
  console.log(`    Alice: http://localhost:${DEMO_PORT}?agent=alice`)
  console.log(`    Bob:   http://localhost:${DEMO_PORT}?agent=bob`)
  console.log(`    Carol: http://localhost:${DEMO_PORT}?agent=carol`)
  console.log('='.repeat(60))
})
