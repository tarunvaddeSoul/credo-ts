import { Agent } from '@credo-ts/core'
import { Subject } from 'rxjs'

import { getAgentOptions, makeConnection } from '../../core/tests/helpers'
import { DidCommModule } from '../src/DidCommModule'
import { GroupMessagingModule } from '../src/modules/group-messaging/GroupMessagingModule'
import { GroupMessagingEventTypes } from '../src/modules/group-messaging/GroupMessagingEvents'
import { GroupMessagingState } from '../src/modules/group-messaging/GroupMessagingState'
import type { GroupMessageReceivedEvent } from '../src/modules/group-messaging/GroupMessagingEvents'
import { SubjectInboundTransport, type SubjectMessage } from '../../../tests/transport/SubjectInboundTransport'
import { SubjectOutboundTransport } from '../../../tests/transport/SubjectOutboundTransport'

// ─── Helper: wait for a group message event on an agent ──────────────

function waitForGroupMessage(
  // biome-ignore lint/suspicious/noExplicitAny: test helper
  agent: Agent<any>,
  timeoutMs = 15000
): Promise<GroupMessageReceivedEvent> {
  return new Promise<GroupMessageReceivedEvent>((resolve, reject) => {
    const timer = setTimeout(() => {
      agent.events.off(GroupMessagingEventTypes.GroupMessageReceived, handler)
      reject(new Error(`waitForGroupMessage timed out after ${timeoutMs}ms`))
    }, timeoutMs)

    const handler = (event: GroupMessageReceivedEvent) => {
      clearTimeout(timer)
      agent.events.off(GroupMessagingEventTypes.GroupMessageReceived, handler)
      resolve(event)
    }

    agent.events.on(GroupMessagingEventTypes.GroupMessageReceived, handler)
  })
}

// ─── Tests ───────────────────────────────────────────────────────────

describe('Group Messaging Protocol 1.0 (DIDComm v2)', () => {
  // biome-ignore lint/suspicious/noExplicitAny: test agent typing
  let alice: Agent<any>
  // biome-ignore lint/suspicious/noExplicitAny: test agent typing
  let bob: Agent<any>
  // biome-ignore lint/suspicious/noExplicitAny: test agent typing
  let carol: Agent<any>

  let aliceMessages: Subject<SubjectMessage>
  let bobMessages: Subject<SubjectMessage>
  let carolMessages: Subject<SubjectMessage>

  // Shared connection references for use across tests
  // biome-ignore lint/suspicious/noExplicitAny: test connection typing
  let aliceBobConnection: any
  // biome-ignore lint/suspicious/noExplicitAny: test connection typing
  let aliceCarolConnection: any

  beforeAll(async () => {
    aliceMessages = new Subject<SubjectMessage>()
    bobMessages = new Subject<SubjectMessage>()
    carolMessages = new Subject<SubjectMessage>()

    const subjectMap: Record<string, Subject<SubjectMessage>> = {
      'rxjs:alice': aliceMessages,
      'rxjs:bob': bobMessages,
      'rxjs:carol': carolMessages,
    }

    const aliceModules = {
      didcomm: new DidCommModule({ endpoints: ['rxjs:alice'], didcommVersions: ['v1', 'v2'] }),
      groupMessaging: new GroupMessagingModule(),
    }
    const bobModules = {
      didcomm: new DidCommModule({ endpoints: ['rxjs:bob'], didcommVersions: ['v1', 'v2'] }),
      groupMessaging: new GroupMessagingModule(),
    }
    const carolModules = {
      didcomm: new DidCommModule({ endpoints: ['rxjs:carol'], didcommVersions: ['v1', 'v2'] }),
      groupMessaging: new GroupMessagingModule(),
    }

    alice = new Agent(
      getAgentOptions('Group Alice', { endpoints: ['rxjs:alice'], didcommVersions: ['v1', 'v2'] }, {}, aliceModules, {
        requireDidcomm: true,
      })
    )
    bob = new Agent(
      getAgentOptions('Group Bob', { endpoints: ['rxjs:bob'], didcommVersions: ['v1', 'v2'] }, {}, bobModules, {
        requireDidcomm: true,
      })
    )
    carol = new Agent(
      getAgentOptions('Group Carol', { endpoints: ['rxjs:carol'], didcommVersions: ['v1', 'v2'] }, {}, carolModules, {
        requireDidcomm: true,
      })
    )

    // Register transports
    for (const [agent, subject] of [
      [alice, aliceMessages],
      [bob, bobMessages],
      [carol, carolMessages],
    ] as [typeof alice, Subject<SubjectMessage>][]) {
      agent.didcomm.registerOutboundTransport(new SubjectOutboundTransport(subjectMap))
      agent.didcomm.registerInboundTransport(new SubjectInboundTransport(subject))
    }

    // Initialize all agents
    await Promise.all([alice.initialize(), bob.initialize(), carol.initialize()])
  }, 30000)

  afterAll(async () => {
    await alice.shutdown()
    await bob.shutdown()
    await carol.shutdown()
  })

  test('Full group chat: create, send messages, verify delivery', async () => {
    // ── Step 1: Establish DIDComm v2 pairwise connections ──

    // Alice <-> Bob (v2)
    const [aliceBobConn] = await makeConnection(alice, bob, { didCommVersion: 'v2' })
    aliceBobConnection = aliceBobConn
    // Alice <-> Carol (v2)
    const [aliceCarolConn] = await makeConnection(alice, carol, { didCommVersion: 'v2' })
    aliceCarolConnection = aliceCarolConn
    // Bob <-> Carol (v2) — needed so Bob can participate in group
    await makeConnection(bob, carol, { didCommVersion: 'v2' })

    // Allow connections to settle
    await new Promise((r) => setTimeout(r, 1500))

    // ── Step 2: Alice creates a group ──

    const groupRecord = await alice.modules.groupMessaging.createGroup({
      name: 'DIDComm v2 Group Chat',
      memberConnectionIds: [aliceBobConn.id, aliceCarolConn.id],
    })

    expect(groupRecord.groupId).toMatch(/^urn:uuid:/)
    expect(groupRecord.epoch).toBe(0)
    expect(groupRecord.members).toHaveLength(3)
    expect(groupRecord.name).toBe('DIDComm v2 Group Chat')

    // Wait for Bob and Carol to process the create message
    await new Promise((r) => setTimeout(r, 3000))

    // ── Step 3: Verify group was created on all agents ──

    const bobGroups = await bob.modules.groupMessaging.getGroups()
    expect(bobGroups).toHaveLength(1)
    expect(bobGroups[0].groupId).toBe(groupRecord.groupId)
    expect(bobGroups[0].state).toBe(GroupMessagingState.Active)
    expect(bobGroups[0].members).toHaveLength(3)

    const carolGroups = await carol.modules.groupMessaging.getGroups()
    expect(carolGroups).toHaveLength(1)
    expect(carolGroups[0].groupId).toBe(groupRecord.groupId)

    // ── Step 4: Alice sends a message ──

    const bobMsgPromise = waitForGroupMessage(bob)
    const carolMsgPromise = waitForGroupMessage(carol)

    await alice.modules.groupMessaging.sendMessage(groupRecord.groupId, 'Hello from Alice!')

    const bobEvent = await bobMsgPromise
    expect(bobEvent.payload.messageRecord.content).toBe('Hello from Alice!')
    expect(bobEvent.payload.messageRecord.groupId).toBe(groupRecord.groupId)

    const carolEvent = await carolMsgPromise
    expect(carolEvent.payload.messageRecord.content).toBe('Hello from Alice!')

    // ── Step 5: Bob replies ──

    const aliceMsgPromise = waitForGroupMessage(alice)
    const carolMsg2Promise = waitForGroupMessage(carol)

    await bob.modules.groupMessaging.sendMessage(groupRecord.groupId, 'Bob here, received loud and clear!')

    const aliceEvent = await aliceMsgPromise
    expect(aliceEvent.payload.messageRecord.content).toBe('Bob here, received loud and clear!')

    const carolEvent2 = await carolMsg2Promise
    expect(carolEvent2.payload.messageRecord.content).toBe('Bob here, received loud and clear!')

    // ── Step 6: Carol replies ──

    const aliceMsg2Promise = waitForGroupMessage(alice)
    const bobMsg2Promise = waitForGroupMessage(bob)

    await carol.modules.groupMessaging.sendMessage(groupRecord.groupId, 'Carol checking in!')

    const aliceEvent2 = await aliceMsg2Promise
    expect(aliceEvent2.payload.messageRecord.content).toBe('Carol checking in!')

    const bobEvent2 = await bobMsg2Promise
    expect(bobEvent2.payload.messageRecord.content).toBe('Carol checking in!')

    // ── Step 7: Verify message history on all agents ──

    const aliceMessages = await alice.modules.groupMessaging.getMessages(groupRecord.groupId)
    // Alice sent 1, received 2 = 3 total
    expect(aliceMessages.length).toBe(3)

    const bobMessages = await bob.modules.groupMessaging.getMessages(groupRecord.groupId)
    // Bob sent 1, received 2 = 3 total
    expect(bobMessages.length).toBe(3)

    const carolMsgs = await carol.modules.groupMessaging.getMessages(groupRecord.groupId)
    expect(carolMsgs.length).toBe(3)
  }, 60000)

  test('Key rotation: admin rotates key, post-rotation messages decrypt correctly', async () => {
    // Reuse connections established in the first test
    if (!aliceBobConnection || !aliceCarolConnection) {
      throw new Error('Expected existing connections from first test')
    }

    // Create a fresh group
    const group = await alice.modules.groupMessaging.createGroup({
      name: 'Rotation Test',
      memberConnectionIds: [aliceBobConnection.id, aliceCarolConnection.id],
    })

    await new Promise((r) => setTimeout(r, 3000))

    const originalGck = group.gck

    // Rotate the key
    const rotated = await alice.modules.groupMessaging.rotateKey(group.groupId, 'scheduled')
    expect(rotated.epoch).toBe(1)
    expect(rotated.gck).not.toBe(originalGck)

    await new Promise((r) => setTimeout(r, 3000))

    // Verify Bob has the new epoch
    const bobGroup = await bob.modules.groupMessaging.getGroupByGroupId(group.groupId)
    expect(bobGroup.epoch).toBe(1)

    // Send a message after rotation — should work
    const bobMsgPromise = waitForGroupMessage(bob)
    await alice.modules.groupMessaging.sendMessage(group.groupId, 'Message after key rotation')

    const bobEvent = await bobMsgPromise
    expect(bobEvent.payload.messageRecord.content).toBe('Message after key rotation')
    expect(bobEvent.payload.messageRecord.epoch).toBe(1)
  }, 60000)
})
