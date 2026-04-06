import { AskarModule } from '@credo-ts/askar'
import { Agent, ConsoleLogger, LogLevel } from '@credo-ts/core'
import { DidCommHttpOutboundTransport, DidCommModule, GroupMessagingModule } from '@credo-ts/didcomm'
import { agentDependencies, DidCommHttpInboundTransport } from '@credo-ts/node'
import { askar } from '@openwallet-foundation/askar-nodejs'

// biome-ignore lint/suspicious/noExplicitAny: agent module typing
export type DemoAgent = Agent<any>

export interface AgentEntry {
  name: string
  agent: DemoAgent
  port: number
}

const logger = new ConsoleLogger(LogLevel.warn)

export async function createAgent(name: string, port: number): Promise<AgentEntry> {
  const agent = new Agent({
    config: { logger },
    dependencies: agentDependencies,
    modules: {
      askar: new AskarModule({
        askar,
        store: {
          id: `demo-gc-${name.toLowerCase()}`,
          key: `demo-gc-${name.toLowerCase()}-key`,
        },
      }),
      didcomm: new DidCommModule({
        endpoints: [`http://localhost:${port}`],
        didcommVersions: ['v1', 'v2'],
        transports: {
          inbound: [new DidCommHttpInboundTransport({ port })],
          outbound: [new DidCommHttpOutboundTransport()],
        },
        connections: { autoAcceptConnections: true },
      }),
      groupMessaging: new GroupMessagingModule(),
    },
  })

  await agent.initialize()
  console.log(`  [${name}] initialized on port ${port}`)
  return { name, agent, port }
}

export async function makeV2Connection(
  agentA: DemoAgent,
  agentB: DemoAgent
): Promise<[string, string]> {
  // B creates invitation, A receives it
  const invB = await agentB.didcomm.oob.createInvitation({ didCommVersion: 'v2' })
  const bDid = invB.outOfBandInvitation.v2Invitation?.from

  const { connectionRecord: aConn, outOfBandRecord: aOob } =
    await agentA.didcomm.oob.receiveInvitation(invB.outOfBandInvitation, { label: '' })
  const aConnId = aConn?.id ?? (await agentA.didcomm.connections.findAllByOutOfBandId(aOob.id))[0]?.id
  if (!aConnId) throw new Error('No connection for agent A')
  const aConnection = await agentA.didcomm.connections.returnWhenIsConnected(aConnId)

  // A creates invitation with same DID, B receives it
  const invA = await agentA.didcomm.oob.createInvitation({
    didCommVersion: 'v2',
    ourDid: aConnection.did,
  })
  const { connectionRecord: bConn, outOfBandRecord: bOob } =
    await agentB.didcomm.oob.receiveInvitation(invA.outOfBandInvitation, {
      label: '',
      ourDid: bDid ?? undefined,
    })
  const bConnId = bConn?.id ?? (await agentB.didcomm.connections.findAllByOutOfBandId(bOob.id))[0]?.id
  if (!bConnId) throw new Error('No connection for agent B')
  await agentB.didcomm.connections.returnWhenIsConnected(bConnId)

  return [aConnection.id, bConnId]
}
