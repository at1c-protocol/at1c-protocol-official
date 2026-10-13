import { AT1C } from '../../packages/sdk/src/client'

// Setup (once): node tools/new-authority-key.mjs "<your authority>", then put the printed record in trusted-keys.json.
// Run:          AT1C_AUTHORITY="<your authority>" npx tsx examples/ai-agent-demo/index.ts
async function main() {
  const authority = process.env.AT1C_AUTHORITY
  if (!authority) {
    console.error('Set AT1C_AUTHORITY to your approver authority id (see the comment at the top of this file).')
    process.exit(1)
  }
  const at1c = new AT1C({ authority })

  console.log('\nAT1C AI Agent Demo')
  console.log('Approver public key:', at1c.getPublicKey())

  const result = await at1c.enforce(
    {
      agentId: 'agent_001',
      action: 'send_email',
      resource: 'mailto:alice@example.com',
      payload: { to: 'alice@example.com', body: 'Hello from the demo' },
    },
    async (payload) => {
      console.log('Sending email:', JSON.stringify(payload))
      return { done: true }
    }
  )

  console.log('\nResult:', result.status)
  if (result.status === 'approved') {
    console.log('Receipt ID:', result.receipt.receipt_id, '(verified by the Gate before the action ran)')
  } else {
    console.log('Reason:', result.reason)
  }
}

main().catch(console.error)
