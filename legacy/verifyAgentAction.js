const fs = require("fs")
const { verifyReceipt } = require("@at1c/sdk")

function verifyAgentAction(agentId, payload, signatureHex) {
  const raw = fs.readFileSync("agents.json", "utf-8")
  const agents = JSON.parse(raw)

  const agent = agents.find(a => a.agentId === agentId)

  if (!agent) {
    throw new Error("Agent not found")
  }

  if (!agent.publicKey) {
    throw new Error("Missing public key")
  }

  // Reconstruct a minimal receipt shape for SDK verification
  const receipt = {
    agentId,
    userId:    agent.ownerUserId,
    action:    payload.action || JSON.stringify(payload),
    status:    'approved',
    signature: signatureHex,
    publicKey: agent.publicKey,
    nonce:     payload.nonce     || '',
    timestamp: payload.timestamp || new Date().toISOString(),
    expiresAt: payload.expiresAt || new Date(Date.now() + 300000).toISOString(),
    receiptId: payload.receiptId || '',
    version:   '1.0',
  }

  const result = verifyReceipt(receipt)
  return result.valid
}

module.exports = { verifyAgentAction }
