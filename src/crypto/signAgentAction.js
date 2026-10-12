const fs = require("fs")
const { buildReceipt } = require("@at1c/sdk")

function signAgentAction(agentId, payload) {
  const raw = fs.readFileSync("agents.json", "utf-8")
  const agents = JSON.parse(raw)

  const agent = agents.find(a => a.agentId === agentId)

  if (!agent) {
    throw new Error("Agent not found")
  }

  const receipt = buildReceipt(
    {
      userId:     agent.ownerUserId,
      agentId:    agent.agentId,
      action:     payload.action || JSON.stringify(payload),
      status:     'approved',
      ttlSeconds: 300,
    },
    agent.privateKey
  )
  return receipt.signature
}

module.exports = {
  signAgentAction
}
