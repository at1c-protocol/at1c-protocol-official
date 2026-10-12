#!/usr/bin/env node
/**
 * AT1C Agent Registrar
 * Registers a new AI agent, issues a signed certificate, and records it in agents.json
 *
 * Usage:
 *   node generate-agent-keys.js --out my-agent-keys.json   (run this first, locally)
 *   node register-agent.js --pubkey <hex> --name "My Payment Agent" --owner "user_abc" --permissions "send_payment,read_balance"
 *   node register-agent.js --list
 *   node register-agent.js --verify <agentId>
 */

const fs       = require('fs')
const path     = require('path')
const crypto   = require('crypto')
const { generateKeyPair, buildReceipt, verifyReceipt } = require('@at1c/sdk')

const AGENTS_FILE = path.join(__dirname, 'agents.json')
const args        = process.argv.slice(2)

function loadAgents() {
  if (!fs.existsSync(AGENTS_FILE)) return []
  try { return JSON.parse(fs.readFileSync(AGENTS_FILE, 'utf-8')) }
  catch { return [] }
}

function saveAgents(agents) {
  fs.writeFileSync(AGENTS_FILE, JSON.stringify(agents, null, 2))
}

function getArg(flag) {
  const i = args.indexOf(flag)
  return i !== -1 ? args[i + 1] : null
}

function hasFlag(flag) {
  return args.includes(flag)
}

function generateAgentId() {
  return 'agent_' + crypto.randomBytes(6).toString('hex')
}

function generateCertId() {
  return 'cert_' + crypto.randomBytes(8).toString('hex')
}

function banner(text) {
  const line = '─'.repeat(42)
  console.log('\n' + line)
  console.log('  ' + text)
  console.log(line)
}

const REGISTRY_KEY_FILE = path.join(__dirname, '.at1c_registry_key.json')

function getRegistryKeys() {
  if (fs.existsSync(REGISTRY_KEY_FILE)) {
    return JSON.parse(fs.readFileSync(REGISTRY_KEY_FILE, 'utf-8'))
  }
  const keypair = generateKeyPair()
  const keys = {
    publicKey:  keypair.publicKey,
    privateKey: keypair.secretKey,
    algorithm:  'ML-DSA-65',
    createdAt:  Date.now()
  }
  fs.writeFileSync(REGISTRY_KEY_FILE, JSON.stringify(keys, null, 2))
  console.log('🔑 AT1C Registry root key generated — ML-DSA-65 (FIPS 204) (first run)')
  return keys
}

function signCertificate(payload, privateKey) {
  const receipt = buildReceipt(
    {
      userId:     payload.ownerUserId,
      agentId:    payload.agentId,
      action:     'register_agent',
      status:     'approved',
      ttlSeconds: 365 * 24 * 60 * 60,
    },
    privateKey
  )
  return receipt.signature
}

function verifyCertSignature(payload, signature, publicKey) {
  const receipt = {
    userId:     payload.ownerUserId,
    agentId:    payload.agentId,
    action:     'register_agent',
    status:     'approved',
    signature,
    publicKey,
    nonce:      payload.certId    || '',
    timestamp:  payload.issuedAt  || new Date().toISOString(),
    expiresAt:  payload.expiresAt || new Date(Date.now() + 300000).toISOString(),
    receiptId:  payload.certId    || '',
    version:    '1.0',
  }
  const result = verifyReceipt(receipt)
  return result.valid
}
function registerAgent() {
  const name      = getArg('--name')
  const owner     = getArg('--owner')
  const permsRaw  = getArg('--permissions')
  const tier      = getArg('--tier') || 'standard'
  const pubKeyHex = getArg('--pubkey')

  if (!name || !owner || !permsRaw || !pubKeyHex) {
    console.error('Usage: node register-agent.js --pubkey <hex> --name "<name>" --owner "<userId>" --permissions "<perm1,perm2>"')
    console.error('Optional: --tier free|standard|enterprise')
    console.error('')
    console.error('No --pubkey? Generate a keypair locally first:')
    console.error('  node generate-agent-keys.js --out my-agent-keys.json')
    process.exit(1)
  }

  const permissions = permsRaw.split(',').map(p => p.trim())
  const agents      = loadAgents()
  const registry    = getRegistryKeys()

  const agentId   = generateAgentId()
  const certId    = generateCertId()
  const now       = Date.now()
  const expiresAt = now + (365 * 24 * 60 * 60 * 1000)

  const certPayload = {
    certId,
    agentId,
    name,
    ownerUserId:  owner,
    permissions,
    tier,
    issuedAt:     new Date(now).toISOString(),
    expiresAt:    new Date(expiresAt).toISOString(),
    issuer:       'AT1C Registry v0.1 — ML-DSA-65',
  }

  const certSignature = signCertificate(certPayload, registry.privateKey)

  const agent = {
    agentId,
    name,
    ownerUserId:  owner,
    permissions,
    tier,
    publicKey:    pubKeyHex,
    certificate: {
      ...certPayload,
      signature:      certSignature,
      registryPubKey: registry.publicKey,
      algorithm:      'ML-DSA-65',
    },
    status:    'active',
    createdAt: now,
    expiresAt,
  }

  agents.push(agent)
  saveAgents(agents)

  banner('AT1C AGENT REGISTRATION CERTIFICATE')
  console.log(`  Status      : ✅ REGISTERED`)
  console.log(`  Agent ID    : ${agentId}`)
  console.log(`  Name        : ${name}`)
  console.log(`  Owner       : ${owner}`)
  console.log(`  Tier        : ${tier}`)
  console.log(`  Permissions : ${permissions.join(', ')}`)
  console.log(`  Cert ID     : ${certId}`)
  console.log(`  Algorithm   : ML-DSA-65 (FIPS 204)`)
  console.log(`  Issued      : ${certPayload.issuedAt}`)
  console.log(`  Expires     : ${certPayload.expiresAt}`)
  console.log(`  Signature   : ${certSignature.slice(0, 40)}...`)
  console.log('─'.repeat(42))
  console.log('  ⚠️  Save your Agent ID — you will need it')
  console.log('  to issue AT1C receipts and verify actions.')
  console.log('─'.repeat(42) + '\n')
}

function listAgents() {
  const agents = loadAgents()
  if (agents.length === 0) {
    console.log('\nNo agents registered yet.\n')
    return
  }
  banner(`AT1C AGENT REGISTRY  (${agents.length} agent${agents.length > 1 ? 's' : ''})`)
  agents.forEach((a, i) => {
    const expired = Date.now() > a.expiresAt
    const status  = expired ? '❌ EXPIRED' : '✅ ACTIVE'
    console.log(`\n  [${i + 1}] ${a.name || a.agentId}`)
    console.log(`      ID          : ${a.agentId}`)
    console.log(`      Owner       : ${a.ownerUserId}`)
    console.log(`      Tier        : ${a.tier || 'standard'}`)
    console.log(`      Permissions : ${(a.permissions || []).join(', ')}`)
    console.log(`      Status      : ${status}`)
    console.log(`      Expires     : ${a.expiresAt ? new Date(a.expiresAt).toISOString() : 'legacy — no expiry set'}`)
  })
  console.log('\n' + '─'.repeat(42) + '\n')
}
function verifyAgent(agentId) {
  const agents = loadAgents()
  const agent  = agents.find(a => a.agentId === agentId)

  banner('AT1C AGENT VERIFICATION')

  if (!agent) {
    console.log(`  ❌ UNKNOWN — Agent ${agentId} not found in registry`)
    console.log('─'.repeat(42) + '\n')
    return
  }

  const cert    = agent.certificate
  const payload = { ...cert }
  const sig     = payload.signature
  const regKey  = payload.registryPubKey
  delete payload.signature
  delete payload.registryPubKey
  delete payload.algorithm

  const sigValid = verifyCertSignature(payload, sig, regKey)
  const expired  = Date.now() > agent.expiresAt

  console.log(`  Agent ID    : ${agent.agentId}`)
  console.log(`  Name        : ${agent.name || '—'}`)
  console.log(`  Owner       : ${agent.ownerUserId}`)
  console.log(`  Permissions : ${(agent.permissions
|| []).join(', ')}`)
  console.log(`  Algorithm   : ML-DSA-65 (FIPS 204)`)
  console.log(`  Cert valid  : ${sigValid ? '✅ YES' : '❌ NO — tampered'}`)
  console.log(`  Expired     : ${expired  ? '❌ YES' : '✅ NO'}`)
  console.log(`  Status      : ${sigValid && !expired ? '✅ TRUSTED' : '❌ NOT TRUSTED'}`)
  console.log('─'.repeat(42) + '\n')
}

if (hasFlag('--list')) {
  listAgents()
} else if (hasFlag('--verify')) {
  const id = getArg('--verify')
  if (!id) { console.error('Provide an agent ID: --verify <agentId>'); process.exit(1) }
  verifyAgent(id)
} else {
  registerAgent()
}
