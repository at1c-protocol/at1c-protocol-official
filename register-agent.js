#!/usr/bin/env node
// AT1C agent registration, certificate format 1 (spec/agent-certificate.md).
// Build the SDK first:  cd packages/sdk && npx tsc -p tsconfig.sdk.json
//   node register-agent.js register --pubkey <hex|b64url> --name <n> --owner <authority> --permissions a,b [--tier standard]
//   node register-agent.js list
//   node register-agent.js verify <agent_id>
//   node register-agent.js revoke <agent_id>
// The registry secret lives OUTSIDE the repo (default ~/at1c-secrets). Create it with:
//   node tools/new-authority-key.mjs "did:web:at1c.com#registry-1"
'use strict'
const fs = require('fs')
const os = require('os')
const path = require('path')
const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js')
const { jcs } = require('./packages/sdk/dist/src/verify')
const { agentIdFor, verifyAgentCertificateV1 } = require('./packages/sdk/dist/src/agentCert')

const AGENTS_FILE = process.env.AT1C_AGENTS_FILE || path.join(__dirname, 'agents.json')
const REVOKED_FILE = process.env.AT1C_REVOKED_FILE || path.join(__dirname, 'revoked-agents.json')
const TRUST_FILE = process.env.AT1C_TRUSTED_REGISTRY_KEYS || path.join(__dirname, 'trusted-registry-keys.json')
const KEY_FILE = process.env.AT1C_REGISTRY_KEY_FILE ||
  path.join(os.homedir(), 'at1c-secrets', 'did_web_at1c.com_registry-1.mldsa65.json')
const TIERS = ['free', 'standard', 'enterprise']
const CERT_DAYS = 365

const die = (msg) => { console.error('ERROR: ' + msg); process.exit(1) }
const b64u = (buf) => Buffer.from(buf).toString('base64url')
const iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z')

function readJson(file, fallback) {
  if (!fs.existsSync(file)) return fallback
  try {
    return JSON.parse(fs.readFileSync(file, 'utf-8'))
  } catch (e) {
    return die(`${file} exists but is not valid JSON (${e.message}). Fix or restore it. Nothing was changed.`)
  }
}

function writeJsonAtomic(file, data) {
  const tmp = `${file}.tmp-${process.pid}`
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n')
  fs.renameSync(tmp, file)
}

function loadAgents() {
  const a = readJson(AGENTS_FILE, [])
  if (!Array.isArray(a)) die(`${AGENTS_FILE} must contain a JSON array.`)
  return a
}

function loadTrust() {
  const t = readJson(TRUST_FILE, null)
  if (!t || !Array.isArray(t.allowed_algs) || typeof t.keys !== 'object' || t.keys === null) {
    die(`No valid trusted registry keys at ${TRUST_FILE}.`)
  }
  return t
}

function loadRegistryKey() {
  if (!fs.existsSync(KEY_FILE)) die(`Registry key not found at ${KEY_FILE}. Create it with tools/new-authority-key.mjs.`)
  if (fs.statSync(KEY_FILE).mode & 0o077) die(`${KEY_FILE} is readable by others. Run: chmod 600 "${KEY_FILE}"`)
  const k = readJson(KEY_FILE, null)
  if (!k || k.alg !== 'ML-DSA-65') die('Registry key file is not an ML-DSA-65 key (an old Ed25519 file will not work).')
  if (typeof k.authority !== 'string' || !/^[0-9a-f]{64}$/.test(k.seed_hex || '')) die('Registry key file is malformed.')
  const { publicKey, secretKey } = ml_dsa65.keygen(Buffer.from(k.seed_hex, 'hex'))
  return { authority: k.authority, publicKey, secretKey }
}

function parseAgentPubkey(s) {
  let buf
  if (/^[0-9a-fA-F]+$/.test(s) && s.length === 3904) buf = Buffer.from(s, 'hex')
  else if (/^[A-Za-z0-9_-]+$/.test(s)) buf = Buffer.from(s, 'base64url')
  else die('--pubkey must be hex or base64url.')
  if (buf.length !== 1952) die(`Agent public key must be an ML-DSA-65 key (1952 bytes), got ${buf.length}.`)
  return b64u(buf)
}

function flag(args, name) {
  const i = args.indexOf(name)
  return i >= 0 && i + 1 < args.length ? args[i + 1] : undefined
}

function state(cert, revoked) {
  if (revoked.has(cert.agent_id)) return 'revoked'
  return Date.now() >= Date.parse(cert.expires_at) ? 'expired' : 'active'
}

function register(args) {
  const pubkey = flag(args, '--pubkey')
  const name = flag(args, '--name')
  const owner = flag(args, '--owner')
  const permsRaw = flag(args, '--permissions')
  const tier = flag(args, '--tier') || 'standard'
  if (!pubkey || !name || !owner || !permsRaw) die('register needs --pubkey --name --owner --permissions')
  if (!TIERS.includes(tier)) die(`--tier must be one of: ${TIERS.join(', ')}`)
  const permissions = [...new Set(permsRaw.split(',').map((p) => p.trim()).filter(Boolean))].sort()
  if (permissions.length === 0) die('--permissions must list at least one action type.')

  const agentKey = parseAgentPubkey(pubkey)
  const reg = loadRegistryKey()
  const trust = loadTrust()
  const pinned = trust.keys[reg.authority]
  if (!pinned || pinned.public_key !== b64u(reg.publicKey)) {
    die(`${TRUST_FILE} does not list this registry key (${reg.authority}). Refusing to issue a certificate nobody could verify.`)
  }

  const agents = loadAgents()
  const agentId = agentIdFor(agentKey)
  if (agents.some((a) => a.certificate && a.certificate.agent_id === agentId)) die(`Agent ${agentId} is already registered.`)

  const now = new Date()
  const cert = {
    version: '1', type: 'agent_certificate', agent_id: agentId, agent_alg: 'ML-DSA-65', agent_public_key: agentKey,
    name, owner, permissions, tier, issued_at: iso(now),
    expires_at: iso(new Date(now.getTime() + CERT_DAYS * 86400 * 1000)),
    issuer: reg.authority, alg: 'ML-DSA-65',
  }
  cert.signature = b64u(ml_dsa65.sign(Buffer.from(jcs(cert), 'utf8'), reg.secretKey))

  // Never save a certificate that our own verifier would reject.
  const check = verifyAgentCertificateV1(cert, { now: new Date(), pinned: trust.keys, allowedAlgs: trust.allowed_algs, revoked: new Set() })
  if (!check.ok) die(`Self-check failed (${check.code}); nothing was saved.`)

  agents.push({ certificate: cert, registered_at: iso(now) })
  writeJsonAtomic(AGENTS_FILE, agents)
  console.log('Registered.\n  agent_id : ' + agentId + '\n  name     : ' + name + '\n  owner    : ' + owner +
    '\n  tier     : ' + tier + '\n  perms    : ' + permissions.join(', ') + '\n  expires  : ' + cert.expires_at)
  console.log('\nNote: format 1 does not prove you control the agent\'s private key (spec/agent-certificate.md section 6).')
}

function list() {
  const revoked = new Set(readJson(REVOKED_FILE, []))
  const agents = loadAgents()
  console.log(`Total registered agents: ${agents.length}`)
  for (const a of agents) {
    const c = a.certificate
    console.log(`  ${c.agent_id}  ${c.name}  owner=${c.owner}  tier=${c.tier}  ${state(c, revoked)}  expires=${c.expires_at}`)
  }
}

function verify(args) {
  const id = args[0]
  if (!id) die('verify needs an agent_id')
  const entry = loadAgents().find((a) => a.certificate && a.certificate.agent_id === id)
  if (!entry) die(`No agent ${id}`)
  const trust = loadTrust()
  const r = verifyAgentCertificateV1(entry.certificate, {
    now: new Date(), pinned: trust.keys, allowedAlgs: trust.allowed_algs, revoked: new Set(readJson(REVOKED_FILE, [])),
  })
  console.log(r.ok ? `VALID  ${id}` : `INVALID (${r.code})  ${id}`)
  process.exit(r.ok ? 0 : 2)
}

function revoke(args) {
  const id = args[0]
  if (!id) die('revoke needs an agent_id')
  if (!loadAgents().some((a) => a.certificate && a.certificate.agent_id === id)) die(`No agent ${id}`)
  const revoked = readJson(REVOKED_FILE, [])
  if (!revoked.includes(id)) revoked.push(id)
  writeJsonAtomic(REVOKED_FILE, revoked)
  console.log(`Revoked ${id}. Publish revoked-agents.json to every verifier that relies on it.`)
}

const [cmd, ...rest] = process.argv.slice(2)
if (cmd === 'register') register(rest)
else if (cmd === 'list') list()
else if (cmd === 'verify') verify(rest)
else if (cmd === 'revoke') revoke(rest)
else {
  console.log('Usage: node register-agent.js <register|list|verify|revoke> ...\n  (see the comment at the top of this file)')
  process.exit(cmd ? 1 : 0)
}
