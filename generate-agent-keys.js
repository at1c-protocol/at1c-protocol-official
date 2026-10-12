#!/usr/bin/env node
/**
 * AT1C Agent Key Generator
 * Run this LOCALLY on the machine/server where your agent runs.
 * The private key never leaves this machine and is never sent to the registry.
 *
 * Usage:
 *   node generate-agent-keys.js --out my-agent-keys.json
 */

const fs   = require('fs')
const path = require('path')
const { generateKeyPair } = require('@at1c/sdk')

const args = process.argv.slice(2)

function getArg(flag, fallback) {
  const i = args.indexOf(flag)
  return i !== -1 ? args[i + 1] : fallback
}

const outFile = getArg('--out', 'agent-keys.json')

if (fs.existsSync(outFile)) {
  console.error(`\n❌ ${outFile} already exists — refusing to overwrite an existing key.`)
  console.error(`   Choose a different --out path if you want to generate a new keypair.\n`)
  process.exit(1)
}

const keypair = generateKeyPair()
const publicKey    = keypair.publicKey
const privateKey   = keypair.secretKey
const publicKeyHex = keypair.publicKey

const record = {
  publicKey,
  privateKey,
  publicKeyHex,
  createdAt: new Date().toISOString(),
}

fs.writeFileSync(outFile, JSON.stringify(record, null, 2), { mode: 0o600 })

const line = '─'.repeat(50)
console.log('\n' + line)
console.log('  AT1C AGENT KEYPAIR GENERATED (ML-DSA-65)')
console.log(line)
console.log(`  Saved to    : ${path.resolve(outFile)}`)
console.log(`  Permissions : 600 (owner read/write only)`)
console.log(`  Algorithm   : ML-DSA-65 (FIPS 204) post-quantum`)
console.log(line)
console.log('  ⚠️  This file contains your PRIVATE KEY.')
console.log('  Never commit it to git. Never send it anywhere.')
console.log('  Only the public key below goes to the registry.')
console.log(line)
console.log('\n  Your PUBLIC KEY (safe to share, needed for registration):\n')
console.log('  ' + publicKeyHex)
console.log('\n' + line)
console.log('  Next step — register this public key:')
console.log(`  node register-agent.js --pubkey ${publicKeyHex} \\`)
console.log(`    --name "My Agent" --owner "user_abc" --permissions "send_payment"`)
console.log(line + '\n')
