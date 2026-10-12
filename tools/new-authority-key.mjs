// Make an ML-DSA-65 key for a human approver. UNTESTED when written; run it and check the output.
// Usage: node tools/new-authority-key.mjs <authority-id> [secrets-dir]
//   e.g. node tools/new-authority-key.mjs "did:web:at1c.com#mora-1"
// The secret seed goes to a 0600 file (default ~/at1c-secrets) and is never printed.
// You paste the printed public record into trusted-keys.json.
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'

const authority = process.argv[2]
if (!authority) { console.error('usage: node tools/new-authority-key.mjs <authority-id> [secrets-dir]'); process.exit(1) }
const dir = process.argv[3] || path.join(os.homedir(), 'at1c-secrets')
fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
const file = path.join(dir, authority.replace(/[^A-Za-z0-9._-]/g, '_') + '.mldsa65.json')
if (fs.existsSync(file)) { console.error('Refusing to overwrite ' + file); process.exit(1) }

const seed = crypto.randomBytes(32)
const { publicKey } = ml_dsa65.keygen(seed)
const iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z')
const from = new Date()
const until = new Date(from.getTime() + 365 * 24 * 3600 * 1000)
fs.writeFileSync(file, JSON.stringify({ alg: 'ML-DSA-65', authority, created: iso(from), seed_hex: seed.toString('hex') }, null, 2), { mode: 0o600 })

console.log('Secret saved to: ' + file + '  (back this up; never commit it)')
console.log('\nAdd this under "keys" in trusted-keys.json:\n')
console.log(JSON.stringify({ [authority]: {
  alg: 'ML-DSA-65',
  public_key: Buffer.from(publicKey).toString('base64url'),
  valid_from: iso(from),
  valid_until: iso(until),
  revoked: false,
} }, null, 2))
