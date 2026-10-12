// AT1C verify endpoint (receipt format v1; see spec/receipt.md and spec/keys.md).
// "valid: true" means: signed by a key in THIS server's trusted-keys file, inside its validity window,
// unexpired, and matching the action the caller says it is about to run.
// It does NOT consume nonces or check revocation: those belong to the gate that executes the action.
const express = require('express')
const fs = require('fs')
const path = require('path')

function loadTrusted(file) {
  try {
    const t = JSON.parse(fs.readFileSync(file, 'utf-8'))
    if (!t || !Array.isArray(t.allowed_algs) || typeof t.keys !== 'object' || t.keys === null) return null
    return t
  } catch {
    return null
  }
}

const isStr = (x) => typeof x === 'string' && x.length > 0

function createApp({ verify, payloadHashOf, trusted, now = () => new Date() }) {
  const app = express()
  app.set('trust proxy', true)
  app.use(express.json({ limit: '64kb' }))

  app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')))
  app.get('/health', (req, res) => res.json({ status: 'ok', service: 'AT1C Verify Endpoint', receipt_format: '1' }))

  app.post('/v1/verify', (req, res) => {
    if (!trusted) return res.status(503).json({ valid: false, reason: 'no_trusted_keys' }) // fail closed
    const { receipt, expected } = req.body || {}
    if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
      return res.status(400).json({ valid: false, reason: 'missing_receipt' })
    }
    if (receipt.version !== '1') {
      return res.status(400).json({
        valid: false,
        reason: 'unsupported_receipt_format',
        detail: 'Only receipt format 1 is accepted. Legacy receipts embed their own key and cannot be trusted.',
      })
    }
    if (!expected || !isStr(expected.agent_id) || !isStr(expected.type) || !isStr(expected.resource)) {
      return res.status(400).json({ valid: false, reason: 'missing_expected_action' })
    }
    let payloadHash
    try {
      if (expected.payload !== undefined && expected.payload_hash !== undefined) {
        return res.status(400).json({ valid: false, reason: 'give_payload_or_payload_hash_not_both' })
      }
      payloadHash = expected.payload !== undefined ? payloadHashOf(expected.payload) : expected.payload_hash
    } catch {
      return res.status(400).json({ valid: false, reason: 'bad_payload' })
    }
    if (!isStr(payloadHash)) return res.status(400).json({ valid: false, reason: 'missing_expected_action' })

    const result = verify(receipt, {
      now: now(),
      pinned: trusted.keys,
      allowedAlgs: trusted.allowed_algs,
      expected: { agent_id: expected.agent_id, type: expected.type, resource: expected.resource, payload_hash: payloadHash },
      nonces: { checkAndRecord: () => true }, // peek only: never burn a nonce from a public endpoint
      revoked: new Set(),
    })
    return res.status(200).json({ valid: result.ok, code: result.code, replay_checked: false, revocation_checked: false })
  })

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => res.status(400).json({ valid: false, reason: 'malformed_json' }))
  return app
}

module.exports = { createApp, loadTrusted }

if (require.main === module || typeof PhusionPassenger !== 'undefined') {
  // Build first: cd packages/sdk && npx tsc -p tsconfig.sdk.json
  const sdk = require(process.env.AT1C_SDK_VERIFY || './packages/sdk/dist/src/verify')
  const trustedFile = process.env.AT1C_TRUSTED_KEYS || path.join(__dirname, 'trusted-keys.json')
  const trusted = loadTrusted(trustedFile)
  if (!trusted) console.error(`WARNING: no valid trusted keys at ${trustedFile}. /v1/verify will answer 503 until you add one.`)
  const app = createApp({ verify: sdk.verifyReceiptV1, payloadHashOf: sdk.payloadHashOf, trusted })
  const PORT = process.env.PORT || 3000
  app.listen(PORT, () => console.log(`AT1C verify endpoint running on port ${PORT}`))
}
