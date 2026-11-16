// AT1C verify endpoint (receipt format 2; see spec/receipt.md and spec/keys.md).
// "valid: true" means: signed under the receipt label by a key in THIS server's trusted-keys file, inside its
// validity window, unexpired, made for the audience the caller names, and matching the action the caller says
// it is about to run. This endpoint is a second opinion for a gate: it is not itself the audience.
// The caller may send the attachment ({ payload, salt }) or only its fingerprint (payload_hash), so the
// payload never has to leave the caller.
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

function createApp({ verify, attachmentHashOf, trusted, now = () => new Date() }) {
  // Refuse to start without the format 2 verifier. An old or misplaced verify.js must stop the server,
  // not leave it running and answering every request with an error (seen on the live server, 15 Nov 2026).
  if (typeof verify !== 'function' || typeof attachmentHashOf !== 'function') {
    throw new Error('AT1C verify endpoint: verifyReceiptV2 and attachmentHashOf are required. Refusing to start.')
  }
  const app = express()
  app.use(express.json({ limit: '64kb' }))

  app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')))
  app.get('/health', (req, res) => res.json({ status: 'ok', service: 'AT1C Verify Endpoint', receipt_format: '2' }))

  app.post('/v1/verify', (req, res) => {
    if (!trusted) return res.status(503).json({ valid: false, reason: 'no_trusted_keys' }) // fail closed
    const { receipt, expected } = req.body || {}
    if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
      return res.status(400).json({ valid: false, reason: 'missing_receipt' })
    }
    if (receipt.version !== '2') {
      return res.status(400).json({
        valid: false,
        reason: 'unsupported_receipt_format',
        detail: 'Only receipt format 2 is accepted. Format 1 receipts carry no signing label, no audience and an unsalted payload hash.',
      })
    }
    if (
      !expected || !isStr(expected.audience) || !isStr(expected.agent_id) || !isStr(expected.type) ||
      !isStr(expected.resource)
    ) {
      return res.status(400).json({ valid: false, reason: 'missing_expected_action' })
    }
    let payloadHash
    try {
      if (expected.attachment !== undefined && expected.payload_hash !== undefined) {
        return res.status(400).json({ valid: false, reason: 'give_attachment_or_payload_hash_not_both' })
      }
      payloadHash = expected.attachment !== undefined ? attachmentHashOf(expected.attachment) : expected.payload_hash
    } catch {
      return res.status(400).json({ valid: false, reason: 'bad_attachment' })
    }
    if (!isStr(payloadHash)) return res.status(400).json({ valid: false, reason: 'missing_expected_action' })

    const result = verify(receipt, {
      now: now(),
      pinned: trusted.keys,
      allowedAlgs: trusted.allowed_algs,
      expected: {
        audience: expected.audience,
        agent_id: expected.agent_id,
        type: expected.type,
        resource: expected.resource,
        payload_hash: payloadHash,
      },
      nonces: { checkAndRecord: () => true }, // peek only: never burn a nonce from a public endpoint
      revoked: new Set(),
    })
    return res.status(200).json({ valid: result.ok, code: result.code, replay_checked: false, revocation_checked: false })
  })

  app.use((err, req, res, next) => {
    if (res.headersSent) return next(err)
    // The caller's fault (the JSON body parser says so): unreadable JSON, body too large, and so on.
    const status = err && (err.status || err.statusCode)
    if (Number.isInteger(status) && status >= 400 && status < 500) {
      const reason = err.type === 'entity.parse.failed' ? 'malformed_json' : 'bad_request'
      return res.status(status).json({ valid: false, reason })
    }
    // Anything else is this server's fault. Say so plainly, so a broken deploy cannot pass for a bad request.
    console.error('AT1C verify endpoint internal error:', (err && err.stack) || err)
    return res.status(500).json({ valid: false, reason: 'internal_error' })
  })
  return app
}

module.exports = { createApp, loadTrusted }

if (require.main === module || typeof PhusionPassenger !== 'undefined') {
  // Build first: cd packages/sdk && npx tsc -p tsconfig.sdk.json
  const sdkFile = process.env.AT1C_SDK_VERIFY || './packages/sdk/dist/src/verify'
  const sdk = require(sdkFile)
  if (typeof sdk.verifyReceiptV2 !== 'function' || typeof sdk.attachmentHashOf !== 'function') {
    console.error(`FATAL: ${sdkFile} has no verifyReceiptV2 or attachmentHashOf. Is it the format 2 build?`)
  }
  const trustedFile = process.env.AT1C_TRUSTED_KEYS || path.join(__dirname, 'trusted-keys.json')
  const trusted = loadTrusted(trustedFile)
  if (!trusted) console.error(`WARNING: no valid trusted keys at ${trustedFile}. /v1/verify will answer 503 until you add one.`)
  const app = createApp({ verify: sdk.verifyReceiptV2, attachmentHashOf: sdk.attachmentHashOf, trusted })
  const PORT = process.env.PORT || 3000
  app.listen(PORT, () => console.log(`AT1C verify endpoint running on port ${PORT}`))
}
