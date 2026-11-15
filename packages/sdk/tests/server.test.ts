// Exercises server.js over real HTTP using the conformance vectors, with a fixed clock.
import { describe, it, expect } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import type { AddressInfo } from 'net'
import { verifyReceiptV2, attachmentHashOf } from '../src/verify'
// @ts-ignore: plain CommonJS file at the repo root
import { createApp } from '../../../server.js'

const data = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../../spec/test-vectors/receipt-v2.json'), 'utf-8'))

async function call(trusted: any, now: string, body: any, raw?: string) {
  const app = createApp({ verify: verifyReceiptV2, attachmentHashOf, trusted, now: () => new Date(now) })
  const server = app.listen(0)
  try {
    const { port } = server.address() as AddressInfo
    const res = await fetch(`http://127.0.0.1:${port}/v1/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: raw ?? JSON.stringify(body),
    })
    return { status: res.status, json: await res.json() as any }
  } finally { server.close() }
}

describe('server.js /v1/verify', () => {
  // REPLAY and REVOKED are the gate's job; this endpoint says so in its response.
  for (const v of data.vectors.filter((x: any) => !['REPLAY', 'REVOKED'].includes(x.expect.code))) {
    it(`vector: ${v.name}`, async () => {
      const trusted = { allowed_algs: data.allowed_algs, keys: v.pinned ?? data.pinned }
      const r = await call(trusted, v.now, { receipt: v.receipt, expected: v.expected_action })
      if (v.expect.code === 'SCHEMA' && r.status === 400) return // rejected even earlier: fine
      expect(r.status).toBe(200)
      expect(r.json.valid).toBe(v.expect.ok)
      expect(r.json.code).toBe(v.expect.code)
      expect(r.json.replay_checked).toBe(false)
    })
  }

  const good = data.vectors[0]
  const trusted = { allowed_algs: data.allowed_algs, keys: data.pinned }

  it('answers 503 when no trusted keys are configured (fail closed)', async () => {
    const r = await call(null, good.now, { receipt: good.receipt, expected: good.expected_action })
    expect(r.status).toBe(503)
    expect(r.json.valid).toBe(false)
  })

  it('rejects the legacy self-keyed receipt format and format 1', async () => {
    const legacy = { receiptId: 'x', publicKey: 'aa', signature: 'bb', status: 'approved', version: '1.6' }
    for (const receipt of [legacy, { ...good.receipt, version: '1' }]) {
      const r = await call(trusted, good.now, { receipt, expected: good.expected_action })
      expect(r.status).toBe(400)
      expect(r.json.reason).toBe('unsupported_receipt_format')
    }
  })

  it('computes the fingerprint itself when given the attachment', async () => {
    const attachment = data.attachment_vectors.accept[0].attachment
    const { payload_hash, ...rest } = good.expected_action
    const e = { ...rest, attachment }
    expect((await call(trusted, good.now, { receipt: good.receipt, expected: e })).json.valid).toBe(true)
    const changed = { ...e, attachment: { ...attachment, payload: { ...attachment.payload, to: 'mallory@example.com' } } }
    expect((await call(trusted, good.now, { receipt: good.receipt, expected: changed })).json.code).toBe('CONTEXT_MISMATCH')
    const noSalt = { ...e, attachment: { payload: attachment.payload } }
    const r = await call(trusted, good.now, { receipt: good.receipt, expected: noSalt })
    expect(r.status).toBe(400)
    expect(r.json.reason).toBe('bad_attachment')
    const both = await call(trusted, good.now, { receipt: good.receipt, expected: { ...e, payload_hash } })
    expect(both.json.reason).toBe('give_attachment_or_payload_hash_not_both')
  })

  it('needs the audience the receipt is for, and refuses a different one', async () => {
    const { audience, ...rest } = good.expected_action
    const missing = await call(trusted, good.now, { receipt: good.receipt, expected: rest })
    expect(missing.status).toBe(400)
    expect(missing.json.reason).toBe('missing_expected_action')
    const other = await call(trusted, good.now, { receipt: good.receipt, expected: { ...rest, audience: 'other-gate.example' } })
    expect(other.json.code).toBe('AUDIENCE_MISMATCH')
  })

  it('answers 400 on malformed JSON', async () => {
    const r = await call(trusted, good.now, null, '{not json')
    expect(r.status).toBe(400)
  })
})
