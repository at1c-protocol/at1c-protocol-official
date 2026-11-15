// Runs every conformance vector in spec/test-vectors/receipt-v2.json through verifyReceiptV2.
// The vectors are produced by an independent Python/OpenSSL implementation (tools/at1c_ref.py), so this also
// proves the SDK's labelled ML-DSA-65 signatures interoperate with another FIPS 204 implementation.
import { describe, it, expect } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import { verifyReceiptV2, attachmentHashOf, RECEIPT_CONTEXT } from '../src/verify'

const file = path.resolve(__dirname, '../../../spec/test-vectors/receipt-v2.json')
const data = JSON.parse(fs.readFileSync(file, 'utf-8'))

describe('AT1C receipt v2 conformance vectors', () => {
  it('the vector file is for format 2 and the receipt label', () => {
    expect(data.receipt_version).toBe('2')
    expect(data.signing_context).toBe(RECEIPT_CONTEXT)
  })

  for (const v of data.vectors) {
    it(v.name, () => {
      const seen = new Set<string>(v.pre_seen_nonces)
      const result = verifyReceiptV2(v.receipt, {
        now: new Date(v.now),
        pinned: v.pinned ?? data.pinned,
        allowedAlgs: data.allowed_algs,
        expected: v.expected_action,
        nonces: { checkAndRecord: (n: string) => (seen.has(n) ? false : (seen.add(n), true)) },
        revoked: new Set<string>(v.revoked),
      })
      expect(result).toEqual({ ok: v.expect.ok, code: v.expect.code })
    })
  }
})

describe('AT1C attachment fingerprint vectors', () => {
  for (const a of data.attachment_vectors.accept) {
    it(`fingerprint: ${a.name}`, () => {
      expect(attachmentHashOf(a.attachment)).toBe(a.payload_hash)
    })
  }
  for (const a of data.attachment_vectors.reject) {
    it(`refused: ${a.name}`, () => {
      expect(() => attachmentHashOf(a.attachment)).toThrow()
    })
  }
})
