// Runs every conformance vector in spec/test-vectors/receipt-v1.json through verifyReceiptV1.
import { describe, it, expect } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import { verifyReceiptV1 } from '../src/verify'

const file = path.resolve(__dirname, '../../../spec/test-vectors/receipt-v1.json')
const data = JSON.parse(fs.readFileSync(file, 'utf-8'))

describe('AT1C receipt v1 conformance vectors', () => {
  for (const v of data.vectors) {
    it(v.name, () => {
      const seen = new Set<string>(v.pre_seen_nonces)
      const result = verifyReceiptV1(v.receipt, {
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
