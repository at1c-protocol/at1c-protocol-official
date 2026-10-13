// Runs every vector in spec/test-vectors/agent-certificate-v1.json through verifyAgentCertificateV1.
import { describe, it, expect } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import { verifyAgentCertificateV1 } from '../src/agentCert'

const data = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../../spec/test-vectors/agent-certificate-v1.json'), 'utf-8'))

describe('AT1C agent certificate v1 conformance vectors', () => {
  for (const v of data.vectors) {
    it(v.name, () => {
      const result = verifyAgentCertificateV1(v.certificate, {
        now: new Date(v.now),
        pinned: v.pinned ?? data.pinned,
        allowedAlgs: data.allowed_algs,
        revoked: new Set<string>(v.revoked),
      })
      expect(result).toEqual({ ok: v.expect.ok, code: v.expect.code })
    })
  }
})
