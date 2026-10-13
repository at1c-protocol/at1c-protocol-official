// AT1C agent certificate verifier, format version 1. Implements spec/agent-certificate.md section 4.
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { createHash } from 'crypto'
import { jcs, KeyRecord } from './verify'

export type CertCode =
  | 'OK' | 'SCHEMA' | 'ALG_NOT_ALLOWED' | 'UNKNOWN_ISSUER' | 'KEY_NOT_VALID' | 'BAD_SIGNATURE'
  | 'BAD_VALIDITY' | 'NOT_YET_VALID' | 'EXPIRED' | 'AGENT_ID_MISMATCH' | 'REVOKED'

export interface CertContext {
  now: Date // the verifier's own clock
  pinned: Record<string, KeyRecord> // REGISTRY keys only; never the approver list used for receipts
  allowedAlgs: string[]
  revoked: Set<string> // agent_id values
}

const MAX_LIFETIME_SECONDS = 366 * 86400
const RE_ID = /^agent:[0-9a-f]{32}$/
const RE_B64U = /^[A-Za-z0-9_-]+$/
const RE_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/
const TIERS = ['free', 'standard', 'enterprise']

const b64u = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64url'))
const ts = (s: string): number => Date.parse(s)

/** agent_id must be derived from the agent's key: "agent:" + first 32 hex of SHA-256(raw public key). */
export function agentIdFor(agentPublicKeyB64u: string): string {
  return 'agent:' + createHash('sha256').update(b64u(agentPublicKeyB64u)).digest('hex').slice(0, 32)
}

function schemaOk(c: any): boolean {
  try {
    const p = c.permissions
    return (
      c.version === '1' && c.type === 'agent_certificate' && RE_ID.test(c.agent_id) &&
      typeof c.agent_alg === 'string' && RE_B64U.test(c.agent_public_key) &&
      typeof c.name === 'string' && typeof c.owner === 'string' && c.owner.length > 0 &&
      Array.isArray(p) && p.every((x: unknown) => typeof x === 'string' && x.length > 0) &&
      p.every((x: string, i: number) => i === 0 || p[i - 1] < x) && // sorted ascending and unique
      TIERS.includes(c.tier) && RE_TS.test(c.issued_at) && RE_TS.test(c.expires_at) &&
      typeof c.issuer === 'string' && c.issuer.length > 0 && typeof c.alg === 'string' &&
      RE_B64U.test(c.signature)
    )
  } catch {
    return false
  }
}

export function verifyAgentCertificateV1(cert: any, ctx: CertContext): { ok: boolean; code: CertCode } {
  const fail = (code: CertCode) => ({ ok: false, code })

  if (!schemaOk(cert)) return fail('SCHEMA')
  if (cert.alg !== 'ML-DSA-65' || !ctx.allowedAlgs.includes(cert.alg) || !ctx.allowedAlgs.includes(cert.agent_alg)) {
    return fail('ALG_NOT_ALLOWED')
  }
  const rec = ctx.pinned[cert.issuer]
  if (!rec) return fail('UNKNOWN_ISSUER')
  const now = ctx.now.getTime()
  if (rec.alg !== cert.alg || rec.revoked || !(ts(rec.valid_from) <= now && now < ts(rec.valid_until))) {
    return fail('KEY_NOT_VALID')
  }

  const unsigned = structuredClone(cert)
  delete unsigned.signature
  let bytes: Uint8Array
  try {
    bytes = new TextEncoder().encode(jcs(unsigned))
  } catch {
    return fail('SCHEMA')
  }
  let sigOk = false
  try {
    sigOk = ml_dsa65.verify(b64u(cert.signature), bytes, b64u(rec.public_key))
  } catch {
    sigOk = false
  }
  if (!sigOk) return fail('BAD_SIGNATURE')

  const iat = ts(cert.issued_at)
  const exp = ts(cert.expires_at)
  if (exp <= iat || (exp - iat) / 1000 > MAX_LIFETIME_SECONDS) return fail('BAD_VALIDITY')
  if (now < iat) return fail('NOT_YET_VALID')
  if (now >= exp) return fail('EXPIRED')
  if (cert.agent_id !== agentIdFor(cert.agent_public_key)) return fail('AGENT_ID_MISMATCH')
  if (ctx.revoked.has(cert.agent_id)) return fail('REVOKED')
  return { ok: true, code: 'OK' }
}
