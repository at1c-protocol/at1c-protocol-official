// AT1C receipt verifier, format version 1. Implements spec/receipt.md section 5 and spec/keys.md.
// UNTESTED until run against spec/test-vectors/receipt-v1.json (see tests/vectors.test.ts).
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import canonicalize from 'canonicalize'

export type VerifyCode =
  | 'OK' | 'SCHEMA' | 'ALG_NOT_ALLOWED' | 'UNKNOWN_AUTHORITY' | 'KEY_NOT_VALID'
  | 'BAD_SIGNATURE' | 'DENIED' | 'BAD_TTL' | 'NOT_YET_VALID' | 'EXPIRED'
  | 'CONTEXT_MISMATCH' | 'REVOKED' | 'REPLAY'

export interface KeyRecord {
  alg: string
  public_key: string // base64url
  valid_from: string
  valid_until: string
  revoked: boolean
}

export interface ExpectedAction {
  agent_id: string
  type: string
  resource: string
  payload_hash: string // the gate computes this from the real payload
}

/** Must be atomic and durable in production. Returns true if the nonce was new (and records it). */
export interface NonceStore {
  checkAndRecord(nonce: string): boolean
}

export interface VerifyContext {
  now: Date // the verifier's own clock
  pinned: Record<string, KeyRecord>
  allowedAlgs: string[]
  expected: ExpectedAction
  nonces: NonceStore
  revoked: Set<string>
}

const MAX_TTL_SECONDS = 86400
const RE_ID = /^at1c_[0-9A-HJKMNP-TV-Z]{26}$/
const RE_HASH = /^sha256:[0-9a-f]{64}$/
const RE_B64U = /^[A-Za-z0-9_-]+$/
const RE_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/
const CLASSES = ['compensable', 'retriable', 'irreversible']

const b64u = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64url'))
const ts = (s: string): number => Date.parse(s)
const isStr = (x: unknown): x is string => typeof x === 'string' && x.length > 0

function schemaOk(r: any): boolean {
  try {
    return (
      r.version === '1' && RE_ID.test(r.receipt_id) &&
      (r.decision === 'approved' || r.decision === 'denied') &&
      RE_TS.test(r.issued_at) && RE_TS.test(r.expires_at) &&
      isStr(r.actor?.agent_id) &&
      CLASSES.includes(r.action?.class) && RE_HASH.test(r.action?.payload_hash) &&
      typeof r.action?.type === 'string' && typeof r.action?.resource === 'string' &&
      RE_HASH.test(r.display_digest) &&
      isStr(r.approval?.authority) && isStr(r.approval?.alg) && RE_B64U.test(r.approval?.signature) &&
      RE_B64U.test(r.nonce) && b64u(r.nonce).length === 32
    )
  } catch {
    return false
  }
}

/** Returns a code; ok is true only for 'OK'. First failing check wins; the nonce is consumed last. */
export function verifyReceiptV1(receipt: any, ctx: VerifyContext): { ok: boolean; code: VerifyCode } {
  const fail = (code: VerifyCode) => ({ ok: false, code })

  if (!schemaOk(receipt)) return fail('SCHEMA')
  const ap = receipt.approval
  if (ap.alg !== 'ML-DSA-65' || !ctx.allowedAlgs.includes(ap.alg)) return fail('ALG_NOT_ALLOWED')

  const rec = ctx.pinned[ap.authority] // key comes from the verifier's list, never from the receipt
  if (!rec) return fail('UNKNOWN_AUTHORITY')
  const now = ctx.now.getTime()
  if (rec.alg !== ap.alg || rec.revoked || !(ts(rec.valid_from) <= now && now < ts(rec.valid_until))) {
    return fail('KEY_NOT_VALID')
  }

  const unsigned = structuredClone(receipt)
  delete unsigned.approval.signature
  const bytes = new TextEncoder().encode(canonicalize(unsigned) as string)
  let sigOk = false
  try {
    sigOk = ml_dsa65.verify(b64u(ap.signature), bytes, b64u(rec.public_key))
  } catch {
    sigOk = false
  }
  if (!sigOk) return fail('BAD_SIGNATURE')

  if (receipt.decision !== 'approved') return fail('DENIED')

  const iat = ts(receipt.issued_at)
  const exp = ts(receipt.expires_at)
  if (exp <= iat || (exp - iat) / 1000 > MAX_TTL_SECONDS) return fail('BAD_TTL')
  if (now < iat) return fail('NOT_YET_VALID')
  if (now >= exp) return fail('EXPIRED')

  const e = ctx.expected
  const a = receipt.action
  if (
    receipt.actor.agent_id !== e.agent_id || a.type !== e.type ||
    a.resource !== e.resource || a.payload_hash !== e.payload_hash
  ) return fail('CONTEXT_MISMATCH')

  if (ctx.revoked.has(receipt.receipt_id)) return fail('REVOKED')
  if (!ctx.nonces.checkAndRecord(receipt.nonce)) return fail('REPLAY')

  return { ok: true, code: 'OK' }
}
