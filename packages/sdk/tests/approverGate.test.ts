// Level 1 Approver + Gate, end to end, receipt format 2. Keys here are deterministic THROWAWAY seeds. Never use them for anything real.
import { describe, it, expect } from 'vitest'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { createHash } from 'crypto'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { LocalKeyApprover, newReceiptId, renderRequest, receiptOnly, type ApprovalRequest } from '../src/approver'
import { Gate, FileNonceStore, MemoryNonceStore, approveAndRun } from '../src/gate'
import { attachmentHashOf, jcs, RECEIPT_CONTEXT } from '../src/verify'

const AUTH = 'did:web:test.example#approver-1'
const AUD = 'gate.test.example'
const SALT = 'A'.repeat(43) // a fixed, well-formed salt for display tests only
const seed = (n: number) => new Uint8Array(32).fill(n)
let clock = new Date('2026-10-13T10:00:00Z')
const now = () => clock
const resetClock = () => { clock = new Date('2026-10-13T10:00:00Z') }

const req = (over: Partial<ApprovalRequest> = {}): ApprovalRequest => ({
  audience: AUD,
  agent_id: 'agent:mail-bot',
  agent_public_key: 'AAAA',
  type: 'send_email',
  class: 'irreversible',
  resource: 'mailto:alice@example.com',
  payload: { to: 'alice@example.com', body: 'Q3 report' },
  ...over,
})

function setup(answer: boolean | ((t: string) => boolean) = true, nonces: any = new MemoryNonceStore(), ttl?: number) {
  resetClock()
  const shown: string[] = []
  const approver = new LocalKeyApprover({
    authority: AUTH, seed: seed(7), now, ttlSeconds: ttl,
    prompt: async (t) => { shown.push(t); return typeof answer === 'function' ? answer(t) : answer },
  })
  const pinned = { [AUTH]: approver.publicRecord('2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z') }
  const gate = new Gate({
    audience: AUD, pinned, allowedAlgs: ['ML-DSA-65'], nonces, now, revoked: () => new Set<string>(),
  })
  return { approver, gate, shown, pinned }
}
const act = (r: ApprovalRequest) => ({ agent_id: r.agent_id, type: r.type, resource: r.resource })

describe('Approver + Gate (level 1)', () => {
  it('approved request verifies and runs once, with the exact payload', async () => {
    const { approver, gate } = setup(true)
    let got: any
    const out = await approveAndRun(approver, gate, req(), (p) => { got = p; return 'sent' })
    expect(out.status).toBe('executed')
    expect(got).toEqual({ to: 'alice@example.com', body: 'Q3 report' })
    expect(out.bundle.receipt.decision).toBe('approved')
    expect(out.bundle.receipt.version).toBe('2')
  })

  it('denied by the human: receipt is signed as denied, fn never runs', async () => {
    const { approver, gate } = setup(false)
    let ran = false
    const out = await approveAndRun(approver, gate, req(), () => { ran = true })
    expect(out).toMatchObject({ status: 'refused', code: 'DENIED' })
    expect(out.bundle.receipt.decision).toBe('denied')
    expect(ran).toBe(false)
  })

  it('replay: the same receipt cannot run twice', async () => {
    const { approver, gate } = setup(true)
    const r = req()
    const bundle = await approver.approve(r)
    let n = 0
    expect((await gate.run(act(r), bundle, () => { n++ })).status).toBe('executed')
    expect(await gate.run(act(r), bundle, () => { n++ })).toEqual({ status: 'refused', code: 'REPLAY' })
    expect(n).toBe(1)
  })

  it('context binding: receipt for payload A cannot run payload B', async () => {
    const { approver, gate } = setup(true)
    const r = req()
    const bundle = await approver.approve(r)
    let ran = false
    const evil = { receipt: bundle.receipt, attachment: { payload: { to: 'attacker@example.com', body: 'Q3 report' }, salt: bundle.attachment.salt } }
    expect(await gate.run(act(r), evil, () => { ran = true })).toEqual({ status: 'refused', code: 'CONTEXT_MISMATCH' })
    expect(ran).toBe(false)
  })

  it('context binding: the same payload with a different salt is refused', async () => {
    const { approver, gate } = setup(true)
    const r = req()
    const bundle = await approver.approve(r)
    const resalted = { receipt: bundle.receipt, attachment: { payload: bundle.attachment.payload, salt: SALT } }
    expect(await gate.run(act(r), resalted, () => 1)).toEqual({ status: 'refused', code: 'CONTEXT_MISMATCH' })
  })

  it('context binding: wrong resource, type or agent is refused', async () => {
    const { approver, gate } = setup(true)
    const r = req()
    const bundle = await approver.approve(r)
    for (const bad of [{ resource: 'mailto:bob@example.com' }, { type: 'delete_all' }, { agent_id: 'agent:other' }]) {
      const out = await gate.run({ ...act(r), ...bad }, bundle, () => 1)
      expect(out).toEqual({ status: 'refused', code: 'CONTEXT_MISMATCH' })
    }
  })

  it('a refused attempt does not burn a valid receipt', async () => {
    const { approver, gate } = setup(true)
    const r = req()
    const bundle = await approver.approve(r)
    await gate.run({ ...act(r), resource: 'mailto:bob@example.com' }, bundle, () => 1)
    expect((await gate.run(act(r), bundle, () => 1)).status).toBe('executed')
  })

  it('expiry uses the gate clock', async () => {
    const { approver, gate } = setup(true, new MemoryNonceStore(), 60)
    const r = req()
    const bundle = await approver.approve(r)
    clock = new Date('2026-10-13T10:01:00Z')
    expect(await gate.run(act(r), bundle, () => 1)).toEqual({ status: 'refused', code: 'EXPIRED' })
  })

  it('a receipt signed by a different key under the same authority name is rejected', async () => {
    const { gate } = setup(true)
    const impostor = new LocalKeyApprover({ authority: AUTH, seed: seed(9), now, prompt: async () => true })
    const r = req()
    const bundle = await impostor.approve(r)
    expect(await gate.run(act(r), bundle, () => 1)).toEqual({ status: 'refused', code: 'BAD_SIGNATURE' })
  })

  it('tampering with a signed receipt is rejected', async () => {
    const { approver, gate } = setup(true)
    const r = req()
    const bundle = await approver.approve(r)
    const t = structuredClone(bundle)
    t.receipt.expires_at = '2026-10-14T10:00:00Z'
    expect(await gate.run(act(r), t, () => 1)).toEqual({ status: 'refused', code: 'BAD_SIGNATURE' })
  })

  it('revoked receipt id is refused', async () => {
    const { approver, gate: g0 } = setup(true)
    const r = req()
    const bundle = await approver.approve(r)
    const gate = new Gate({ audience: AUD, pinned: (g0 as any).o.pinned, allowedAlgs: ['ML-DSA-65'], nonces: new MemoryNonceStore(), now, revoked: () => new Set([bundle.receipt.receipt_id]) })
    expect(await gate.run(act(r), bundle, () => 1)).toEqual({ status: 'refused', code: 'REVOKED' })
  })

  it('if fn throws, the error propagates and the receipt is spent', async () => {
    const { approver, gate } = setup(true)
    const r = req()
    const bundle = await approver.approve(r)
    await expect(gate.run(act(r), bundle, () => { throw new Error('boom') })).rejects.toThrow('boom')
    expect(await gate.run(act(r), bundle, () => 1)).toEqual({ status: 'refused', code: 'REPLAY' })
  })

  it('floats in the payload are refused before any prompt', async () => {
    const { approver, shown } = setup(true)
    await expect(approver.approve(req({ payload: { amount: 1.5 } }))).rejects.toThrow()
    expect(shown.length).toBe(0)
  })
})

describe('Format 2: bundle, salt, audience, label', () => {
  it('no travel without salt: a receipt without its attachment is refused, fn never runs', async () => {
    const { approver, gate } = setup(true)
    const r = req()
    const bundle = await approver.approve(r)
    let ran = false
    expect(await gate.run(act(r), { receipt: bundle.receipt }, () => { ran = true })).toEqual({ status: 'refused', code: 'NO_ATTACHMENT' })
    expect(await gate.run(act(r), bundle.receipt, () => { ran = true })).toEqual({ status: 'refused', code: 'SCHEMA' })
    expect(await gate.run(act(r), null, () => { ran = true })).toEqual({ status: 'refused', code: 'SCHEMA' })
    expect(ran).toBe(false)
    expect((await gate.run(act(r), bundle, () => 1)).status).toBe('executed') // none of the refusals burned it
  })

  it('a malformed attachment is refused', async () => {
    const { approver, gate } = setup(true)
    const r = req()
    const bundle = await approver.approve(r)
    const p = bundle.attachment.payload
    for (const bad of [{ payload: p }, { payload: p, salt: 'short' }, { payload: p, salt: bundle.attachment.salt, extra: 1 }, { salt: bundle.attachment.salt }, 'text', []]) {
      expect(await gate.run(act(r), { receipt: bundle.receipt, attachment: bad }, () => 1)).toEqual({ status: 'refused', code: 'SCHEMA' })
    }
  })

  it('every receipt gets a fresh salt: the same payload twice gives two different fingerprints', async () => {
    const { approver } = setup(true)
    const a = await approver.approve(req())
    const b = await approver.approve(req())
    expect(a.attachment.salt).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(a.attachment.salt).not.toBe(b.attachment.salt)
    expect(a.receipt.action.payload_hash).not.toBe(b.receipt.action.payload_hash)
    expect(a.receipt.action.payload_hash).toBe(attachmentHashOf(a.attachment))
    const unsalted = 'sha256:' + createHash('sha256').update(jcs(req().payload), 'utf8').digest('hex')
    expect(a.receipt.action.payload_hash).not.toBe(unsalted)
  })

  it('the receipt alone does not contain the payload or the salt', async () => {
    const { approver } = setup(true)
    const bundle = await approver.approve(req())
    const text = JSON.stringify(receiptOnly(bundle))
    expect(text).not.toContain('Q3 report')
    expect(text).not.toContain(bundle.attachment.salt)
  })

  it('the bundle does not change if the caller alters its payload object afterwards', async () => {
    const { approver, gate } = setup(true)
    const payload = { to: 'alice@example.com', body: 'Q3 report' }
    const r = req({ payload })
    const bundle = await approver.approve(r)
    payload.to = 'attacker@example.com'
    let got: any
    expect((await gate.run(act(r), bundle, (p) => { got = p })).status).toBe('executed')
    expect(got).toEqual({ to: 'alice@example.com', body: 'Q3 report' })
  })

  it('audience: a receipt made for one gate is refused by a gate with another name', async () => {
    const { approver, pinned } = setup(true)
    const r = req()
    const bundle = await approver.approve(r)
    const other = new Gate({ audience: 'other-gate.example', pinned, allowedAlgs: ['ML-DSA-65'], nonces: new MemoryNonceStore(), now, revoked: () => new Set<string>() })
    let ran = false
    expect(await other.run(act(r), bundle, () => { ran = true })).toEqual({ status: 'refused', code: 'AUDIENCE_MISMATCH' })
    expect(ran).toBe(false)
  })

  it('audience: changing it after signing breaks the signature', async () => {
    const { approver, pinned } = setup(true)
    const r = req()
    const bundle = await approver.approve(r)
    const t = structuredClone(bundle)
    t.receipt.audience = 'other-gate.example'
    const other = new Gate({ audience: 'other-gate.example', pinned, allowedAlgs: ['ML-DSA-65'], nonces: new MemoryNonceStore(), now, revoked: () => new Set<string>() })
    expect(await other.run(act(r), t, () => 1)).toEqual({ status: 'refused', code: 'BAD_SIGNATURE' })
  })

  it('a Gate refuses to start without its own audience name, and the approver refuses a request without one', async () => {
    expect(() => new Gate({ pinned: {}, allowedAlgs: ['ML-DSA-65'], nonces: new MemoryNonceStore(), revoked: () => new Set<string>() } as any)).toThrow(/audience/)
    expect(() => new Gate({ audience: '', pinned: {}, allowedAlgs: ['ML-DSA-65'], nonces: new MemoryNonceStore(), revoked: () => new Set<string>() })).toThrow(/audience/)
    const { approver, shown } = setup(true)
    await expect(approver.approve(req({ audience: '' }))).rejects.toThrow('audience')
    expect(shown.length).toBe(0)
  })

  it('label: the signature verifies only under the receipt label', async () => {
    const { approver, pinned } = setup(true)
    const { receipt } = await approver.approve(req())
    const unsigned: any = structuredClone(receipt)
    delete unsigned.approval.signature
    const msg = new TextEncoder().encode(jcs(unsigned))
    const sig = new Uint8Array(Buffer.from(receipt.approval.signature, 'base64url'))
    const pub = new Uint8Array(Buffer.from(pinned[AUTH].public_key, 'base64url'))
    const ctx = (s: string) => ({ context: new TextEncoder().encode(s) })
    expect(ml_dsa65.verify(sig, msg, pub, ctx(RECEIPT_CONTEXT))).toBe(true)
    expect(ml_dsa65.verify(sig, msg, pub)).toBe(false)
    expect(ml_dsa65.verify(sig, msg, pub, ctx('AT1C/identity-log/v1'))).toBe(false)
  })

  it('an authority named like a built-in property finds no key', async () => {
    const { gate } = setup(true)
    const impostor = new LocalKeyApprover({ authority: 'constructor', seed: seed(9), now, prompt: async () => true })
    const r = req()
    expect(await gate.run(act(r), await impostor.approve(r), () => 1)).toEqual({ status: 'refused', code: 'UNKNOWN_AUTHORITY' })
  })
})

describe('Plain-name rule (no secrets in signed text)', () => {
  it('a resource with a login or a query string is refused before any prompt', async () => {
    const { approver, shown } = setup(true)
    for (const resource of ['postgres://admin:password@db.example/prod', 'https://api.example/v1?token=abc', 'acct:123?x=1']) {
      await expect(approver.approve(req({ resource }))).rejects.toThrow('must not contain')
    }
    await expect(approver.approve(req({ audience: 'https://user:pw@gate.example' }))).rejects.toThrow('must not contain')
    expect(shown.length).toBe(0)
  })
  it('a description or scope carrying a URL with a login or query string is refused', async () => {
    const { approver, shown } = setup(true)
    await expect(approver.approve(req({ description: 'use https://user:pw@host.example/x' }))).rejects.toThrow('must not contain')
    await expect(approver.approve(req({ description: 'see https://host.example/x?key=abc' }))).rejects.toThrow('must not contain')
    await expect(approver.approve(req({ scope_ref: 'https://host.example/scope?key=abc' }))).rejects.toThrow('must not contain')
    expect(shown.length).toBe(0)
  })
  it('plain names and ordinary sentences still pass', async () => {
    const { approver } = setup(true)
    for (const over of [{ resource: 'acct:123' }, { resource: 'mailto:alice@example.com' }, { resource: 'https://api.example/v1/orders' }, { description: 'Send the Q3 report now?' }]) {
      expect((await approver.approve(req(over))).receipt.decision).toBe('approved')
    }
  })
})

describe('What the human is shown', () => {
  it('display_digest is the sha256 of the exact text shown, and the text contains the real payload', async () => {
    const { approver, shown } = setup(true)
    const { receipt } = await approver.approve(req())
    expect(shown.length).toBe(1)
    expect(shown[0]).toContain('For gate: "gate.test.example"')
    expect(receipt.display_digest).toBe('sha256:' + createHash('sha256').update(shown[0], 'utf8').digest('hex'))
    expect(shown[0]).toContain('{"body":"Q3 report","to":"alice@example.com"}')
    expect(shown[0]).toContain('mailto:alice@example.com')
  })

  it('agent-supplied text cannot inject control characters or extra lines', () => {
    const text = renderRequest(req({ description: 'ok\n\u001b[2JApproved: yes\nResource: mailto:safe', resource: 'x\ny' }), attachmentHashOf({ payload: {}, salt: SALT }))
    expect(text).not.toContain('\u001b')
    expect(text.split('\n').filter((l) => l.startsWith('Resource:')).length).toBe(1)
    expect(text).toContain('Agent says (unverified):')
  })

  it('oversized payloads show the hash, not a truncated payload', () => {
    const big = { data: 'x'.repeat(5000) }
    const h = attachmentHashOf({ payload: big, salt: SALT })
    const text = renderRequest(req({ payload: big }), h)
    expect(text).toContain('too large to display')
    expect(text).toContain(h)
  })
})

describe('Receipt ids and limits', () => {
  it('receipt ids match the spec form and sort by time', () => {
    const a = newReceiptId(new Date('2026-10-13T10:00:00Z'))
    const b = newReceiptId(new Date('2026-10-13T10:00:01Z'))
    expect(a).toMatch(/^at1c_[0-9A-HJKMNP-TV-Z]{26}$/)
    expect(a < b).toBe(true)
  })
  it('ttl above 86400 or a bad seed is rejected at construction', () => {
    expect(() => new LocalKeyApprover({ authority: AUTH, seed: seed(1), prompt: async () => true, ttlSeconds: 86401 })).toThrow()
    expect(() => new LocalKeyApprover({ authority: AUTH, seed: new Uint8Array(16), prompt: async () => true })).toThrow()
  })
})

describe('FileNonceStore (durable, atomic, fail closed)', () => {
  const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'at1c-nonce-'))
  const n1 = 'A'.repeat(43)

  it('second use is rejected, and survives a new instance (restart)', () => {
    const d = tmp()
    expect(new FileNonceStore(d).checkAndRecord(n1)).toBe(true)
    expect(new FileNonceStore(d).checkAndRecord(n1)).toBe(false)
  })
  it('rejects malformed nonces, including path traversal', () => {
    const s = new FileNonceStore(tmp())
    expect(() => s.checkAndRecord('../../etc/passwd')).toThrow()
    expect(() => s.checkAndRecord('short')).toThrow()
  })
  it('gate end to end with files: replay refused after restart', async () => {
    const d = tmp()
    const { approver } = setup(true)
    const pinned = { [AUTH]: approver.publicRecord('2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z') }
    const r = req()
    const bundle = await approver.approve(r)
    const g1 = new Gate({ audience: AUD, pinned, allowedAlgs: ['ML-DSA-65'], nonces: new FileNonceStore(d), now, revoked: () => new Set<string>() })
    expect((await g1.run(act(r), bundle, () => 1)).status).toBe('executed')
    const g2 = new Gate({ audience: AUD, pinned, allowedAlgs: ['ML-DSA-65'], nonces: new FileNonceStore(d), now, revoked: () => new Set<string>() })
    expect(await g2.run(act(r), bundle, () => 1)).toEqual({ status: 'refused', code: 'REPLAY' })
  })
  it('fail closed: a broken nonce store means refusal, and fn does not run', async () => {
    const broken = { checkAndRecord: () => { throw new Error('disk gone') } }
    const { approver, gate } = setup(true, broken)
    const r = req()
    const bundle = await approver.approve(r)
    let ran = false
    expect(await gate.run(act(r), bundle, () => { ran = true })).toEqual({ status: 'refused', code: 'GATE_ERROR' })
    expect(ran).toBe(false)
  })
})

describe('Gate: revocation list is required (2.0.0)', () => {
  it('refuses to start without a revoked list', () => {
    expect(() => new Gate({ pinned: {}, allowedAlgs: ['ML-DSA-65'], nonces: new MemoryNonceStore() } as any)).toThrow(/revoked/)
  })
  it('revoked() returning something other than a Set refuses, and fn does not run', async () => {
    const { approver } = setup(true)
    const pinned = { [AUTH]: approver.publicRecord('2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z') }
    const r = req()
    const bundle = await approver.approve(r)
    const g = new Gate({ audience: AUD, pinned, allowedAlgs: ['ML-DSA-65'], nonces: new MemoryNonceStore(), now, revoked: (() => [bundle.receipt.receipt_id]) as any })
    let ran = false
    expect(await g.run(act(r), bundle, () => { ran = true; return 1 })).toEqual({ status: 'refused', code: 'GATE_ERROR' })
    expect(ran).toBe(false)
  })
})

describe('fileRevocationList (2.0.0)', () => {
  it('creates an empty list if missing; a receipt id added to the file is refused as REVOKED', async () => {
    const fsm = await import('fs'); const pathm = await import('path')
    const { fileRevocationList } = await import('../src/gate')
    const file = pathm.join(fsm.mkdtempSync(pathm.join((await import('os')).tmpdir(), 'at1c-rev-')), 'sub', 'revoked.json')
    const list = fileRevocationList(file)
    expect(JSON.parse(fsm.readFileSync(file, 'utf8'))).toEqual([])
    const { approver } = setup(true)
    const pinned = { [AUTH]: approver.publicRecord('2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z') }
    const r = req()
    const bundle = await approver.approve(r)
    fsm.writeFileSync(file, JSON.stringify([bundle.receipt.receipt_id]))
    const g = new Gate({ audience: AUD, pinned, allowedAlgs: ['ML-DSA-65'], nonces: new MemoryNonceStore(), now, revoked: list })
    let ran = false
    expect(await g.run(act(r), bundle, () => { ran = true; return 1 })).toEqual({ status: 'refused', code: 'REVOKED' })
    expect(ran).toBe(false)
  })
  it('file deleted or corrupt after start: refused (GATE_ERROR), fn does not run', async () => {
    const fsm = await import('fs'); const pathm = await import('path')
    const { fileRevocationList } = await import('../src/gate')
    const file = pathm.join(fsm.mkdtempSync(pathm.join((await import('os')).tmpdir(), 'at1c-rev-')), 'revoked.json')
    const list = fileRevocationList(file)
    const { approver } = setup(true)
    const pinned = { [AUTH]: approver.publicRecord('2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z') }
    for (const breakIt of [() => fsm.rmSync(file), () => fsm.writeFileSync(file, '{not json')]) {
      const r = req()
      const bundle = await approver.approve(r)
      breakIt()
      const g = new Gate({ audience: AUD, pinned, allowedAlgs: ['ML-DSA-65'], nonces: new MemoryNonceStore(), now, revoked: list })
      let ran = false
      expect(await g.run(act(r), bundle, () => { ran = true; return 1 })).toEqual({ status: 'refused', code: 'GATE_ERROR' })
      expect(ran).toBe(false)
    }
  })
})
