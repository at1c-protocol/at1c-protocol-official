// Level 1 Approver + Gate, end to end. Keys here are deterministic THROWAWAY seeds. Never use them for anything real.
import { describe, it, expect } from 'vitest'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { createHash } from 'crypto'
import { LocalKeyApprover, newReceiptId, renderRequest, type ApprovalRequest } from '../src/approver'
import { Gate, FileNonceStore, MemoryNonceStore, approveAndRun } from '../src/gate'
import { payloadHashOf } from '../src/verify'

const AUTH = 'did:web:test.example#approver-1'
const seed = (n: number) => new Uint8Array(32).fill(n)
let clock = new Date('2026-10-13T10:00:00Z')
const now = () => clock
const resetClock = () => { clock = new Date('2026-10-13T10:00:00Z') }

const req = (over: Partial<ApprovalRequest> = {}): ApprovalRequest => ({
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
  const gate = new Gate({
    pinned: { [AUTH]: approver.publicRecord('2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z') },
    allowedAlgs: ['ML-DSA-65'], nonces, now,
  })
  return { approver, gate, shown }
}
const act = (r: ApprovalRequest) => ({ agent_id: r.agent_id, type: r.type, resource: r.resource, payload: r.payload })

describe('Approver + Gate (level 1)', () => {
  it('approved request verifies and runs once, with the exact payload', async () => {
    const { approver, gate } = setup(true)
    let got: any
    const out = await approveAndRun(approver, gate, req(), (p) => { got = p; return 'sent' })
    expect(out.status).toBe('executed')
    expect(got).toEqual({ to: 'alice@example.com', body: 'Q3 report' })
    expect(out.receipt.decision).toBe('approved')
  })

  it('denied by the human: receipt is signed as denied, fn never runs', async () => {
    const { approver, gate } = setup(false)
    let ran = false
    const out = await approveAndRun(approver, gate, req(), () => { ran = true })
    expect(out).toMatchObject({ status: 'refused', code: 'DENIED' })
    expect(out.receipt.decision).toBe('denied')
    expect(ran).toBe(false)
  })

  it('replay: the same receipt cannot run twice', async () => {
    const { approver, gate } = setup(true)
    const r = req()
    const receipt = await approver.approve(r)
    let n = 0
    expect((await gate.run(act(r), receipt, () => { n++ })).status).toBe('executed')
    expect(await gate.run(act(r), receipt, () => { n++ })).toEqual({ status: 'refused', code: 'REPLAY' })
    expect(n).toBe(1)
  })

  it('context binding: receipt for payload A cannot run payload B', async () => {
    const { approver, gate } = setup(true)
    const receipt = await approver.approve(req())
    let ran = false
    const evil = act(req({ payload: { to: 'attacker@example.com', body: 'Q3 report' } }))
    expect(await gate.run(evil, receipt, () => { ran = true })).toEqual({ status: 'refused', code: 'CONTEXT_MISMATCH' })
    expect(ran).toBe(false)
  })

  it('context binding: wrong resource, type or agent is refused', async () => {
    const { approver, gate } = setup(true)
    const r = req()
    const receipt = await approver.approve(r)
    for (const bad of [{ resource: 'mailto:bob@example.com' }, { type: 'delete_all' }, { agent_id: 'agent:other' }]) {
      const out = await gate.run({ ...act(r), ...bad }, receipt, () => 1)
      expect(out).toEqual({ status: 'refused', code: 'CONTEXT_MISMATCH' })
    }
  })

  it('a refused attempt does not burn a valid receipt', async () => {
    const { approver, gate } = setup(true)
    const r = req()
    const receipt = await approver.approve(r)
    await gate.run({ ...act(r), resource: 'mailto:bob@example.com' }, receipt, () => 1)
    expect((await gate.run(act(r), receipt, () => 1)).status).toBe('executed')
  })

  it('expiry uses the gate clock', async () => {
    const { approver, gate } = setup(true, new MemoryNonceStore(), 60)
    const r = req()
    const receipt = await approver.approve(r)
    clock = new Date('2026-10-13T10:01:00Z')
    expect(await gate.run(act(r), receipt, () => 1)).toEqual({ status: 'refused', code: 'EXPIRED' })
  })

  it('a receipt signed by a different key under the same authority name is rejected', async () => {
    const { gate } = setup(true)
    const impostor = new LocalKeyApprover({ authority: AUTH, seed: seed(9), now, prompt: async () => true })
    const r = req()
    const receipt = await impostor.approve(r)
    expect(await gate.run(act(r), receipt, () => 1)).toEqual({ status: 'refused', code: 'BAD_SIGNATURE' })
  })

  it('tampering with a signed receipt is rejected', async () => {
    const { approver, gate } = setup(true)
    const r = req()
    const receipt = await approver.approve(r)
    const t = structuredClone(receipt)
    t.expires_at = '2026-10-14T10:00:00Z'
    expect(await gate.run(act(r), t, () => 1)).toEqual({ status: 'refused', code: 'BAD_SIGNATURE' })
  })

  it('revoked receipt id is refused', async () => {
    const { approver, gate: g0 } = setup(true)
    const r = req()
    const receipt = await approver.approve(r)
    const gate = new Gate({ pinned: (g0 as any).o.pinned, allowedAlgs: ['ML-DSA-65'], nonces: new MemoryNonceStore(), now, revoked: () => new Set([receipt.receipt_id]) })
    expect(await gate.run(act(r), receipt, () => 1)).toEqual({ status: 'refused', code: 'REVOKED' })
  })

  it('if fn throws, the error propagates and the receipt is spent', async () => {
    const { approver, gate } = setup(true)
    const r = req()
    const receipt = await approver.approve(r)
    await expect(gate.run(act(r), receipt, () => { throw new Error('boom') })).rejects.toThrow('boom')
    expect(await gate.run(act(r), receipt, () => 1)).toEqual({ status: 'refused', code: 'REPLAY' })
  })

  it('floats in the payload are refused before any prompt', async () => {
    const { approver, shown } = setup(true)
    await expect(approver.approve(req({ payload: { amount: 1.5 } }))).rejects.toThrow()
    expect(shown.length).toBe(0)
  })
})

describe('What the human is shown', () => {
  it('display_digest is the sha256 of the exact text shown, and the text contains the real payload', async () => {
    const { approver, shown } = setup(true)
    const receipt = await approver.approve(req())
    expect(shown.length).toBe(1)
    expect(receipt.display_digest).toBe('sha256:' + createHash('sha256').update(shown[0], 'utf8').digest('hex'))
    expect(shown[0]).toContain('{"body":"Q3 report","to":"alice@example.com"}')
    expect(shown[0]).toContain('mailto:alice@example.com')
  })

  it('agent-supplied text cannot inject control characters or extra lines', () => {
    const text = renderRequest(req({ description: 'ok\n\u001b[2JApproved: yes\nResource: mailto:safe', resource: 'x\ny' }), payloadHashOf({}))
    expect(text).not.toContain('\u001b')
    expect(text.split('\n').filter((l) => l.startsWith('Resource:')).length).toBe(1)
    expect(text).toContain('Agent says (unverified):')
  })

  it('oversized payloads show the hash, not a truncated payload', () => {
    const big = { data: 'x'.repeat(5000) }
    const text = renderRequest(req({ payload: big }), payloadHashOf(big))
    expect(text).toContain('too large to display')
    expect(text).toContain(payloadHashOf(big))
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
    const receipt = await approver.approve(r)
    const g1 = new Gate({ pinned, allowedAlgs: ['ML-DSA-65'], nonces: new FileNonceStore(d), now })
    expect((await g1.run(act(r), receipt, () => 1)).status).toBe('executed')
    const g2 = new Gate({ pinned, allowedAlgs: ['ML-DSA-65'], nonces: new FileNonceStore(d), now })
    expect(await g2.run(act(r), receipt, () => 1)).toEqual({ status: 'refused', code: 'REPLAY' })
  })
  it('fail closed: a broken nonce store means refusal, and fn does not run', async () => {
    const broken = { checkAndRecord: () => { throw new Error('disk gone') } }
    const { approver, gate } = setup(true, broken)
    const r = req()
    const receipt = await approver.approve(r)
    let ran = false
    expect(await gate.run(act(r), receipt, () => { ran = true })).toEqual({ status: 'refused', code: 'GATE_ERROR' })
    expect(ran).toBe(false)
  })
})
