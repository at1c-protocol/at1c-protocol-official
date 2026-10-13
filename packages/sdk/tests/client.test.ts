// AT1C client (level 1). Uses throwaway seeds and temp folders only. Never use these keys for anything real.
import { describe, it, expect } from 'vitest'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { AT1C, terminalPrompt, sanitiseAuthority } from '../src/client'
import { LocalKeyApprover } from '../src/approver'

const AUTH = 'did:web:test.example#user-1'
const SEED_HEX = '07'.repeat(32)
const now = () => new Date('2026-10-13T10:00:00Z')

function env(over: { prompt?: (t: string) => Promise<boolean>; policies?: string; keyMode?: number; trustedSeed?: number } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'at1c-client-'))
  const keyFile = path.join(dir, 'key.json')
  fs.writeFileSync(keyFile, JSON.stringify({ alg: 'ML-DSA-65', authority: AUTH, seed_hex: SEED_HEX }), { mode: 0o600 })
  fs.chmodSync(keyFile, over.keyMode ?? 0o600)
  const pubSource = new LocalKeyApprover({
    authority: AUTH, seed: new Uint8Array(32).fill(over.trustedSeed ?? 7), prompt: async () => true,
  })
  const trustedKeysFile = path.join(dir, 'trusted-keys.json')
  fs.writeFileSync(trustedKeysFile, JSON.stringify({
    allowed_algs: ['ML-DSA-65'],
    keys: { [AUTH]: pubSource.publicRecord('2026-01-01T00:00:00Z', '2027-01-01T00:00:00Z') },
  }))
  const policiesFile = path.join(dir, 'policies.json')
  if (over.policies !== undefined) fs.writeFileSync(policiesFile, over.policies)
  const shown: string[] = []
  const prompt = over.prompt ?? (async (t: string) => { shown.push(t); return true })
  const opts = {
    authority: AUTH, keyFile, trustedKeysFile, policiesFile,
    receiptsFile: path.join(dir, 'receipts.json'), nonceDir: path.join(dir, 'nonces'), prompt, now,
  }
  return { dir, opts, shown }
}

const cfg = (over: object = {}) => ({
  agentId: 'agent:mail-bot', action: 'send_email', resource: 'mailto:alice@example.com',
  payload: { to: 'alice@example.com', body: 'hi' }, ...over,
})

describe('AT1C client', () => {
  it('approved: runs fn with the exact payload, saves the receipt', async () => {
    const e = env()
    const at1c = new AT1C(e.opts)
    let got: any
    const out = await at1c.enforce(cfg(), (p) => { got = p; return 'sent' })
    expect(out.status).toBe('approved')
    expect(got).toEqual({ to: 'alice@example.com', body: 'hi' })
    const saved = JSON.parse(fs.readFileSync(e.opts.receiptsFile, 'utf-8'))
    expect(saved.length).toBe(1)
    expect(saved[0].decision).toBe('approved')
    expect(at1c.getApprovalLog().length).toBe(1)
  })

  it('human says no: denied, fn never runs, the denial is still saved', async () => {
    const e = env({ prompt: async () => false })
    const at1c = new AT1C(e.opts)
    let ran = false
    const out = await at1c.enforce(cfg(), () => { ran = true })
    expect(out).toMatchObject({ status: 'denied', reason: 'user_rejected' })
    expect(ran).toBe(false)
    expect(JSON.parse(fs.readFileSync(e.opts.receiptsFile, 'utf-8'))[0].decision).toBe('denied')
  })

  it('deny policy: refused without ever asking the human', async () => {
    const e = env({ policies: JSON.stringify([{ action: 'send_email', decision: 'deny' }]) })
    const at1c = new AT1C(e.opts)
    let ran = false
    const out = await at1c.enforce(cfg(), () => { ran = true })
    expect(out).toEqual({ status: 'denied', reason: 'blocked_policy' })
    expect(e.shown.length).toBe(0)
    expect(ran).toBe(false)
  })

  it('an allow policy does NOT skip the human', async () => {
    const e = env({ policies: JSON.stringify([{ action: 'send_email', decision: 'allow' }]) })
    const at1c = new AT1C(e.opts)
    await at1c.enforce(cfg(), () => 1)
    expect(e.shown.length).toBe(1)
  })

  it('two approvals in a row both work (fresh nonce each time) and leave two nonce files', async () => {
    const e = env()
    const at1c = new AT1C(e.opts)
    expect((await at1c.enforce(cfg(), () => 1)).status).toBe('approved')
    expect((await at1c.enforce(cfg(), () => 1)).status).toBe('approved')
    expect(fs.readdirSync(e.opts.nonceDir).length).toBe(2)
  })

  it('a policies file that exists but is broken is an error, not "no rules"', () => {
    const e = env({ policies: '[{"action": "send_email", "decision": "deny"' })
    expect(() => new AT1C(e.opts)).toThrow()
  })

  it('refuses a key file readable by others', () => {
    const e = env({ keyMode: 0o644 })
    expect(() => new AT1C(e.opts)).toThrow('chmod 600')
  })

  it('refuses when the key file does not match the pinned key', () => {
    const e = env({ trustedSeed: 9 })
    expect(() => new AT1C(e.opts)).toThrow('does not match')
  })

  it('refuses to start with no trusted-keys file', () => {
    const e = env()
    expect(() => new AT1C({ ...e.opts, trustedKeysFile: path.join(e.dir, 'missing.json') })).toThrow()
  })

  it('a corrupt receipts file is never overwritten, and fn does not run', async () => {
    const e = env()
    fs.writeFileSync(e.opts.receiptsFile, '{not json')
    const at1c = new AT1C(e.opts)
    let ran = false
    await expect(at1c.enforce(cfg(), () => { ran = true })).rejects.toThrow()
    expect(ran).toBe(false)
    expect(fs.readFileSync(e.opts.receiptsFile, 'utf-8')).toBe('{not json')
  })

  it('terminal prompt fails closed when stdin is not a terminal', async () => {
    if (process.stdin.isTTY) return
    expect(await terminalPrompt('x')).toBe(false)
  })

  it('authority file names match tools/new-authority-key.mjs', () => {
    expect(sanitiseAuthority('did:web:at1c.com#mora-1')).toBe('did_web_at1c.com_mora-1')
  })
})
