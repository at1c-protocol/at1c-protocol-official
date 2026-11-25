// Repository receipts: the merge gate, end to end with real git and real signatures.
// Keys here are deterministic THROWAWAY seeds. Never use them for anything real.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { execFileSync } from 'child_process'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { LocalKeyApprover } from '../src/approver'
import { Gate, MemoryNonceStore } from '../src/gate'
import { repoPayloadFor } from '../src/repo'
import { mergeWithReceipt, repoApprovalRequest, receiptPathFor, REPO_MERGE_TYPE } from '../src/repoGate'

const AUTH = 'did:web:test.example#approver-1'
const AUD = 'repo-gate.test.example'
const REPO = 'demo'
const AGENT = 'agent:coder'
let tmp = ''
let bare = ''
let work = ''
let n = 0
let moveDuringCheck: (() => void) | null = null

const run = (dir: string, ...args: string[]) =>
  execFileSync('git', ['-C', dir, '-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args], {
    stdio: ['ignore', 'pipe', 'pipe'],
  }).toString().trim()
const write = (p: string, s: string) => {
  fs.mkdirSync(path.dirname(path.join(work, p)), { recursive: true })
  fs.writeFileSync(path.join(work, p), s)
}
const commit = (msg: string) => {
  run(work, 'add', '-A')
  run(work, 'commit', '-q', '-m', msg)
  return run(work, 'rev-parse', 'HEAD')
}
const mainTip = () => run(bare, 'rev-parse', 'refs/heads/main')

function setup(answer = true) {
  const approver = new LocalKeyApprover({ authority: AUTH, seed: new Uint8Array(32).fill(7), prompt: async () => answer })
  const pinned = { [AUTH]: approver.publicRecord('2026-01-01T00:00:00Z', '2099-01-01T00:00:00Z') }
  const gate = new Gate({
    audience: AUD, pinned, allowedAlgs: ['ML-DSA-65'], nonces: new MemoryNonceStore(),
    revoked: () => { if (moveDuringCheck) { moveDuringCheck(); moveDuringCheck = null } return new Set<string>() },
  })
  return { approver, gate, opts: { repoDir: bare, repo: REPO, gate } }
}

/** The agent's work on a fresh branch from main, then (optionally) the human's receipt committed on top. */
async function agentChange(
  approver: LocalKeyApprover,
  edit: () => void,
  o: { branch?: string; approveFor?: string; addReceipt?: boolean; afterApproval?: () => void } = {},
) {
  const b = `agent-${++n}`
  run(work, 'fetch', '-q', 'origin')
  run(work, 'checkout', '-q', '-B', b, 'origin/main')
  edit()
  const workCommit = commit('agent work')
  const base = run(work, 'rev-parse', 'origin/main')
  const payload = repoPayloadFor(work, base, workCommit)
  const bundle = await approver.approve(repoApprovalRequest({
    audience: AUD, repo: REPO, branch: o.approveFor ?? 'main', agent_id: AGENT, agent_public_key: 'AAAA', payload,
  }))
  if (o.afterApproval) o.afterApproval()
  let source = workCommit
  if (o.addReceipt !== false) {
    write(receiptPathFor(bundle.receipt.receipt_id), JSON.stringify(bundle, null, 2) + '\n')
    source = commit('at1c receipt')
  } else if (o.afterApproval) {
    source = commit('more agent work')
  }
  run(work, 'push', '-q', 'origin', `${b}:refs/heads/${b}`)
  return { source: b, sourceId: source, bundle }
}

beforeAll(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'at1c-gate-'))
  bare = path.join(tmp, 'host.git')
  work = path.join(tmp, 'work')
  execFileSync('git', ['init', '-q', '--bare', '-b', 'main', bare])
  execFileSync('git', ['clone', '-q', bare, work], { stdio: 'ignore' })
  run(work, 'checkout', '-q', '-b', 'main')
  write('README.md', 'hello\n')
  write('src/app.txt', 'v1\n')
  commit('start')
  run(work, 'push', '-q', 'origin', 'main')
  run(bare, 'branch', 'dev', 'main')
})
afterAll(() => {
  if (tmp) fs.rmSync(tmp, { recursive: true, force: true })
})

describe('merge gate: no human-signed receipt, no merge', () => {
  it('merges an approved change, fast-forward, and keeps the receipt in the repo', async () => {
    const { approver, opts } = setup()
    const before = mainTip()
    const c = await agentChange(approver, () => write('src/app.txt', 'v2\n'))
    const out = await mergeWithReceipt(opts, { branch: 'main', source: c.source, agent_id: AGENT })
    expect(out).toEqual({ status: 'merged', receipt_id: c.bundle.receipt.receipt_id, from: before, to: c.sourceId })
    expect(mainTip()).toBe(c.sourceId)
    expect(run(bare, 'cat-file', '-e', `main:${receiptPathFor(c.bundle.receipt.receipt_id)}`)).toBe('')
    expect(c.bundle.receipt.action.type).toBe(REPO_MERGE_TYPE)
  })

  it('refuses a change with no receipt, and main does not move', async () => {
    const { approver, opts } = setup()
    const before = mainTip()
    const c = await agentChange(approver, () => write('src/app.txt', 'sneaky\n'), { addReceipt: false })
    const out = await mergeWithReceipt(opts, { branch: 'main', source: c.source, agent_id: AGENT })
    expect(out.status === 'refused' && out.code).toBe('NO_RECEIPT')
    expect(mainTip()).toBe(before)
  })

  it('refuses when files change after the human approved (PAYLOAD_MISMATCH)', async () => {
    const { approver, opts } = setup()
    const before = mainTip()
    const c = await agentChange(approver, () => write('src/app.txt', 'v3\n'), {
      afterApproval: () => write('src/evil.txt', 'added after approval\n'),
    })
    const out = await mergeWithReceipt(opts, { branch: 'main', source: c.source, agent_id: AGENT })
    expect(out.status === 'refused' && out.code).toBe('PAYLOAD_MISMATCH')
    expect(mainTip()).toBe(before)
  })

  it('refuses a denial', async () => {
    const { approver, opts } = setup(false)
    const before = mainTip()
    const c = await agentChange(approver, () => write('src/app.txt', 'denied\n'))
    const out = await mergeWithReceipt(opts, { branch: 'main', source: c.source, agent_id: AGENT })
    expect(out.status === 'refused' && out.code).toBe('DENIED')
    expect(mainTip()).toBe(before)
  })

  it('refuses a receipt made for another branch', async () => {
    const { approver, opts } = setup()
    const before = run(bare, 'rev-parse', 'refs/heads/dev')
    run(bare, 'update-ref', 'refs/heads/dev', mainTip()) // dev at main, so the change is a fast-forward for both
    const c = await agentChange(approver, () => write('src/app.txt', 'for main only\n'), { approveFor: 'main' })
    const out = await mergeWithReceipt(opts, { branch: 'dev', source: c.source, agent_id: AGENT })
    expect(out.status).toBe('refused')
    expect(run(bare, 'rev-parse', 'refs/heads/dev')).not.toBe(c.sourceId)
    run(bare, 'update-ref', 'refs/heads/dev', before)
  })

  it('refuses a different agent presenting the receipt', async () => {
    const { approver, opts } = setup()
    const c = await agentChange(approver, () => write('src/app.txt', 'mine\n'))
    const out = await mergeWithReceipt(opts, { branch: 'main', source: c.source, agent_id: 'agent:other' })
    expect(out.status).toBe('refused')
  })

  it('refuses when main moved on: fast-forward only', async () => {
    const { approver, opts } = setup()
    const c = await agentChange(approver, () => write('src/app.txt', 'late\n'))
    const ok = await agentChange(approver, () => write('README.md', 'someone else first\n'))
    expect((await mergeWithReceipt(opts, { branch: 'main', source: ok.source, agent_id: AGENT })).status).toBe('merged')
    const out = await mergeWithReceipt(opts, { branch: 'main', source: c.source, agent_id: AGENT })
    expect(out.status === 'refused' && out.code).toBe('NOT_FAST_FORWARD')
    expect(mainTip()).toBe(ok.sourceId)
  })

  it('refuses merging the same change twice', async () => {
    const { approver, opts } = setup()
    const c = await agentChange(approver, () => write('src/app.txt', 'once\n'))
    expect((await mergeWithReceipt(opts, { branch: 'main', source: c.source, agent_id: AGENT })).status).toBe('merged')
    const again = await mergeWithReceipt(opts, { branch: 'main', source: c.source, agent_id: AGENT })
    expect(again.status).toBe('refused')
  })

  it('refuses two receipts, an edited old receipt, and a wrongly named receipt file', async () => {
    const { approver, opts } = setup()
    const before = mainTip()
    const two = await agentChange(approver, () => {
      write('src/app.txt', 'two\n')
      write('.at1c/receipts/at1c_00000000000000000000000000.json', '{}\n')
    })
    let out = await mergeWithReceipt(opts, { branch: 'main', source: two.source, agent_id: AGENT })
    expect(out.status === 'refused' && out.code).toBe('MORE_THAN_ONE_RECEIPT')

    const old = run(bare, 'ls-tree', '-r', '--name-only', 'main', '.at1c/receipts/').split('\n')[0]
    const edited = await agentChange(approver, () => {
      write('src/app.txt', 'edit history\n')
      write(old, '{"tampered":true}\n')
    })
    out = await mergeWithReceipt(opts, { branch: 'main', source: edited.source, agent_id: AGENT })
    expect(out.status === 'refused' && out.code).toBe('RECEIPT_CHANGED')

    const b = `agent-${++n}`
    run(work, 'checkout', '-q', '-B', b, 'origin/main')
    write('src/app.txt', 'bad name\n')
    write('.at1c/receipts/receipt.json', '{}\n')
    commit('bad name')
    run(work, 'push', '-q', 'origin', `${b}:refs/heads/${b}`)
    out = await mergeWithReceipt(opts, { branch: 'main', source: b, agent_id: AGENT })
    expect(out.status === 'refused' && out.code).toBe('BAD_RECEIPT_FILE')
    expect(mainTip()).toBe(before)
  })

  it('if main moves during the check, the branch is not moved and the receipt is spent (BRANCH_MOVED)', async () => {
    const { approver, opts } = setup()
    const c = await agentChange(approver, () => write('src/app.txt', 'race\n'))
    const other = run(bare, 'commit-tree', '-p', mainTip(), '-m', 'racer', run(bare, 'rev-parse', 'main^{tree}'))
    moveDuringCheck = () => run(bare, 'update-ref', 'refs/heads/main', other)
    const out = await mergeWithReceipt(opts, { branch: 'main', source: c.source, agent_id: AGENT })
    expect(out.status === 'refused' && out.code).toBe('BRANCH_MOVED')
    expect(mainTip()).toBe(other)
  })

  it('refuses to work on a non-bare copy, and refuses odd branch names', async () => {
    const { gate } = setup()
    let out = await mergeWithReceipt({ repoDir: work, repo: REPO, gate }, { branch: 'main', source: 'HEAD', agent_id: AGENT })
    expect(out.status === 'refused' && out.code).toBe('NOT_BARE')
    out = await mergeWithReceipt({ repoDir: bare, repo: REPO, gate }, { branch: '--force', source: 'main', agent_id: AGENT })
    expect(out.status === 'refused' && out.code).toBe('BAD_BRANCH')
  })
})
