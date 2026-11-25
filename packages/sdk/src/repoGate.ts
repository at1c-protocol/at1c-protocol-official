// AT1C repository receipts: the merge gate. "No human-signed receipt, no merge."
// Owner decisions (24-25 Nov 2026): the receipt travels inside the change, as exactly one new file in
// .at1c/receipts/; fast-forward only, so what lands is byte for byte what the human approved.
//
// Order (spec/gate.md section 4): read the change from git, rebuild the finished-files payload ourselves,
// compare it with what was signed, let the existing Gate verify the receipt (nonce spent last), then move the
// branch with an atomic compare-and-swap. The agent's word is never used for what lands.
//
// HONEST LIMIT: this is only an ENFORCING gate if the agent cannot push to the branch any other way
// (spec/gate.md sections 3 and 7). Run it on the host's own (bare) copy, as a user the agent is not.
import { execFileSync } from 'child_process'
import { jcs, type VerifyCode } from './verify'
import type { Gate } from './gate'
import type { ApprovalRequest } from './approver'
import { makeRepoPayload, readRepoChanges, RepoPayloadError, RECEIPTS_DIR, type RepoErrorCode, type RepoPayload } from './repo'

export const REPO_MERGE_TYPE = 'repo.merge'
const MAX_BUNDLE_BYTES = 4 * 1024 * 1024
const RE_RECEIPT_FILE = /^at1c_[0-9A-HJKMNP-TV-Z]{26}\.json$/

export type RepoGateCode =
  | VerifyCode
  | RepoErrorCode
  | 'GATE_ERROR'
  | 'NO_ATTACHMENT'
  | 'NOT_BARE'
  | 'BAD_BRANCH'
  | 'NOT_FAST_FORWARD'
  | 'NO_RECEIPT'
  | 'MORE_THAN_ONE_RECEIPT'
  | 'RECEIPT_CHANGED'
  | 'BAD_RECEIPT_FILE'
  | 'PAYLOAD_MISMATCH'
  | 'BRANCH_MOVED'

export type RepoGateResult =
  | { status: 'merged'; receipt_id: string; from: string; to: string }
  | { status: 'refused'; code: RepoGateCode; detail?: string }

export interface RepoGateOptions {
  /** Path to the gate's own BARE copy of the repository (the one the host serves). */
  repoDir: string
  /** Plain repository name, from the gate's settings, e.g. "at1c-protocol-official". Never from the caller. */
  repo: string
  /** The existing format 2 Gate: its audience, pinned keys, nonce store and revocation list. */
  gate: Gate
}

export interface MergeRequest {
  /** Target branch name, e.g. "main". */
  branch: string
  /** The commit to fast-forward the branch to: the agent's work plus the one new receipt file on top. */
  source: string
  /** The agent that asks. Must match the receipt's actor.agent_id. */
  agent_id: string
}

const refuse = (code: RepoGateCode, detail?: string): RepoGateResult => ({ status: 'refused', code, detail })

function git(repoDir: string, args: string[]): Buffer {
  return execFileSync('git', ['-C', repoDir, ...args], { maxBuffer: 1 << 30, stdio: ['ignore', 'pipe', 'pipe'] })
}
/** Runs git and reports only whether it succeeded (exit 0). */
function gitOk(repoDir: string, args: string[]): boolean {
  try {
    git(repoDir, args)
    return true
  } catch {
    return false
  }
}

const utf8 = new TextDecoder('utf-8', { fatal: true })

/**
 * Merge `source` into `branch` only if exactly one new receipt in .at1c/receipts/ approves exactly the finished
 * files that would land. Never moves the branch on any failure. A receipt that verifies is spent even if the final
 * branch move then fails (spec/gate.md section 4.4): the agent must rebuild and ask the human again.
 */
export async function mergeWithReceipt(o: RepoGateOptions, req: MergeRequest): Promise<RepoGateResult> {
  try {
    // 0. Settings and request shape.
    if (typeof o.repo !== 'string' || o.repo.length === 0) throw new Error('RepoGate: `repo` is required')
    if (!gitOk(o.repoDir, ['rev-parse', '--is-bare-repository']) ||
        git(o.repoDir, ['rev-parse', '--is-bare-repository']).toString().trim() !== 'true') {
      return refuse('NOT_BARE', 'the gate works on its own bare copy, so no working files can drift from the branch')
    }
    if (typeof req.branch !== 'string' || req.branch.startsWith('-') ||
        !gitOk(o.repoDir, ['check-ref-format', '--branch', req.branch])) {
      return refuse('BAD_BRANCH')
    }
    const ref = `refs/heads/${req.branch}`

    // 1. Where the branch is now, and what would land. readRepoChanges refuses odd refs, paths and submodules.
    let base: string
    let source: string
    let changes
    try {
      const read = readRepoChanges(o.repoDir, ref, req.source)
      base = read.base
      changes = read.changes
      source = git(o.repoDir, ['rev-parse', '--verify', '--quiet', `${req.source}^{commit}`]).toString().trim()
    } catch (e) {
      if (e instanceof RepoPayloadError) return refuse(e.code, e.message)
      throw e
    }

    // 2. Fast-forward only: the branch tip must be an ancestor of the source.
    if (!gitOk(o.repoDir, ['merge-base', '--is-ancestor', base, source])) return refuse('NOT_FAST_FORWARD')

    // 3. The receipts folder: exactly one NEW file, nothing old touched.
    const inFolder = changes.filter((c) => c.path.startsWith(RECEIPTS_DIR))
    if (inFolder.some((c) => 'deleted' in c)) return refuse('RECEIPT_CHANGED', 'an existing receipt was removed')
    for (const c of inFolder) {
      if (gitOk(o.repoDir, ['cat-file', '-e', `${base}:${c.path}`])) return refuse('RECEIPT_CHANGED', `existing receipt edited: ${c.path}`)
    }
    if (inFolder.length === 0) return refuse('NO_RECEIPT')
    if (inFolder.length > 1) return refuse('MORE_THAN_ONE_RECEIPT')
    const file = inFolder[0]
    if ('deleted' in file) return refuse('RECEIPT_CHANGED')
    const name = file.path.slice(RECEIPTS_DIR.length)
    if (!RE_RECEIPT_FILE.test(name) || file.mode !== '100644') return refuse('BAD_RECEIPT_FILE', 'expected .at1c/receipts/<receipt_id>.json')
    if (file.bytes.length > MAX_BUNDLE_BYTES) return refuse('BAD_RECEIPT_FILE', 'receipt file too large')
    let bundle: any
    try {
      bundle = JSON.parse(utf8.decode(file.bytes))
    } catch {
      return refuse('BAD_RECEIPT_FILE', 'receipt file is not valid JSON')
    }
    if (bundle?.receipt?.receipt_id + '.json' !== name) return refuse('BAD_RECEIPT_FILE', 'file name must be the receipt id')

    // 4. Rebuild the payload from git (receipts folder left out) and compare with what was signed.
    let ours: string
    try {
      ours = jcs(makeRepoPayload(base, changes))
    } catch (e) {
      if (e instanceof RepoPayloadError) return refuse(e.code, e.message)
      throw e
    }
    if (bundle?.attachment == null) return refuse('NO_ATTACHMENT')
    let theirs: string
    try {
      theirs = jcs(bundle.attachment.payload)
    } catch {
      return refuse('SCHEMA')
    }
    if (ours !== theirs) return refuse('PAYLOAD_MISMATCH', 'the files that would land are not the files that were approved')

    // 5. The existing Gate verifies the receipt (signature, audience, agent, type, resource, fingerprint, expiry,
    //    revocation, single use). Only then is the branch moved, atomically: update-ref with the old value fails
    //    if anyone moved the branch in between.
    let moved = true
    const out = await o.gate.run(
      { agent_id: req.agent_id, type: REPO_MERGE_TYPE, resource: `${o.repo}:${req.branch}` },
      bundle,
      () => {
        moved = gitOk(o.repoDir, ['update-ref', '-m', `at1c: ${bundle.receipt.receipt_id}`, ref, source, base])
      },
    )
    if (out.status === 'refused') return refuse(out.code)
    if (!moved) return refuse('BRANCH_MOVED', 'the branch moved after approval; the receipt is spent, ask again')
    return { status: 'merged', receipt_id: bundle.receipt.receipt_id, from: base, to: source }
  } catch (e: any) {
    return refuse('GATE_ERROR', String(e?.message ?? e)) // fail closed
  }
}

/** The approval request for a merge, ready for any Approver. `payload` comes from repoPayloadFor(base, agent's work).
 *  The description is a plain count, labelled to the human as the agent's claim; the payload itself is what is signed. */
export function repoApprovalRequest(o: {
  audience: string
  repo: string
  branch: string
  agent_id: string
  agent_public_key: string
  payload: RepoPayload
}): ApprovalRequest {
  const n = o.payload.files.length
  const d = o.payload.deleted.length
  return {
    audience: o.audience,
    agent_id: o.agent_id,
    agent_public_key: o.agent_public_key,
    type: REPO_MERGE_TYPE,
    class: 'compensable', // a merge can be reverted; a verifier may demand more, never less
    resource: `${o.repo}:${o.branch}`,
    payload: o.payload,
    description: `${n} file${n === 1 ? '' : 's'} added or changed, ${d} removed`,
  }
}

/** Where the bundle goes in the change: .at1c/receipts/<receipt_id>.json */
export const receiptPathFor = (receipt_id: string): string => `${RECEIPTS_DIR}${receipt_id}.json`
