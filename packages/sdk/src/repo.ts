// AT1C repository receipts: the "finished files" payload (draft spec, owner decisions of 13 and 24 Nov 2026).
// The payload a human approves for a merge, built from what git actually stores. The gate builds it again
// from the merge result it is about to make and compares; it never takes a payload from the agent.
// This file only BUILDS the payload. Hashing with the salt is attachmentHashOf() in verify.ts, unchanged.
import { execFileSync } from 'child_process'
import { createHash } from 'crypto'

export const REPO_PAYLOAD_KIND = 'at1c.repo.files.v1'
/** Receipts kept in the repo live here. This folder is left out of its own fingerprint. */
export const RECEIPTS_DIR = '.at1c/receipts/'

export interface RepoFileEntry {
  path: string
  mode: '100644' | '100755' | '120000'
  sha256: string
}

export interface RepoPayload {
  kind: typeof REPO_PAYLOAD_KIND
  /** Commit id of the target branch tip. A label: it says where the change was made, it is not what is approved. */
  base: string
  /** Every added or changed file, with its final bytes' SHA-256, sorted by path (UTF-8 byte order). */
  files: RepoFileEntry[]
  /** Every removed path, sorted the same way. */
  deleted: string[]
}

/** One change as the gate sees it: a file with its final bytes (as git stores them), or a removed path. */
export type RepoChange =
  | { path: string; mode: string; bytes: Uint8Array }
  | { path: string; deleted: true }

export type RepoErrorCode =
  | 'BAD_BASE'
  | 'BAD_PATH'
  | 'DUPLICATE_PATH'
  | 'BAD_MODE'
  | 'SUBMODULE'
  | 'NO_CHANGES'
  | 'BAD_REF'
  | 'GIT_FAILED'

export class RepoPayloadError extends Error {
  constructor(public readonly code: RepoErrorCode, message: string) {
    super(message)
    this.name = 'RepoPayloadError'
  }
}

const MODES = new Set(['100644', '100755', '120000'])
const SUBMODULE_MODE = '160000'
const RE_COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/ // SHA-1 or SHA-256 repositories

const byUtf8 = (a: string, b: string): number => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))
const sha256Hex = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex')

/** A path as git writes it: relative, '/'-separated, no empty, '.' or '..' parts, no NUL. */
function checkPath(p: string): void {
  if (typeof p !== 'string' || p.length === 0 || p.includes('\0') || p.startsWith('/')) {
    throw new RepoPayloadError('BAD_PATH', `not a repository path: ${JSON.stringify(p)}`)
  }
  for (const part of p.split('/')) {
    if (part === '' || part === '.' || part === '..') {
      throw new RepoPayloadError('BAD_PATH', `not a repository path: ${JSON.stringify(p)}`)
    }
  }
}

const isExcluded = (p: string): boolean => p.startsWith(RECEIPTS_DIR)

/**
 * Build the payload from a list of changes. Pure: no git, no disk.
 * Refuses: bad paths, the same path twice, submodules, unknown file modes, and a change that touches nothing
 * (after the receipts folder is left out) — a receipt for nothing is not issued.
 */
export function makeRepoPayload(base: string, changes: RepoChange[]): RepoPayload {
  if (typeof base !== 'string' || !RE_COMMIT.test(base)) {
    throw new RepoPayloadError('BAD_BASE', 'base must be a full commit id (40 or 64 lowercase hex characters)')
  }
  const seen = new Set<string>()
  const files: RepoFileEntry[] = []
  const deleted: string[] = []
  for (const c of changes) {
    checkPath(c.path)
    if (seen.has(c.path)) throw new RepoPayloadError('DUPLICATE_PATH', `path listed twice: ${c.path}`)
    seen.add(c.path)
    if (isExcluded(c.path)) continue
    if ('deleted' in c) {
      deleted.push(c.path)
      continue
    }
    if (c.mode === SUBMODULE_MODE) throw new RepoPayloadError('SUBMODULE', `submodules are refused for now: ${c.path}`)
    if (!MODES.has(c.mode)) throw new RepoPayloadError('BAD_MODE', `unknown file mode ${c.mode} for ${c.path}`)
    if (!(c.bytes instanceof Uint8Array)) throw new RepoPayloadError('BAD_PATH', `no bytes for ${c.path}`)
    files.push({ path: c.path, mode: c.mode as RepoFileEntry['mode'], sha256: sha256Hex(c.bytes) })
  }
  if (files.length === 0 && deleted.length === 0) {
    throw new RepoPayloadError('NO_CHANGES', 'nothing to approve: no file changes outside the receipts folder')
  }
  files.sort((a, b) => byUtf8(a.path, b.path))
  deleted.sort(byUtf8)
  return { kind: REPO_PAYLOAD_KIND, base, files, deleted }
}

function git(repoDir: string, args: string[]): Buffer {
  try {
    // execFileSync with an argument list: no shell, so nothing in a ref or path is ever run as a command.
    return execFileSync('git', ['-C', repoDir, ...args], { maxBuffer: 1 << 30, stdio: ['ignore', 'pipe', 'pipe'] })
  } catch (e: any) {
    const why = e?.stderr ? String(e.stderr).trim() : String(e?.message ?? e)
    throw new RepoPayloadError('GIT_FAILED', `git ${args[0]} failed: ${why}`)
  }
}

/** Resolve a ref to a full commit id. Refuses anything that git could read as an option. */
function resolveCommit(repoDir: string, ref: string): string {
  if (typeof ref !== 'string' || ref.length === 0 || ref.startsWith('-')) {
    throw new RepoPayloadError('BAD_REF', `not a usable ref: ${JSON.stringify(ref)}`)
  }
  return git(repoDir, ['rev-parse', '--verify', '--quiet', `${ref}^{commit}`]).toString('utf8').trim()
}

const utf8 = new TextDecoder('utf-8', { fatal: true })

/**
 * Read the changes between the target branch tip (`base`) and the merge result (`result`) from git,
 * with each file's bytes exactly as git stores them (the blob, after git's own line-ending rules).
 * Renames are reported as a removal plus an addition. Paths that are not valid UTF-8 are refused.
 */
export function readRepoChanges(repoDir: string, base: string, result: string): { base: string; changes: RepoChange[] } {
  const baseId = resolveCommit(repoDir, base)
  const resultId = resolveCommit(repoDir, result)
  // -z: raw paths, NUL-separated, never quoted. --no-renames: plain add/delete. -r: whole tree.
  const raw = git(repoDir, ['diff-tree', '-r', '-z', '--no-renames', '--no-abbrev', '--no-commit-id', baseId, resultId])
  const parts = raw.toString('latin1').split('\0')
  const changes: RepoChange[] = []
  for (let i = 0; i + 1 < parts.length; i += 2) {
    const meta = parts[i]
    if (meta === '') break
    // ":<old mode> <new mode> <old id> <new id> <status>"
    const m = /^:(\d{6}) (\d{6}) ([0-9a-f]+) ([0-9a-f]+) ([A-Z])$/.exec(meta)
    if (!m) throw new RepoPayloadError('GIT_FAILED', `unexpected diff-tree line: ${meta}`)
    const [, oldMode, newMode, , newId, status] = m
    let p: string
    try {
      p = utf8.decode(Buffer.from(parts[i + 1], 'latin1'))
    } catch {
      throw new RepoPayloadError('BAD_PATH', 'a changed path is not valid UTF-8')
    }
    if (status === 'D') {
      if (oldMode === SUBMODULE_MODE) throw new RepoPayloadError('SUBMODULE', `submodules are refused for now: ${p}`)
      changes.push({ path: p, deleted: true })
    } else if (newMode === SUBMODULE_MODE) {
      throw new RepoPayloadError('SUBMODULE', `submodules are refused for now: ${p}`)
    } else {
      const bytes = new Uint8Array(git(repoDir, ['cat-file', 'blob', newId]))
      changes.push({ path: p, mode: newMode, bytes })
    }
  }
  return { base: baseId, changes }
}

/** The whole job in one call: the payload for merging `result` onto `base`. */
export function repoPayloadFor(repoDir: string, base: string, result: string): RepoPayload {
  const { base: baseId, changes } = readRepoChanges(repoDir, base, result)
  return makeRepoPayload(baseId, changes)
}
