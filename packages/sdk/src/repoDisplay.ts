// AT1C repository receipts: what the human SEES before approving a merge (closes threat T7's "approving blind" gap
// for repo merges). Owner decision 26 Nov 2026: cautious route. A change too big to read is refused before the
// human is asked; the agent must split it into smaller changes. A human never approves a file list they cannot read.
//
// The Approver calls this, not the agent: the agent cannot shape what is shown. Every path goes through
// JSON.stringify (escapes control characters and line breaks) and then showPath() also escapes invisible and
// direction-changing characters (e.g. U+202E, which can make "gnp.exe" look like "exe.png").
// GAP (still open): lookalike letters from other alphabets (Cyrillic "а" for Latin "a") are not detected.
import { REPO_PAYLOAD_KIND, type RepoPayload } from './repo'

export const REPO_MERGE_TYPE = 'repo.merge'
/** Most files (added, changed and removed together) one approval may cover. Above this: split the change. */
export const MAX_REPO_FILES = 100
/** Most characters the file list may take on screen. Guards against a few very long paths. */
export const MAX_REPO_LIST_CHARS = 20000

const MODES = new Set(['100644', '100755', '120000'])
const RE_COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/
const RE_SHA256 = /^[0-9a-f]{64}$/
const MODE_NOTE: Record<string, string> = { '100644': '', '100755': '  [executable]', '120000': '  [shortcut]' }

const sameKeys = (o: object, keys: string[]): boolean => {
  const k = Object.keys(o).sort()
  const want = [...keys].sort()
  return k.length === want.length && k.every((x, i) => x === want[i])
}
const isObj = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x)

/** True only for a payload of exactly the repo shape, with no extra fields (an extra field would be signed but
 *  not shown, so it is refused). */
export function isRepoPayload(p: unknown): p is RepoPayload {
  if (!isObj(p) || !sameKeys(p, ['kind', 'base', 'files', 'deleted'])) return false
  if (p.kind !== REPO_PAYLOAD_KIND || typeof p.base !== 'string' || !RE_COMMIT.test(p.base)) return false
  if (!Array.isArray(p.files) || !Array.isArray(p.deleted)) return false
  for (const f of p.files) {
    if (!isObj(f) || !sameKeys(f, ['path', 'mode', 'sha256'])) return false
    if (typeof f.path !== 'string' || f.path.length === 0) return false
    if (typeof f.mode !== 'string' || !MODES.has(f.mode)) return false
    if (typeof f.sha256 !== 'string' || !RE_SHA256.test(f.sha256)) return false
  }
  for (const d of p.deleted) if (typeof d !== 'string' || d.length === 0) return false
  return p.files.length + p.deleted.length > 0
}

// Invisible or direction-changing characters, private-use characters, and every space except the plain one.
const RE_HIDDEN = /[\p{Cf}\p{Zl}\p{Zp}\p{Co}]|(?! )\p{Zs}/gu

/** A path as the human sees it: quoted, with control, invisible and direction-changing characters written as
 *  \u{XXXX}, so nothing in a file name can hide, reorder or fake text on screen. */
export function showPath(p: string): string {
  return JSON.stringify(p).replace(RE_HIDDEN, (c) => `\\u{${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}}`)
}

/** The file list shown for a repo merge. Throws (before any prompt) if the change is too big to read. */
export function renderRepoFiles(p: RepoPayload): string {
  const total = p.files.length + p.deleted.length
  if (total > MAX_REPO_FILES) {
    throw new Error(
      `bad request: this change touches ${total} files, more than ${MAX_REPO_FILES} can be shown for approval; ` +
        'ask the agent to split it into smaller changes',
    )
  }
  const n = p.files.length
  const d = p.deleted.length
  const lines = [`repository change on top of commit ${p.base}`]
  lines.push(`  Added or changed: ${n} file${n === 1 ? '' : 's'}`)
  for (const f of p.files) lines.push(`    ${showPath(f.path)}${MODE_NOTE[f.mode]}`)
  lines.push(`  Removed: ${d} file${d === 1 ? '' : 's'}`)
  for (const x of p.deleted) lines.push(`    ${showPath(x)}`)
  lines.push('  (This approves these exact file contents, fixed by fingerprint. Read the changes, e.g. git diff, first.)')
  const text = lines.join('\n')
  if (text.length > MAX_REPO_LIST_CHARS) {
    throw new Error(
      `bad request: the file list is ${text.length} characters, more than ${MAX_REPO_LIST_CHARS} can be shown for approval; ` +
        'ask the agent to split it into smaller changes',
    )
  }
  return text
}
