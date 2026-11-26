// What the human sees for a repo merge (threat T7 fix, owner decision 26 Nov 2026: cautious route).
import { describe, it, expect } from 'vitest'
import { renderRepoFiles, showPath, isRepoPayload, MAX_REPO_FILES, MAX_REPO_LIST_CHARS } from '../src/repoDisplay'
import { REPO_PAYLOAD_KIND, type RepoPayload } from '../src/repo'

const BASE = 'b'.repeat(40)
const H = 'c'.repeat(64)
const pay = (files: RepoPayload['files'], deleted: string[] = []): RepoPayload => ({ kind: REPO_PAYLOAD_KIND, base: BASE, files, deleted })
const many = (k: number) => Array.from({ length: k }, (_, i) => ({ path: `f${i}.txt`, mode: '100644' as const, sha256: H }))

describe('renderRepoFiles: a readable file list', () => {
  it('lists every file by name, marks executables and shortcuts, lists removals, shows the base', () => {
    const text = renderRepoFiles(pay(
      [
        { path: 'src/a.ts', mode: '100644', sha256: H },
        { path: 'run.sh', mode: '100755', sha256: H },
        { path: 'link', mode: '120000', sha256: H },
      ],
      ['old/b.ts'],
    ))
    expect(text).toContain(BASE)
    expect(text).toContain('Added or changed: 3 files')
    expect(text).toContain('    "src/a.ts"\n')
    expect(text).toContain('"run.sh"  [executable]')
    expect(text).toContain('"link"  [shortcut]')
    expect(text).toContain('Removed: 1 file\n    "old/b.ts"')
    expect(text).toContain('git diff')
  })

  it('says 1 file, and 0 files, in plain words', () => {
    const text = renderRepoFiles(pay([{ path: 'a', mode: '100644', sha256: H }]))
    expect(text).toContain('Added or changed: 1 file\n')
    expect(text).toContain('Removed: 0 files')
  })

  it(`accepts exactly ${MAX_REPO_FILES} files (added, changed and removed together)`, () => {
    const text = renderRepoFiles(pay(many(MAX_REPO_FILES - 1), ['gone.txt']))
    expect(text).toContain('"f98.txt"')
    expect(text).toContain('"gone.txt"')
  })

  it(`refuses ${MAX_REPO_FILES + 1} files and tells the agent to split the change`, () => {
    expect(() => renderRepoFiles(pay(many(MAX_REPO_FILES), ['gone.txt']))).toThrow(/split it into smaller changes/)
    expect(() => renderRepoFiles(pay(many(MAX_REPO_FILES + 1)))).toThrow(/101 files/)
  })

  it('refuses a list too long to read, even under the file count', () => {
    const long = Array.from({ length: 10 }, (_, i) => ({ path: `${i}/` + 'x'.repeat(2500), mode: '100644' as const, sha256: H }))
    expect(() => renderRepoFiles(pay(long))).toThrow(new RegExp(`more than ${MAX_REPO_LIST_CHARS}`))
  })
})

describe('showPath: nothing in a file name can hide or fake text', () => {
  it('escapes line breaks and terminal codes', () => {
    const s = showPath('a\n\u001b[2Jb')
    expect(s).not.toContain('\n')
    expect(s).not.toContain('\u001b')
  })

  it('escapes direction-changing characters (the "gnp.exe" trick)', () => {
    const s = showPath('photo‮gnp.exe')
    expect(s).not.toContain('‮')
    expect(s).toContain('\\u{202E}')
  })

  it('escapes zero-width characters and odd spaces, keeps plain spaces and ordinary letters', () => {
    const s = showPath('my file​ é.txt')
    expect(s).toContain('\\u{200B}')
    expect(s).toContain('\\u{00A0}')
    expect(s).toContain('my file')
    expect(s).toContain('é.txt')
  })
})

describe('isRepoPayload: only the exact shape', () => {
  it('accepts a real payload', () => {
    expect(isRepoPayload(pay([{ path: 'a', mode: '100644', sha256: H }]))).toBe(true)
  })

  it('refuses extra fields (they would be signed but not shown)', () => {
    expect(isRepoPayload({ ...pay([{ path: 'a', mode: '100644', sha256: H }]), note: 'hidden' })).toBe(false)
    expect(isRepoPayload(pay([{ path: 'a', mode: '100644', sha256: H, extra: 1 } as any]))).toBe(false)
  })

  it('refuses wrong kind, bad base, bad mode, bad hash, empty change, and non-objects', () => {
    const f = { path: 'a', mode: '100644' as const, sha256: H }
    expect(isRepoPayload({ ...pay([f]), kind: 'other' })).toBe(false)
    expect(isRepoPayload({ ...pay([f]), base: 'main' })).toBe(false)
    expect(isRepoPayload(pay([{ ...f, mode: '160000' as any }]))).toBe(false)
    expect(isRepoPayload(pay([{ ...f, sha256: 'xyz' }]))).toBe(false)
    expect(isRepoPayload(pay([]))).toBe(false)
    expect(isRepoPayload(null)).toBe(false)
    expect(isRepoPayload([])).toBe(false)
  })
})
