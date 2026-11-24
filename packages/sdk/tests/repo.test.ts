import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { execFileSync } from 'child_process'
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import { createHash } from 'crypto'
import { makeRepoPayload, repoPayloadFor, RepoPayloadError, REPO_PAYLOAD_KIND } from '../src/repo'
import { attachmentHashOf } from '../src/verify'

const BASE = 'a'.repeat(40)
const enc = (s: string) => new TextEncoder().encode(s)
// sha256 of "hello\n"
const HELLO_LF = '5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03'

const codeOf = (fn: () => unknown): string => {
  try {
    fn()
  } catch (e) {
    if (e instanceof RepoPayloadError) return e.code
    throw e
  }
  return 'NO_ERROR'
}

describe('makeRepoPayload (no git)', () => {
  it('hashes final bytes and sorts files and deletions by path', () => {
    const p = makeRepoPayload(BASE, [
      { path: 'z.txt', mode: '100644', bytes: enc('hello\n') },
      { path: 'a/b.txt', mode: '100755', bytes: enc('hello\n') },
      { path: 'old/y', deleted: true },
      { path: 'old/x', deleted: true },
    ])
    expect(p).toEqual({
      kind: REPO_PAYLOAD_KIND,
      base: BASE,
      files: [
        { path: 'a/b.txt', mode: '100755', sha256: HELLO_LF },
        { path: 'z.txt', mode: '100644', sha256: HELLO_LF },
      ],
      deleted: ['old/x', 'old/y'],
    })
  })
  it('gives the same payload whatever order the changes arrive in', () => {
    const a = { path: 'a', mode: '100644', bytes: enc('1') }
    const b = { path: 'b', mode: '100644', bytes: enc('2') }
    expect(makeRepoPayload(BASE, [a, b])).toEqual(makeRepoPayload(BASE, [b, a]))
  })
  it('leaves the receipts folder out of its own fingerprint', () => {
    const p = makeRepoPayload(BASE, [
      { path: '.at1c/receipts/at1c_X.json', mode: '100644', bytes: enc('{}') },
      { path: 'src/a.ts', mode: '100644', bytes: enc('x') },
    ])
    expect(p.files.map((f) => f.path)).toEqual(['src/a.ts'])
  })
  it('refuses a change that only touches the receipts folder', () => {
    expect(codeOf(() => makeRepoPayload(BASE, [{ path: '.at1c/receipts/r.json', mode: '100644', bytes: enc('{}') }]))).toBe('NO_CHANGES')
  })
  it('refuses an empty change', () => {
    expect(codeOf(() => makeRepoPayload(BASE, []))).toBe('NO_CHANGES')
  })
  it('refuses submodules', () => {
    expect(codeOf(() => makeRepoPayload(BASE, [{ path: 'lib', mode: '160000', bytes: enc('') }]))).toBe('SUBMODULE')
  })
  it('refuses unknown modes', () => {
    expect(codeOf(() => makeRepoPayload(BASE, [{ path: 'a', mode: '100666', bytes: enc('') }]))).toBe('BAD_MODE')
  })
  it('refuses the same path twice', () => {
    expect(codeOf(() => makeRepoPayload(BASE, [{ path: 'a', deleted: true }, { path: 'a', mode: '100644', bytes: enc('') }]))).toBe('DUPLICATE_PATH')
  })
  it('refuses paths git would never write', () => {
    for (const bad of ['', '/etc/passwd', 'a/../b', './a', 'a//b', 'a/', 'a\0b']) {
      expect(codeOf(() => makeRepoPayload(BASE, [{ path: bad, deleted: true }]))).toBe('BAD_PATH')
    }
  })
  it('refuses a base that is not a full commit id', () => {
    for (const bad of ['main', 'abc123', 'A'.repeat(40), 'a'.repeat(41)]) {
      expect(codeOf(() => makeRepoPayload(bad, [{ path: 'a', deleted: true }]))).toBe('BAD_BASE')
    }
  })
  it('accepts a SHA-256 repository commit id', () => {
    expect(makeRepoPayload('b'.repeat(64), [{ path: 'a', deleted: true }]).base).toBe('b'.repeat(64))
  })
  it('is plain data the format 2 attachment hash accepts', () => {
    const payload = makeRepoPayload(BASE, [{ path: 'a', mode: '100644', bytes: enc('x') }])
    expect(attachmentHashOf({ payload, salt: 'A'.repeat(43) })).toMatch(/^sha256:[0-9a-f]{64}$/)
  })
})

describe('repoPayloadFor (real git)', () => {
  let dir = ''
  const g = (...args: string[]) =>
    execFileSync('git', ['-C', dir, '-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', ...args])
      .toString('utf8')
      .trim()
  const write = (p: string, s: string) => {
    fs.mkdirSync(path.dirname(path.join(dir, p)), { recursive: true })
    fs.writeFileSync(path.join(dir, p), s)
  }
  let base = ''
  let result = ''

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'at1c-repo-'))
    execFileSync('git', ['init', '-q', '-b', 'main', dir])
    write('.gitattributes', '*.txt text\n')
    write('keep.txt', 'same\n')
    write('change.txt', 'before\n')
    write('gone.txt', 'bye\n')
    write('run.sh', 'echo hi\n')
    g('add', '-A')
    g('commit', '-q', '-m', 'base')
    base = g('rev-parse', 'HEAD')

    write('change.txt', 'hello\r\n') // CRLF on disk; git stores LF because of the text attribute
    fs.rmSync(path.join(dir, 'gone.txt'))
    write('new/added.txt', 'hello\n')
    fs.chmodSync(path.join(dir, 'run.sh'), 0o755)
    fs.symlinkSync('keep.txt', path.join(dir, 'link'))
    write('.at1c/receipts/at1c_OLD.json', '{}')
    g('add', '-A')
    g('commit', '-q', '-m', 'change')
    result = g('rev-parse', 'HEAD')
  })
  afterAll(() => {
    if (dir) fs.rmSync(dir, { recursive: true, force: true })
  })

  it('builds the finished-files payload from what git stores', () => {
    const p = repoPayloadFor(dir, base, result)
    const sha = (s: string) => createHash('sha256').update(s).digest('hex')
    expect(p).toEqual({
      kind: REPO_PAYLOAD_KIND,
      base,
      files: [
        { path: 'change.txt', mode: '100644', sha256: HELLO_LF }, // LF, as git stores it
        { path: 'link', mode: '120000', sha256: sha('keep.txt') }, // a shortcut is its link text
        { path: 'new/added.txt', mode: '100644', sha256: HELLO_LF },
        { path: 'run.sh', mode: '100755', sha256: sha('echo hi\n') }, // permission change counts
      ],
      deleted: ['gone.txt'],
    })
  })
  it('accepts branch names and resolves them to full commit ids', () => {
    expect(repoPayloadFor(dir, 'main~1', 'main').base).toBe(base)
  })
  it('refuses a ref that git could read as an option', () => {
    expect(codeOf(() => repoPayloadFor(dir, '--output=/tmp/x', result))).toBe('BAD_REF')
  })
  it('refuses a ref that does not exist', () => {
    expect(codeOf(() => repoPayloadFor(dir, 'no-such-branch', result))).toBe('GIT_FAILED')
  })
  it('refuses a merge that changes nothing', () => {
    expect(codeOf(() => repoPayloadFor(dir, result, result))).toBe('NO_CHANGES')
  })
})
