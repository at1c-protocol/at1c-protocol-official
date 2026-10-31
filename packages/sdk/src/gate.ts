// AT1C Gate. Runs spec/receipt.md section 5 before any side effect (Rule 4, Verification Before Execution).
// The Gate holds only PUBLIC keys. It never sees a secret key.
import * as fs from 'fs'
import * as path from 'path'
import { jcs, payloadHashOf, verifyReceiptV1, type KeyRecord, type NonceStore, type VerifyCode } from './verify'
import type { Approver, ApprovalRequest, ReceiptV1 } from './approver'

/** In-memory nonce store. Tests and single-process dev only: it forgets on restart. */
export class MemoryNonceStore implements NonceStore {
  private seen = new Set<string>()
  checkAndRecord(nonce: string): boolean {
    if (this.seen.has(nonce)) return false
    this.seen.add(nonce)
    return true
  }
}

/** Durable, atomic nonce store: one file per nonce, created with O_EXCL ('wx'), so two racing callers
 *  cannot both succeed. Survives restarts. Single host only (multi-gateway needs a shared store; spec gap).
 *  Throws on anything unexpected, so the Gate fails closed. */
export class FileNonceStore implements NonceStore {
  constructor(private readonly dir: string) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  }
  checkAndRecord(nonce: string): boolean {
    if (!/^[A-Za-z0-9_-]{43}$/.test(nonce)) throw new Error('invalid nonce') // 32 bytes b64url; also blocks path tricks
    try {
      fs.closeSync(fs.openSync(path.join(this.dir, nonce), 'wx', 0o600))
      return true
    } catch (e: any) {
      if (e && e.code === 'EEXIST') return false
      throw e
    }
  }
}

export interface GateOptions {
  pinned: Record<string, KeyRecord>
  allowedAlgs: string[]
  nonces: NonceStore
  /** REQUIRED (since 2.0.0). Returns the revoked receipt ids; called on every check so a fresh list is used.
   *  If you really have no revocations, say so explicitly with `revoked: NO_REVOCATIONS`. */
  revoked: () => Set<string>
  now?: () => Date
}

/** Explicit opt-out: this Gate has no revocation list. Use only when that is a deliberate choice. */
export const NO_REVOCATIONS: () => Set<string> = () => new Set<string>()

/** Revocation list kept in a JSON file: an array of revoked receipt ids, e.g. ["at1c_..."].
 *  Creates the file empty (mode 600) if it does not exist yet, so there is always a visible place to revoke.
 *  Re-read on every check. If the file later goes missing, or is not a JSON array of strings, the read throws
 *  and the Gate refuses (GATE_ERROR): hard-fail, never "treat as nothing revoked". */
export function fileRevocationList(file: string): () => Set<string> {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
  try {
    fs.writeFileSync(file, '[]\n', { flag: 'wx', mode: 0o600 })
  } catch (e: any) {
    if (!e || e.code !== 'EEXIST') throw e
  }
  return () => {
    const list = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (!Array.isArray(list) || !list.every((x) => typeof x === 'string')) {
      throw new Error(`${file}: must be a JSON array of receipt ids`)
    }
    return new Set<string>(list)
  }
}

export interface GateAction {
  agent_id: string
  type: string
  resource: string
  payload: unknown
}

export type GateResult<T> =
  | { status: 'executed'; result: T }
  | { status: 'refused'; code: VerifyCode | 'GATE_ERROR' }

export class Gate {
  constructor(private readonly o: GateOptions) {
    // Fail at start-up, not silently at check time: a Gate without a revocation list would never refuse a revoked receipt.
    if (typeof o?.revoked !== 'function') {
      throw new Error('AT1C Gate: `revoked` is required and must be a function returning a Set of receipt ids. ' +
        'If this Gate deliberately has no revocations, pass `revoked: NO_REVOCATIONS`.')
    }
  }

  /** Verify `receipt` against what is about to run, then run `fn`. Never runs `fn` on any failure.
   *  `fn` receives the payload re-parsed from its canonical form, so what executes is exactly what was hashed.
   *  The nonce is consumed by a successful verification; if `fn` throws, the receipt is still spent (single use). */
  async run<T>(action: GateAction, receipt: unknown, fn: (payload: any) => T | Promise<T>): Promise<GateResult<T>> {
    let canonical: string
    let expectedHash: string
    try {
      canonical = jcs(action.payload)
      expectedHash = payloadHashOf(action.payload)
    } catch {
      return { status: 'refused', code: 'SCHEMA' }
    }
    let verdict
    try {
      const revoked = this.o.revoked()
      if (!(revoked instanceof Set)) throw new Error('revoked() must return a Set') // fail closed below
      verdict = verifyReceiptV1(receipt, {
        now: (this.o.now ?? (() => new Date()))(),
        pinned: this.o.pinned,
        allowedAlgs: this.o.allowedAlgs,
        expected: { agent_id: action.agent_id, type: action.type, resource: action.resource, payload_hash: expectedHash },
        nonces: this.o.nonces,
        revoked,
      })
    } catch {
      return { status: 'refused', code: 'GATE_ERROR' } // fail closed: nonce store or revocation list unavailable
    }
    if (!verdict.ok) return { status: 'refused', code: verdict.code }
    return { status: 'executed', result: await fn(JSON.parse(canonical)) }
  }
}

/** Convenience: ask the Approver, then let the Gate decide. `fn` runs only if the human approved and the
 *  receipt verifies. The agent never touches a key. */
export async function approveAndRun<T>(
  approver: Approver,
  gate: Gate,
  req: ApprovalRequest,
  fn: (payload: any) => T | Promise<T>,
): Promise<GateResult<T> & { receipt: ReceiptV1 }> {
  const receipt = await approver.approve(req)
  const out = await gate.run({ agent_id: req.agent_id, type: req.type, resource: req.resource, payload: req.payload }, receipt, fn)
  return { ...out, receipt }
}
