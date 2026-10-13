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
  revoked?: () => Set<string> // receipt ids; called on every check so a fresh list is used
  now?: () => Date
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
  constructor(private readonly o: GateOptions) {}

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
      verdict = verifyReceiptV1(receipt, {
        now: (this.o.now ?? (() => new Date()))(),
        pinned: this.o.pinned,
        allowedAlgs: this.o.allowedAlgs,
        expected: { agent_id: action.agent_id, type: action.type, resource: action.resource, payload_hash: expectedHash },
        nonces: this.o.nonces,
        revoked: this.o.revoked ? this.o.revoked() : new Set<string>(),
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
