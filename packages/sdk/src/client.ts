// AT1C client (level 1, "dev mode"): a thin wrapper over LocalKeyApprover + Gate.
//
// SECURITY NOTE: the Approver key is read from a file owned by the same OS user that runs the agent.
// This stops mistakes and bugs, not a hijacked agent (see docs/STATUS.md, levels 2 and 3).
// What this class does guarantee: nothing runs without a human-signed, single-use, payload-bound receipt
// that the Gate verified against the operator's pinned public key (Rules 1 to 5).
import * as fs from 'fs'
import * as os from 'os'
import * as path from 'path'
import * as readline from 'readline'
import { LocalKeyApprover, type ActionClass, type Prompt, type ReceiptV1 } from './approver'
import { Gate, FileNonceStore } from './gate'
import type { KeyRecord } from './verify'

export interface AT1COptions {
  /** Authority id of the human approver, e.g. "did:web:example.com#user-1". Must be pinned in trustedKeysFile. */
  authority: string
  /** Secret key file (mode 600). Default: env AT1C_APPROVER_KEY_FILE, else ~/at1c-secrets/<authority>.mldsa65.json */
  keyFile?: string
  /** Pinned public keys (same shape as trusted-keys.example.json). Default: env AT1C_TRUSTED_KEYS, else ./trusted-keys.json */
  trustedKeysFile?: string
  /** Durable single-use nonce store. Default: ./.at1c/nonces */
  nonceDir?: string
  /** Deny list. Missing file = no rules. A file that exists but cannot be parsed is an error. Default: ./policies.json */
  policiesFile?: string
  /** Audit log of every receipt signed, approved or denied. Default: ./receipts.json */
  receiptsFile?: string
  prompt?: Prompt
  now?: () => Date
  ttlSeconds?: number
}

export interface EnforceConfig {
  agentId: string
  action: string // action.type
  resource: string
  payload: unknown // the exact structured payload; `fn` receives it back in canonical form
  class?: ActionClass // default 'irreversible' (the most cautious label)
  scopeRef?: string
  description?: string
  agentPublicKey?: string // informational in format 1
}

export type EnforceResult =
  | { status: 'approved'; result: any; receipt: ReceiptV1 }
  | { status: 'denied'; reason: string; receipt?: ReceiptV1 }

/** Safe file-name form of an authority id, matching tools/new-authority-key.mjs. */
export const sanitiseAuthority = (a: string): string => a.replace(/[^A-Za-z0-9._-]/g, '_')

/** Terminal y/n. Fails closed when stdin is not a terminal, so piped input cannot approve anything. */
export const terminalPrompt: Prompt = (text) => {
  if (!process.stdin.isTTY) return Promise.resolve(false)
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  return new Promise((resolve) => {
    rl.question(`\n${text}\n\nApprove? (y/n): `, (answer) => {
      rl.close()
      resolve(answer.trim().toLowerCase() === 'y')
    })
  })
}

function loadSeed(file: string, authority: string): Uint8Array {
  const st = fs.statSync(file)
  if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {
    throw new Error(`key file ${file} is readable by others; run: chmod 600 "${file}"`)
  }
  const j = JSON.parse(fs.readFileSync(file, 'utf-8'))
  if (j.alg !== 'ML-DSA-65') throw new Error('key file is not ML-DSA-65')
  if (j.authority !== authority) throw new Error(`key file is for a different authority (${String(j.authority)})`)
  if (typeof j.seed_hex !== 'string' || !/^[0-9a-f]{64}$/.test(j.seed_hex)) throw new Error('key file has no valid seed_hex')
  return Uint8Array.from(Buffer.from(j.seed_hex, 'hex'))
}

function loadTrusted(file: string): { allowed_algs: string[]; keys: Record<string, KeyRecord> } {
  const j = JSON.parse(fs.readFileSync(file, 'utf-8')) // missing or invalid file throws: fail closed
  if (!Array.isArray(j.allowed_algs) || typeof j.keys !== 'object' || j.keys === null) {
    throw new Error(`${file} must contain allowed_algs and keys`)
  }
  return { allowed_algs: j.allowed_algs, keys: j.keys }
}

function loadPolicies(file: string): Array<{ action: string; decision: string }> {
  if (!fs.existsSync(file)) return []
  const j = JSON.parse(fs.readFileSync(file, 'utf-8')) // unparseable file throws: never silently drop deny rules
  if (!Array.isArray(j)) throw new Error(`${file} must be a JSON array`)
  return j
}

export class AT1C {
  private readonly approver: LocalKeyApprover
  private readonly gate: Gate
  private readonly policies: Array<{ action: string; decision: string }>
  private readonly receiptsFile: string
  private readonly publicKey: string
  private approvalLog: ReceiptV1[] = []

  constructor(o: AT1COptions) {
    const keyFile =
      o.keyFile ??
      process.env.AT1C_APPROVER_KEY_FILE ??
      path.join(os.homedir(), 'at1c-secrets', `${sanitiseAuthority(o.authority)}.mldsa65.json`)
    const trusted = loadTrusted(o.trustedKeysFile ?? process.env.AT1C_TRUSTED_KEYS ?? 'trusted-keys.json')
    this.policies = loadPolicies(o.policiesFile ?? 'policies.json')
    this.receiptsFile = o.receiptsFile ?? 'receipts.json'

    this.approver = new LocalKeyApprover({
      authority: o.authority,
      seed: loadSeed(keyFile, o.authority),
      prompt: o.prompt ?? terminalPrompt,
      now: o.now,
      ttlSeconds: o.ttlSeconds,
    })
    this.publicKey = this.approver.publicRecord('1970-01-01T00:00:00Z', '9999-12-31T23:59:59Z').public_key
    const pinned = trusted.keys[o.authority]
    if (!pinned || pinned.public_key !== this.publicKey) {
      throw new Error('the key file does not match the key pinned for this authority in trusted-keys')
    }
    this.gate = new Gate({
      pinned: trusted.keys,
      allowedAlgs: trusted.allowed_algs,
      nonces: new FileNonceStore(o.nonceDir ?? path.join('.at1c', 'nonces')),
      now: o.now,
    })
  }

  /** Public key (base64url) of the approver. */
  getPublicKey(): string {
    return this.publicKey
  }

  /** Receipts signed during this process, approved and denied. */
  getApprovalLog(): ReceiptV1[] {
    return this.approvalLog
  }

  /** Ask the human, then run `fn(payload)` only if a receipt for exactly this action verifies. */
  async enforce(config: EnforceConfig, fn: (payload: any) => Promise<any> | any): Promise<EnforceResult> {
    const policy = this.policies.find((p) => p.action === config.action)
    if (policy?.decision === 'deny') return { status: 'denied', reason: 'blocked_policy' }
    // A policy decision of "allow" does not skip the receipt. Authority comes only from a human signature (Rule 1).

    const receipt = await this.approver.approve({
      agent_id: config.agentId,
      agent_public_key: config.agentPublicKey ?? 'unspecified',
      type: config.action,
      class: config.class ?? 'irreversible',
      resource: config.resource,
      payload: config.payload,
      scope_ref: config.scopeRef,
      description: config.description,
    })
    this.approvalLog.push(receipt)
    this.saveReceipt(receipt) // before running anything: if the audit write fails, fn does not run

    const out = await this.gate.run(
      { agent_id: config.agentId, type: config.action, resource: config.resource, payload: config.payload },
      receipt,
      fn,
    )
    if (out.status === 'executed') return { status: 'approved', result: out.result, receipt }
    return { status: 'denied', reason: out.code === 'DENIED' ? 'user_rejected' : out.code, receipt }
  }

  private saveReceipt(receipt: ReceiptV1): void {
    let list: unknown[] = []
    if (fs.existsSync(this.receiptsFile)) {
      const j = JSON.parse(fs.readFileSync(this.receiptsFile, 'utf-8')) // corrupt file throws; never overwrite it
      if (!Array.isArray(j)) throw new Error(`${this.receiptsFile} must be a JSON array`)
      list = j
    }
    list.push(receipt)
    const tmp = `${this.receiptsFile}.tmp-${process.pid}`
    fs.writeFileSync(tmp, JSON.stringify(list, null, 2), { mode: 0o600 })
    fs.renameSync(tmp, this.receiptsFile)
  }
}
