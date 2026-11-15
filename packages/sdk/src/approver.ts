// AT1C Approver (level 1, "dev mode"). Implements the signing side of spec/receipt.md (receipt format 2).
//
// SECURITY NOTE (read this): in level 1 the Approver runs in the SAME OS account as the agent.
// Anything the agent can run can read the key and approve itself. This stops mistakes and bugs,
// not a hijacked agent. Level 2 (separate OS account) and level 3 (separate device) run this same
// interface elsewhere; the Gate does not change. See docs/STATUS.md.
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { createHash, randomBytes } from 'crypto'
import { jcs, attachmentHashOf, RECEIPT_CONTEXT, type Attachment, type KeyRecord } from './verify'

export type ActionClass = 'compensable' | 'retriable' | 'irreversible'

export interface ApprovalRequest {
  audience: string // the name of the one gate this receipt is for; shown to the human and signed
  agent_id: string
  agent_public_key: string // b64url, informational in format 2
  type: string
  class: ActionClass
  resource: string
  payload: unknown // the exact structured payload that will be executed
  scope_ref?: string
  description?: string // written by the agent: shown to the human, but labelled as the agent's claim
}

export interface ReceiptV2 {
  version: '2'
  receipt_id: string
  decision: 'approved' | 'denied'
  issued_at: string
  expires_at: string
  audience: string
  actor: { agent_id: string; public_key: string }
  action: {
    type: string
    class: ActionClass
    resource: string
    payload_hash: string
    scope_ref?: string
    description?: string
  }
  display_digest: string
  approval: { authority: string; alg: 'ML-DSA-65'; signature: string }
  nonce: string
}

/** What an Approver returns and a Gate takes: the signed receipt plus the attachment it fingerprints.
 *  The two travel together ("no travel without salt"): a Gate refuses a receipt without its attachment.
 *  The bundle holds the payload in plain view. To show a receipt to an outsider, or to time-stamp it,
 *  hand over `receiptOnly(bundle)`: the salted fingerprint reveals nothing about the payload. */
export interface Bundle {
  receipt: ReceiptV2
  attachment: Attachment
}

/** The shareable half of a bundle: the signed receipt without the payload or the salt. */
export const receiptOnly = (bundle: Bundle): ReceiptV2 => bundle.receipt

/** Shows `text` to the human and returns their decision. The Approver, not the agent, produces `text`. */
export type Prompt = (text: string) => Promise<boolean>

/** Anything that can turn a request into a signed receipt. Level 1, 2 and 3 all implement this. */
export interface Approver {
  readonly authority: string
  approve(req: ApprovalRequest): Promise<Bundle>
}

const MAX_TTL_SECONDS = 86400
const MAX_DISPLAY_PAYLOAD = 2000
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
const CLASSES: ActionClass[] = ['compensable', 'retriable', 'irreversible']

const fmt = (d: Date): string => d.toISOString().slice(0, 19) + 'Z'

// Plain-name rule. A receipt is signed and may be kept for years, so a secret written into one of its plain-text
// fields can never be taken out again. These checks run BEFORE the human is asked, so they cover denials too.
// They catch the obvious shapes only (a login inside a URL, a query string): a guard, not a guarantee.
const RE_URL_LOGIN = /[a-z][a-z0-9+.-]*:\/\/[^\s/?#]*@/i // scheme://user:password@host
const RE_URL_QUERY = /:\/\/[^\s#]*\?/ // a URL carrying a query string
function assertPlainText(field: string, s: string, isName: boolean): void {
  if (RE_URL_LOGIN.test(s) || RE_URL_QUERY.test(s) || (isName && s.includes('?'))) {
    throw new Error(`bad request: ${field} must not contain a login or a query string (put such details in the payload)`)
  }
}
const sha256 = (s: string): string => 'sha256:' + createHash('sha256').update(s, 'utf8').digest('hex')

/** ULID: 48-bit millisecond time + 80 random bits, Crockford base32, 26 chars. */
export function newReceiptId(now: Date, rand: (n: number) => Uint8Array = randomBytes): string {
  let t = BigInt(now.getTime())
  let time = ''
  for (let i = 0; i < 10; i++) {
    time = CROCKFORD[Number(t % 32n)] + time
    t /= 32n
  }
  let r = 0n
  for (const b of rand(10)) r = (r << 8n) | BigInt(b)
  let rnd = ''
  for (let i = 0; i < 16; i++) {
    rnd = CROCKFORD[Number(r % 32n)] + rnd
    r /= 32n
  }
  return 'at1c_' + time + rnd
}

/** The exact text the human is shown. Agent-supplied strings go through JSON.stringify, which escapes
 *  control characters (e.g. ESC), so an agent cannot inject terminal escape codes or fake extra lines.
 *  Gap: lookalike and bidirectional Unicode are not filtered. */
export function renderRequest(req: ApprovalRequest, payloadHash: string): string {
  const canonical = jcs(req.payload)
  const shown =
    canonical.length <= MAX_DISPLAY_PAYLOAD
      ? canonical
      : `(too large to display, ${canonical.length} chars; hash only) ${payloadHash}`
  const lines = [
    'AT1C approval request',
    `For gate: ${JSON.stringify(req.audience)}`,
    `Agent:    ${JSON.stringify(req.agent_id)}`,
    `Action:   ${JSON.stringify(req.type)} (${req.class})`,
    `Resource: ${JSON.stringify(req.resource)}`,
    `Payload:  ${shown}`,
  ]
  if (req.scope_ref !== undefined) lines.push(`Scope:    ${JSON.stringify(req.scope_ref)}`)
  if (req.description !== undefined) lines.push(`Agent says (unverified): ${JSON.stringify(req.description)}`)
  return lines.join('\n')
}

export interface LocalKeyApproverOptions {
  authority: string
  seed: Uint8Array // 32 bytes; the caller loads it from a 0600 key file
  prompt: Prompt
  now?: () => Date
  ttlSeconds?: number // default 300; maximum 86400
  rand?: (n: number) => Uint8Array // injectable for tests
}

export class LocalKeyApprover implements Approver {
  readonly authority: string
  private readonly secretKey: Uint8Array
  private readonly publicKey: Uint8Array
  private readonly prompt: Prompt
  private readonly now: () => Date
  private readonly ttl: number
  private readonly rand: (n: number) => Uint8Array

  constructor(o: LocalKeyApproverOptions) {
    if (!o.authority) throw new Error('authority required')
    if (o.seed.length !== 32) throw new Error('seed must be 32 bytes')
    const ttl = o.ttlSeconds ?? 300
    if (!Number.isInteger(ttl) || ttl <= 0 || ttl > MAX_TTL_SECONDS) throw new Error('ttlSeconds must be 1..86400')
    const kp = ml_dsa65.keygen(o.seed)
    this.secretKey = kp.secretKey
    this.publicKey = kp.publicKey
    this.authority = o.authority
    this.prompt = o.prompt
    this.now = o.now ?? (() => new Date())
    this.ttl = ttl
    this.rand = o.rand ?? randomBytes
  }

  /** The public record a verifier pins. Safe to share. */
  publicRecord(valid_from: string, valid_until: string): KeyRecord {
    return {
      alg: 'ML-DSA-65',
      public_key: Buffer.from(this.publicKey).toString('base64url'),
      valid_from,
      valid_until,
      revoked: false,
    }
  }

  async approve(req: ApprovalRequest): Promise<Bundle> {
    if (!req || typeof req.agent_id !== 'string' || !req.agent_id) throw new Error('bad request: agent_id')
    if (typeof req.audience !== 'string' || !req.audience) throw new Error('bad request: audience')
    if (typeof req.agent_public_key !== 'string') throw new Error('bad request: agent_public_key')
    if (typeof req.type !== 'string' || !req.type) throw new Error('bad request: type')
    if (typeof req.resource !== 'string') throw new Error('bad request: resource')
    if (!CLASSES.includes(req.class)) throw new Error('bad request: class')
    if (req.scope_ref !== undefined && typeof req.scope_ref !== 'string') throw new Error('bad request: scope_ref')
    if (req.description !== undefined && typeof req.description !== 'string') throw new Error('bad request: description')
    assertPlainText('audience', req.audience, true)
    assertPlainText('resource', req.resource, true)
    if (req.scope_ref !== undefined) assertPlainText('scope_ref', req.scope_ref, true)
    if (req.description !== undefined) assertPlainText('description', req.description, false)

    // The attachment is what the receipt fingerprints. The payload is copied through its canonical form, so the
    // bundle cannot change if the caller later alters its own object. jcs() throws on floats and on anything that
    // is not plain data, before any prompt. Every receipt gets a fresh random salt; no exceptions.
    const attachment: Attachment = {
      payload: JSON.parse(jcs(req.payload)),
      salt: Buffer.from(this.rand(32)).toString('base64url'),
    }
    const payloadHash = attachmentHashOf(attachment)

    const text = renderRequest(req, payloadHash)
    const approved = await this.prompt(text)

    const issued = this.now()
    const action: ReceiptV2['action'] = {
      type: req.type,
      class: req.class,
      resource: req.resource,
      payload_hash: payloadHash,
    }
    if (req.scope_ref !== undefined) action.scope_ref = req.scope_ref
    if (req.description !== undefined) action.description = req.description

    const unsigned = {
      version: '2' as const,
      receipt_id: newReceiptId(issued, this.rand),
      decision: approved ? ('approved' as const) : ('denied' as const),
      issued_at: fmt(issued),
      expires_at: fmt(new Date(issued.getTime() + this.ttl * 1000)),
      audience: req.audience,
      actor: { agent_id: req.agent_id, public_key: req.agent_public_key },
      action,
      display_digest: sha256(text),
      approval: { authority: this.authority, alg: 'ML-DSA-65' as const },
      nonce: Buffer.from(this.rand(32)).toString('base64url'),
    }
    // Signed under the receipt label, never unlabelled: a signature made here cannot pass as any other kind of
    // AT1C record, and no other kind can pass as a receipt.
    const sig = ml_dsa65.sign(new TextEncoder().encode(jcs(unsigned)), this.secretKey, {
      context: new TextEncoder().encode(RECEIPT_CONTEXT),
    })
    const receipt: ReceiptV2 = {
      ...unsigned,
      approval: { ...unsigned.approval, signature: Buffer.from(sig).toString('base64url') },
    }
    return { receipt, attachment }
  }
}
