/**
 * AT1C Protocol SDK
 * The Human Authorisation Layer — receipt format 2
 *
 * No action without consent. No consent without proof.
 *
 * @example
 * ```typescript
 * import { AT1C } from '@at1c/sdk'
 *
 * const at1c = new AT1C({ authority: 'did:web:example.com#user-1', audience: 'gate.example.com' })
 *
 * const result = await at1c.enforce(
 *   {
 *     agentId: 'agent_payments',
 *     action: 'send_payment',
 *     resource: 'acct:123',
 *     payload: { amount: 500, currency: 'GBP' },
 *   },
 *   async (payload) => sendPayment(payload)
 * )
 *
 * if (result.status === 'approved') {
 *   console.log('Receipt ID:', result.receipt.receipt_id)
 * }
 * ```
 *
 * Level 1 (this client) keeps the approver key in the same OS account as the agent: it stops
 * mistakes, not a hijacked agent. See docs/STATUS.md.
 */

// ── Core client ───────────────────────────────────────────────────────────────
export { AT1C, terminalPrompt, sanitiseAuthority } from './src/client'
export type { AT1COptions, EnforceConfig, EnforceResult } from './src/client'

// ── Approver and Gate (receipt format 2) ──────────────────────────────────────
export { LocalKeyApprover, renderRequest, newReceiptId, receiptOnly } from './src/approver'
export type { Approver, ApprovalRequest, ReceiptV2, Bundle, ActionClass, Prompt } from './src/approver'
export { Gate, FileNonceStore, MemoryNonceStore, approveAndRun, NO_REVOCATIONS, fileRevocationList } from './src/gate'
export type { GateOptions, GateAction, GateResult } from './src/gate'

// ── Key helpers (the pre-v1 receipt functions were removed in 2.0.0) ─────────
export {
  generateKeyPair,
  publicKeyToHex,
  secretKeyToHex,
  hexToPublicKey,
  hexToSecretKey,
} from './src/crypto'

// ── Key management ────────────────────────────────────────────────────────────
export {
  saveKeyPair,
  loadKeyPair,
  loadOrCreateKeyPair,
  getPublicKeyFromFile,
} from './src/keys'

export type { KeyPair } from './src/crypto'

export type { StoredKeyPair } from './src/keys'

// ── Verification (format 2; format 1 receipts are refused) ────────────────────
export { verifyReceiptV2, jcs, attachmentHashOf, RECEIPT_CONTEXT, IDENTITY_LOG_CONTEXT } from './src/verify'
export type {
  VerifyCode,
  KeyRecord,
  ExpectedAction,
  Attachment,
  NonceStore,
  VerifyContext,
} from './src/verify'

// ── Agent certificates ────────────────────────────────────────────────────────
export { verifyAgentCertificateV1, agentIdFor } from './src/agentCert'
export type { CertCode, CertContext } from './src/agentCert'

// ── Repository receipts: the "finished files" payload (draft spec) ────────────
export { makeRepoPayload, readRepoChanges, repoPayloadFor, RepoPayloadError, REPO_PAYLOAD_KIND, RECEIPTS_DIR } from './src/repo'
export type { RepoPayload, RepoFileEntry, RepoChange, RepoErrorCode } from './src/repo'
export { mergeWithReceipt, repoApprovalRequest, receiptPathFor, REPO_MERGE_TYPE } from './src/repoGate'
export { renderRepoFiles, showPath, isRepoPayload, MAX_REPO_FILES, MAX_REPO_LIST_CHARS } from './src/repoDisplay'
export type { RepoGateOptions, MergeRequest, RepoGateResult, RepoGateCode } from './src/repoGate'
