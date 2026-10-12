/**
 * AT1C Protocol SDK
 * AI Transparency & Compliance — v1.0
 *
 * No action without consent. No consent without proof.
 *
 * @example
 * ```typescript
 * import { AT1C, buildReceipt, verifyReceipt, generateKeyPair } from '@at1c/sdk'
 *
 * const at1c = new AT1C()
 *
 * const result = await at1c.enforce(
 *   { userId: 'user_123', agentId: 'agent_payments', action: 'send_payment' },
 *   async () => sendPayment()
 * )
 *
 * if (result.status === 'approved') {
 *   console.log('Receipt ID:', result.receipt.receiptId)
 * }
 * ```
 */

// ── Core client ───────────────────────────────────────────────────────────────
export { AT1C } from './src/client'

// ── Crypto primitives ─────────────────────────────────────────────────────────
export {
  generateKeyPair,
  buildReceipt,
  signReceipt,
  verifyReceipt,
  canonicalise,
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

// ── Types — everything a consumer needs to type their integration ─────────────
export type { ApprovalReceipt } from './src/types'

export type {
  KeyPair,
  ReceiptPayload,
  SignedReceipt,
  VerifyResult,
} from './src/crypto'

export type { StoredKeyPair } from './src/keys'

export { verifyReceiptV1 } from './src/verify'
export type {
  VerifyCode,
  KeyRecord,
  ExpectedAction,
  NonceStore,
  VerifyContext,
} from './src/verify'
