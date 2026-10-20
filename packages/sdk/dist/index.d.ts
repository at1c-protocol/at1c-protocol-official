/**
 * AT1C Protocol SDK
 * The Human Authorisation Layer — receipt format 1
 *
 * No action without consent. No consent without proof.
 *
 * @example
 * ```typescript
 * import { AT1C } from '@at1c/sdk'
 *
 * const at1c = new AT1C({ authority: 'did:web:example.com#user-1' })
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
export { AT1C, terminalPrompt, sanitiseAuthority } from './src/client';
export type { AT1COptions, EnforceConfig, EnforceResult } from './src/client';
export { LocalKeyApprover, renderRequest, newReceiptId } from './src/approver';
export type { Approver, ApprovalRequest, ReceiptV1, ActionClass, Prompt } from './src/approver';
export { Gate, FileNonceStore, MemoryNonceStore, approveAndRun } from './src/gate';
export type { GateOptions, GateAction, GateResult } from './src/gate';
export { generateKeyPair, buildReceipt, signReceipt, verifyReceipt, canonicalise, publicKeyToHex, secretKeyToHex, hexToPublicKey, hexToSecretKey, } from './src/crypto';
export { saveKeyPair, loadKeyPair, loadOrCreateKeyPair, getPublicKeyFromFile, } from './src/keys';
export type { ApprovalReceipt } from './src/types';
export type { KeyPair, ReceiptPayload, SignedReceipt, VerifyResult, } from './src/crypto';
export type { StoredKeyPair } from './src/keys';
export { verifyReceiptV1, jcs, payloadHashOf } from './src/verify';
export type { VerifyCode, KeyRecord, ExpectedAction, NonceStore, VerifyContext, } from './src/verify';
export { verifyAgentCertificateV1, agentIdFor } from './src/agentCert';
export type { CertCode, CertContext } from './src/agentCert';
//# sourceMappingURL=index.d.ts.map