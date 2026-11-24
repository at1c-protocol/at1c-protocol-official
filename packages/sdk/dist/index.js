"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.RECEIPTS_DIR = exports.REPO_PAYLOAD_KIND = exports.RepoPayloadError = exports.repoPayloadFor = exports.readRepoChanges = exports.makeRepoPayload = exports.agentIdFor = exports.verifyAgentCertificateV1 = exports.IDENTITY_LOG_CONTEXT = exports.RECEIPT_CONTEXT = exports.attachmentHashOf = exports.jcs = exports.verifyReceiptV2 = exports.getPublicKeyFromFile = exports.loadOrCreateKeyPair = exports.loadKeyPair = exports.saveKeyPair = exports.hexToSecretKey = exports.hexToPublicKey = exports.secretKeyToHex = exports.publicKeyToHex = exports.generateKeyPair = exports.fileRevocationList = exports.NO_REVOCATIONS = exports.approveAndRun = exports.MemoryNonceStore = exports.FileNonceStore = exports.Gate = exports.receiptOnly = exports.newReceiptId = exports.renderRequest = exports.LocalKeyApprover = exports.sanitiseAuthority = exports.terminalPrompt = exports.AT1C = void 0;
// ── Core client ───────────────────────────────────────────────────────────────
var client_1 = require("./src/client");
Object.defineProperty(exports, "AT1C", { enumerable: true, get: function () { return client_1.AT1C; } });
Object.defineProperty(exports, "terminalPrompt", { enumerable: true, get: function () { return client_1.terminalPrompt; } });
Object.defineProperty(exports, "sanitiseAuthority", { enumerable: true, get: function () { return client_1.sanitiseAuthority; } });
// ── Approver and Gate (receipt format 2) ──────────────────────────────────────
var approver_1 = require("./src/approver");
Object.defineProperty(exports, "LocalKeyApprover", { enumerable: true, get: function () { return approver_1.LocalKeyApprover; } });
Object.defineProperty(exports, "renderRequest", { enumerable: true, get: function () { return approver_1.renderRequest; } });
Object.defineProperty(exports, "newReceiptId", { enumerable: true, get: function () { return approver_1.newReceiptId; } });
Object.defineProperty(exports, "receiptOnly", { enumerable: true, get: function () { return approver_1.receiptOnly; } });
var gate_1 = require("./src/gate");
Object.defineProperty(exports, "Gate", { enumerable: true, get: function () { return gate_1.Gate; } });
Object.defineProperty(exports, "FileNonceStore", { enumerable: true, get: function () { return gate_1.FileNonceStore; } });
Object.defineProperty(exports, "MemoryNonceStore", { enumerable: true, get: function () { return gate_1.MemoryNonceStore; } });
Object.defineProperty(exports, "approveAndRun", { enumerable: true, get: function () { return gate_1.approveAndRun; } });
Object.defineProperty(exports, "NO_REVOCATIONS", { enumerable: true, get: function () { return gate_1.NO_REVOCATIONS; } });
Object.defineProperty(exports, "fileRevocationList", { enumerable: true, get: function () { return gate_1.fileRevocationList; } });
// ── Key helpers (the pre-v1 receipt functions were removed in 2.0.0) ─────────
var crypto_1 = require("./src/crypto");
Object.defineProperty(exports, "generateKeyPair", { enumerable: true, get: function () { return crypto_1.generateKeyPair; } });
Object.defineProperty(exports, "publicKeyToHex", { enumerable: true, get: function () { return crypto_1.publicKeyToHex; } });
Object.defineProperty(exports, "secretKeyToHex", { enumerable: true, get: function () { return crypto_1.secretKeyToHex; } });
Object.defineProperty(exports, "hexToPublicKey", { enumerable: true, get: function () { return crypto_1.hexToPublicKey; } });
Object.defineProperty(exports, "hexToSecretKey", { enumerable: true, get: function () { return crypto_1.hexToSecretKey; } });
// ── Key management ────────────────────────────────────────────────────────────
var keys_1 = require("./src/keys");
Object.defineProperty(exports, "saveKeyPair", { enumerable: true, get: function () { return keys_1.saveKeyPair; } });
Object.defineProperty(exports, "loadKeyPair", { enumerable: true, get: function () { return keys_1.loadKeyPair; } });
Object.defineProperty(exports, "loadOrCreateKeyPair", { enumerable: true, get: function () { return keys_1.loadOrCreateKeyPair; } });
Object.defineProperty(exports, "getPublicKeyFromFile", { enumerable: true, get: function () { return keys_1.getPublicKeyFromFile; } });
// ── Verification (format 2; format 1 receipts are refused) ────────────────────
var verify_1 = require("./src/verify");
Object.defineProperty(exports, "verifyReceiptV2", { enumerable: true, get: function () { return verify_1.verifyReceiptV2; } });
Object.defineProperty(exports, "jcs", { enumerable: true, get: function () { return verify_1.jcs; } });
Object.defineProperty(exports, "attachmentHashOf", { enumerable: true, get: function () { return verify_1.attachmentHashOf; } });
Object.defineProperty(exports, "RECEIPT_CONTEXT", { enumerable: true, get: function () { return verify_1.RECEIPT_CONTEXT; } });
Object.defineProperty(exports, "IDENTITY_LOG_CONTEXT", { enumerable: true, get: function () { return verify_1.IDENTITY_LOG_CONTEXT; } });
// ── Agent certificates ────────────────────────────────────────────────────────
var agentCert_1 = require("./src/agentCert");
Object.defineProperty(exports, "verifyAgentCertificateV1", { enumerable: true, get: function () { return agentCert_1.verifyAgentCertificateV1; } });
Object.defineProperty(exports, "agentIdFor", { enumerable: true, get: function () { return agentCert_1.agentIdFor; } });
// ── Repository receipts: the "finished files" payload (draft spec) ────────────
var repo_1 = require("./src/repo");
Object.defineProperty(exports, "makeRepoPayload", { enumerable: true, get: function () { return repo_1.makeRepoPayload; } });
Object.defineProperty(exports, "readRepoChanges", { enumerable: true, get: function () { return repo_1.readRepoChanges; } });
Object.defineProperty(exports, "repoPayloadFor", { enumerable: true, get: function () { return repo_1.repoPayloadFor; } });
Object.defineProperty(exports, "RepoPayloadError", { enumerable: true, get: function () { return repo_1.RepoPayloadError; } });
Object.defineProperty(exports, "REPO_PAYLOAD_KIND", { enumerable: true, get: function () { return repo_1.REPO_PAYLOAD_KIND; } });
Object.defineProperty(exports, "RECEIPTS_DIR", { enumerable: true, get: function () { return repo_1.RECEIPTS_DIR; } });
//# sourceMappingURL=index.js.map