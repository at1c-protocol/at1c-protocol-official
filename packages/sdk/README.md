# @at1c/sdk

**The Human Authorisation Layer**

> No action without consent. No consent without proof.

AT1C is a human-signed, single-use, scope-bound approval receipt that a gate verifies before an action runs. Any chain or anchor is optional.

The wire format is defined in [`spec/receipt.md`](../../spec/receipt.md) (receipt format `"1"`). Where this README and the spec disagree, the spec wins.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

---

## Read this first: what level 1 does and does not protect

This SDK currently runs the **Approver** (which holds your signing key) in the **same OS account** as the agent. That is "level 1, dev mode".

- It **does** stop mistakes and bugs: nothing runs without a receipt you signed for exactly that action and payload.
- It **does not** stop a hijacked or malicious agent that can read your key file and sign for itself.
- It only protects actions that are routed through the Gate. An agent with a raw shell or direct network access can bypass it.

Level 2 (Approver in a separate OS account) and level 3 (Approver on a separate device) use the same interface; the Gate does not change. See `docs/STATUS.md`.

---

## Install

```bash
npm install @at1c/sdk
```

## Setup (once)

1. Create an approver key. The secret stays in a mode-600 file and is never printed:
   ```bash
   node tools/new-authority-key.mjs "did:web:example.com#user-1"
   ```
   This prints a public key record.
2. Put that record in `trusted-keys.json` (the Gate pins this; see `trusted-keys.example.json`):
   ```json
   {
     "allowed_algs": ["ML-DSA-65"],
     "keys": {
       "did:web:example.com#user-1": {
         "alg": "ML-DSA-65",
         "public_key": "<b64url>",
         "valid_from": "2026-10-13T00:00:00Z",
         "valid_until": "2027-10-13T00:00:00Z",
         "revoked": false
       }
     }
   }
   ```
3. Back up the secret key file. If it is lost, receipts can no longer be signed; if it leaks, set `"revoked": true`.

---

## Quick start

```typescript
import { AT1C } from '@at1c/sdk'

const at1c = new AT1C({ authority: 'did:web:example.com#user-1' })

const result = await at1c.enforce(
  {
    agentId:  'agent_payments',
    action:   'send_payment',
    resource: 'acct:123',
    payload:  { amount: 500, currency: 'GBP', to: 'john_smith' },
  },
  async (payload) => sendPayment(payload) // runs only if a valid receipt exists
)

if (result.status === 'approved') {
  console.log('Done. Receipt ID:', result.receipt.receipt_id)
} else {
  console.log('Blocked:', result.reason)
}
```

You are shown the real action, resource and payload and asked y/n. The function receives the payload back in canonical form, so what runs is exactly what was approved.

`result.reason` is `blocked_policy`, `user_rejected`, or a verification code such as `EXPIRED`, `CONTEXT_MISMATCH`, `REPLAY` or `GATE_ERROR`.

---

## How it works

```
request  ->  deny-list check  ->  Approver shows the real payload, human signs
         ->  receipt saved    ->  Gate verifies  ->  action runs once
```

| Rule | How it is provided |
|---|---|
| 1. No Implicit Authority | Only a pinned human key's `approved` signature grants anything. A policy of `allow` does not skip the human. |
| 2. Context Binding | The receipt signs the agent id, action type, resource and a hash of the payload; the Gate recomputes the hash itself. |
| 3. Proof Integrity | JCS (RFC 8785) canonical bytes signed with ML-DSA-65 (FIPS 204); the algorithm is inside the signed bytes and allow-listed. |
| 4. Verification Before Execution | The Gate runs the full check before the side effect, and fails closed if the nonce store is unavailable. |
| 5. Replay Protection | Single-use nonce (durable, atomic), short expiry (default 5 minutes, maximum 24 hours), revocation by receipt id. |

### Receipt (format 1)

```json
{
  "version": "1",
  "receipt_id": "at1c_01JA0000000000000000000001",
  "decision": "approved",
  "issued_at": "2026-10-13T10:00:00Z",
  "expires_at": "2026-10-13T10:05:00Z",
  "actor": { "agent_id": "agent_payments", "public_key": "unspecified" },
  "action": {
    "type": "send_payment", "class": "irreversible", "resource": "acct:123",
    "payload_hash": "sha256:<64 hex>"
  },
  "display_digest": "sha256:<64 hex>",
  "approval": { "authority": "did:web:example.com#user-1", "alg": "ML-DSA-65", "signature": "<b64url>" },
  "nonce": "<32 random bytes, b64url>"
}
```

`display_digest` is the hash of the exact text you were shown, so an auditor can prove what you saw. Denials are signed receipts too and are saved to `receipts.json`.

---

## Verifying elsewhere

Any system can verify a receipt, using **its own** pinned keys (never a key taken from the receipt):

```typescript
import { verifyReceiptV1, payloadHashOf, FileNonceStore } from '@at1c/sdk'

const verdict = verifyReceiptV1(receipt, {
  now: new Date(),
  pinned: trustedKeys.keys,
  allowedAlgs: ['ML-DSA-65'],
  expected: { agent_id, type, resource, payload_hash: payloadHashOf(payload) },
  nonces: new FileNonceStore('.at1c/nonces'),
  revoked: new Set(),
})
// verdict.ok, verdict.code
```

Codes: `OK`, `SCHEMA`, `ALG_NOT_ALLOWED`, `UNKNOWN_AUTHORITY`, `KEY_NOT_VALID`, `BAD_SIGNATURE`, `DENIED`, `BAD_TTL`, `NOT_YET_VALID`, `EXPIRED`, `CONTEXT_MISMATCH`, `REVOKED`, `REPLAY`.

Conformance vectors: `spec/test-vectors/receipt-v1.json`.

> **Deprecated and insecure:** the old `verifyReceipt()` and `buildReceipt()` use the pre-v1 format and trust the public key inside the receipt. Do not use them for anything real.

---

## Policies

`policies.json` (optional) is a deny list:

```json
[
  { "action": "delete_database", "decision": "deny" }
]
```

- A `deny` action is refused without asking you.
- Any other decision still requires your signature. There is no way to skip the human.
- A `policies.json` that exists but cannot be parsed is an error, so deny rules are never silently dropped.

---

## Using the Approver and Gate directly

```typescript
import { LocalKeyApprover, Gate, FileNonceStore, approveAndRun } from '@at1c/sdk'
```

`LocalKeyApprover` signs receipts; `Gate` verifies and runs. The `Approver` interface (`approve(request) -> receipt`) is what level 2 and level 3 implement elsewhere.

---

## Known limits (from the spec, not hidden)

- Level 1 key lives with the agent (above).
- No cumulative limits: a receipt authorises one action; spend caps and "N per day" are not solved.
- The nonce store is a hard dependency; multiple gateways need a shared store.
- The agent does not yet prove its own identity; a stolen valid receipt can be presented by any caller whose payload matches.
- Key rotation, recovery and multiple keys per person are not specified.
- Terminal display does not filter lookalike or bidirectional Unicode.

Full list: `spec/receipt.md` section 7 and `spec/keys.md`.

---

## EU AI Act

AT1C produces signed, tamper-evident records of human approval, which may be useful as evidence in oversight and record-keeping processes. It is not legal advice and makes no claim of compliance with any regulation; check your obligations with a qualified adviser.

---

## API reference

| | |
|---|---|
| `new AT1C(options)` | `authority` (required); optional `keyFile`, `trustedKeysFile`, `nonceDir`, `policiesFile`, `receiptsFile`, `prompt`, `ttlSeconds`. Throws if the key file is group/world readable or does not match the pinned key. |
| `at1c.enforce(config, fn)` | `config`: `agentId`, `action`, `resource`, `payload` (required); `class`, `scopeRef`, `description` (optional). Returns `{ status, receipt, result? }` or `{ status: 'denied', reason, receipt? }`. |
| `at1c.getPublicKey()` | Approver public key, base64url. |
| `at1c.getApprovalLog()` | Receipts signed in this process. |
| `verifyReceiptV1(receipt, ctx)` | Format 1 verifier. |
| `payloadHashOf(payload)`, `jcs(value)` | Hash and canonicalisation helpers. |
| `verifyAgentCertificateV1(cert, ctx)` | Agent certificate verifier (`spec/agent-certificate.md`). |

---

## Examples

```bash
AT1C_AUTHORITY="did:web:example.com#user-1" npx tsx examples/ai-agent-demo/index.ts
node_modules/.bin/tsx examples/receipts-viewer.ts   # lists receipts.json (does not verify signatures)
```

---

## Licence

MIT
