# AT1C Receipt Specification — format version 1

**Status:** Draft, canonical. This file supersedes the receipt schemas in `protocol.md` (Ch. 5, flat camelCase) and `receipts.md` (v0.1). Where any other document disagrees, this file wins.

**One-line focus:** AT1C is a human-signed, single-use, scope-bound approval receipt that a gate verifies before an action runs. Any chain or anchor is optional.

Normative words (MUST, SHOULD) follow RFC 2119. Items marked **[standard]** use an established pattern. Items marked **[AT1C choice]** are judgment calls specific to this protocol. They have not been externally reviewed.

---

## 1. Versioning (read this first)

There are several version numbers in the repo because they version different things. From now on:

| Thing | Where it lives | Current | Meaning |
|---|---|---|---|
| **Receipt format** | `version` field inside every receipt | `"1"` | The wire format in this file. Changes only on a breaking change. |
| **Spec document** | this file | 1.0-draft | Editorial revisions. Do not change the format. |
| **SDK** | `package.json` | 1.0.x | Code release. Must state which receipt format it implements. |
| Legacy: `protocol.md` "v1.4", whitepaper "v1.6", standards "v0.1" | old docs | frozen | Document revision numbers, not protocol versions. Retire them, or relabel them as "document rev". |

Rule: only the `version` field in a receipt is the protocol version. A verifier MUST reject a receipt whose `version` it does not implement.

## 2. Receipt structure

A receipt is a JSON object. Only strings, integers, booleans, arrays and objects are allowed. **Floats are forbidden** (canonicalisation ambiguity). All timestamps are `YYYY-MM-DDTHH:MM:SSZ` (UTC, seconds, literal `Z`).

```json
{
  "version": "1",
  "receipt_id": "at1c_01JA0000000000000000000001",
  "decision": "approved",
  "issued_at": "2026-10-12T11:59:00Z",
  "expires_at": "2026-10-12T12:04:00Z",
  "actor": { "agent_id": "agent:mail-bot", "public_key": "<b64url>" },
  "action": {
    "type": "send_email",
    "class": "irreversible",
    "resource": "mailto:alice@example.com",
    "payload_hash": "sha256:<64 hex>",
    "scope_ref": "scope:mail-v1",
    "description": "Send Q3 report"
  },
  "display_digest": "sha256:<64 hex>",
  "approval": { "authority": "did:web:example.com#user-1", "alg": "ML-DSA-65", "signature": "<b64url>" },
  "nonce": "<32 random bytes, b64url>"
}
```

| Field | Req | Rule |
|---|---|---|
| `version` | yes | `"1"` |
| `receipt_id` | yes | `at1c_` + 26-char ULID. Also the idempotency and revocation key. |
| `decision` | yes | `approved` or `denied`. Denials are first-class signed receipts. |
| `issued_at`, `expires_at` | yes | `expires_at > issued_at`; lifetime ≤ **86400 s** [AT1C choice; tune per deployment]. |
| `actor.agent_id` | yes | Identifier of the acting agent. |
| `actor.public_key` | yes | The agent's key (informational in v1; binding the agent's own signature to the request is future work). |
| `action.type`, `action.resource` | yes | What, and on what. Compared by exact string match. |
| `action.class` | yes | `compensable`, `retriable` or `irreversible`. |
| `action.payload_hash` | yes | `sha256:` + hex of the JCS-canonical payload the agent will actually send. The payload itself is never in the receipt (fingerprint, not payload). |
| `action.scope_ref` | no | Pointer to a scope document (see `scopes.md`). |
| `action.description` | no | Human text. Not trusted for authorisation. |
| `display_digest` | yes | SHA-256 of the exact text/UI the human was shown. Lets an auditor prove what the human saw. [AT1C choice] |
| `approval.authority` | yes | Identifier of the signing principal (resolved through verifier-pinned keys, §4). |
| `approval.alg` | yes | Must be `ML-DSA-65` in format 1. Signed, so it cannot be swapped without breaking the signature. |
| `approval.signature` | yes | b64url ML-DSA-65 signature (§3). |
| `nonce` | yes | 32 random bytes, b64url, no padding. |

Unknown extra fields are **ignored** by verifiers but are covered by the signature if present. Reserved for later: `principalValidUntil`, `dissolutionTrigger`, `inheritorAgentId`, `postDissolutionPolicy`. Use an `x_` prefix for experiments.

## 3. Canonicalisation and signature

- **Canonical form [standard]:** JSON Canonicalization Scheme, RFC 8785, applied to the whole receipt with `approval.signature` removed. `approval.alg` and `approval.authority` stay inside the signed bytes.
- **Algorithm [standard]:** ML-DSA-65, NIST **FIPS 204** (not 203; 203 is ML-KEM). Pure signature, empty context string. Public key 1952 bytes, signature 3309 bytes.
- **Encoding:** base64url, no padding.
- **Payload hash:** `sha256(JCS(payload))`, where the payload is the structured request body the gate will execute.

Inferred, not tested: that `@noble/post-quantum` `sign(msg, sk)` with default (empty) context produces signatures interoperable with other FIPS 204 implementations. The vectors in this repo were produced by Python `cryptography` (OpenSSL). **Run them through the SDK before relying on this.**

## 4. Trust model for the signing key (v1)

The verifier holds a **pinned map** `authority → key record` (`alg`, `public_key`, `valid_from`, `valid_until`, `revoked`), defined in `keys.md`. A receipt from an authority not in the map, or whose key is revoked or outside its window, is rejected. No registry, DID resolution or chain is needed in v1. [AT1C choice]

Gap (unresolved): key rotation, revocation of a compromised user key, and how a verifier first learns a key. `did:web` resolution is a candidate, but it is not specified here and is not in v1.

## 5. Verification order (normative)

The first failing check returns its code and the gate MUST NOT execute.

1. `SCHEMA`: all required fields present and well-formed; `version == "1"`.
2. `ALG_NOT_ALLOWED`: `approval.alg` is in the verifier's allowlist (never taken from the receipt alone).
3. `UNKNOWN_AUTHORITY`: authority has a pinned key.
4. `KEY_NOT_VALID`: key is not revoked, its `alg` matches, and the verifier's own clock is within `valid_from ≤ now < valid_until` (see `keys.md`; never use `issued_at` for this).
5. `BAD_SIGNATURE`: signature verifies over the canonical bytes.
6. `DENIED`: `decision != approved` (a valid denial is logged, never executed).
7. `BAD_TTL`, `NOT_YET_VALID`, `EXPIRED`: `issued_at ≤ now < expires_at` and lifetime ≤ 86400 s.
8. `CONTEXT_MISMATCH`: `actor.agent_id`, `action.type`, `action.resource` and `action.payload_hash` equal what the gate is about to execute. The gate computes the payload hash itself from the real payload.
9. `REVOKED`: `receipt_id` is not revoked.
10. `REPLAY`: atomically check-and-record `nonce`. **This runs last**, so a failed attempt never burns a valid receipt.

Fail closed: if the nonce store or revocation list is unreachable, reject.

## 6. The Five Core Safety Rules mapped to checks

| Rule | Enforced by |
|---|---|
| 1. No Implicit Authority | Steps 3–6: only a pinned human key's `approved` signature grants anything. Agent claims grant nothing. |
| 2. Context Binding | Step 8 plus signed `payload_hash`. |
| 3. Proof Integrity | Steps 1, 2, 5: JCS plus signature over everything but the signature; `alg` is signed and allowlisted. |
| 4. Verification Before Execution | The gate runs §5 before the side effect. Nothing in the receipt can bypass it. |
| 5. Replay Protection | Step 10 (single-use nonce), step 7 (short expiry), step 9 (revocation). |

## 7. Known gaps (stated, not hidden)

- **Cumulative limits / mosaic attack.** A receipt authorises one action. Spend caps or "N actions per day" need verifier-side state in the scope, and aggregation across sessions is not solved.
- **Nonce store is a hard dependency.** It must be atomic and durable. Multi-gateway deployments need a shared store.
- **Post-execution attestation** (proof the action ran as approved) is not in format 1.
- **Agent authentication.** `actor.public_key` is not yet proved by the agent. A stolen valid receipt can be presented by any caller whose payload matches.
- **Platform/device attestation** is deliberately not a dependency. Optional WebAuthn/passkey attestation at registration is a possible v1.5 addition.
- **Anchoring** (any chain, any timestamp service) is an optional adapter that publishes a receipt hash. It is not part of verification.

## 8. Test vectors

`spec/test-vectors/receipt-v1.json` holds 22 vectors (2 accepts, 1 denial, 19 negatives). Each lists the receipt, `now`, the gate's expected action, pre-seen nonces and revoked ids, and the expected result code. The key is a deterministic throwaway; **it must never be used for anything real**. Any implementation is conformant only if it reproduces every `expect`. Reference verifier: `tools/at1c_ref.py`; runner: `tools/run_vectors.py`.
