# AT1C Receipt Specification — format version 2

**Status:** Draft, canonical. This file supersedes the receipt schemas in `protocol.md` (Ch. 5, flat camelCase) and `receipts.md` (v0.1). Where any other document disagrees, this file wins.

**One-line focus:** AT1C is a human-signed, single-use, scope-bound approval receipt that a gate verifies before an action runs. Any chain or anchor is optional.

Normative words (MUST, SHOULD) follow RFC 2119. Items marked **[standard]** use an established pattern. Items marked **[AT1C choice]** are judgment calls specific to this protocol. They have not been externally reviewed.

**What changed from format 1** (a clean cut: a format 2 verifier refuses every format 1 receipt):

1. **Signing label.** The signature is made under the FIPS 204 context string `AT1C/receipt/v2`. Format 1 used the empty context.
2. **Salted fingerprint.** `action.payload_hash` covers an *attachment* `{ payload, salt }`, not the bare payload.
3. **Bundle.** A receipt travels with its attachment. A gate refuses a receipt that arrives without one.
4. **Audience.** Every receipt names the one gate it is for.

---

## 1. Versioning (read this first)

There are several version numbers in the repo because they version different things:

| Thing | Where it lives | Current | Meaning |
|---|---|---|---|
| **Receipt format** | `version` field inside every receipt | `"2"` | The wire format in this file. Changes only on a breaking change. |
| **Signing label** | FIPS 204 context string | `AT1C/receipt/v2` | Names the kind of signed thing and its format. Changes with the receipt format. |
| **Spec document** | this file | 2.0-draft | Editorial revisions. Do not change the format. |
| **SDK** | `package.json` | 3.0.x | Code release. Must state which receipt format it implements. |
| Legacy: `protocol.md` "v1.4", whitepaper "v1.6", standards "v0.1" | old docs | frozen | Document revision numbers, not protocol versions. Retire them, or relabel them as "document rev". |

Rule: only the `version` field in a receipt is the protocol version. A verifier MUST reject a receipt whose `version` it does not implement. A format 2 verifier MUST NOT accept format 1 receipts: doing so would keep the unlabelled, unsalted format usable as a downgrade. [standard]

## 2. Receipt structure

A receipt is a JSON object. Only strings, integers, booleans, null, arrays and objects are allowed. **Floats are forbidden** (canonicalisation ambiguity). All timestamps are `YYYY-MM-DDTHH:MM:SSZ` (UTC, seconds, literal `Z`).

```json
{
  "version": "2",
  "receipt_id": "at1c_01JA0000000000000000000001",
  "decision": "approved",
  "issued_at": "2026-10-12T11:59:00Z",
  "expires_at": "2026-10-12T12:04:00Z",
  "audience": "gate.example.com",
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
| `version` | yes | `"2"` |
| `receipt_id` | yes | `at1c_` + 26-char ULID. Also the idempotency and revocation key. |
| `decision` | yes | `approved` or `denied`. Denials are first-class signed receipts. |
| `issued_at`, `expires_at` | yes | `expires_at > issued_at`; lifetime ≤ **86400 s** [AT1C choice; tune per deployment]. |
| `audience` | yes | Non-empty text: the name of the one gate this receipt is for (§2.2). Shown to the human and signed. |
| `actor.agent_id` | yes | Identifier of the acting agent. |
| `actor.public_key` | yes | The agent's key (informational in format 2; binding the agent's own signature to the request is future work). |
| `action.type`, `action.resource` | yes | What, and on what. Compared by exact string match. |
| `action.class` | yes | `compensable`, `retriable` or `irreversible`. Comes from the request, so a verifier MAY use it to demand more and MUST NOT use it to demand less. [AT1C choice] |
| `action.payload_hash` | yes | `sha256:` + hex of the JCS-canonical **attachment** (§2.1). The payload itself is never in the receipt (fingerprint, not payload). |
| `action.scope_ref` | no | Pointer to a scope document (see `scopes.md`). |
| `action.description` | no | Human text. Not trusted for authorisation. |
| `display_digest` | yes | SHA-256 of the exact text/UI the human was shown. Lets an auditor prove what the human saw. [AT1C choice] |
| `approval.authority` | yes | Identifier of the signing principal (resolved through verifier-pinned keys, §4). |
| `approval.alg` | yes | Must be `ML-DSA-65` in format 2. Signed, so it cannot be swapped without breaking the signature. |
| `approval.signature` | yes | b64url ML-DSA-65 signature (§3). |
| `nonce` | yes | 32 random bytes, b64url, no padding. |

Unknown extra fields are **ignored** by verifiers but are covered by the signature if present. Reserved for later: `principalValidUntil`, `dissolutionTrigger`, `inheritorAgentId`, `postDissolutionPolicy`. Use an `x_` prefix for experiments.

### 2.1 Attachment and bundle

The **attachment** is a JSON object with exactly two fields:

```json
{ "payload": { "to": "alice@example.com", "subject": "Q3 report" }, "salt": "<32 random bytes, b64url, 43 chars>" }
```

- `payload` is the structured request body the gate will execute. It MUST be present.
- `salt` is 32 fresh random bytes per receipt, base64url without padding. Every receipt has one; there is no unsalted form. [AT1C choice]
- `action.payload_hash = "sha256:" + hex(SHA-256(JCS(attachment)))`. The fingerprint covers the whole attachment, so it cannot be checked, or the payload guessed, without the salt. [standard: a commitment needs a secret value outside the published fingerprint]

A **bundle** is `{ "receipt": <receipt>, "attachment": <attachment> }`. An approver returns a bundle and a gate takes a bundle. A gate MUST refuse a receipt that arrives without its attachment. The attachment is outside the signed receipt, so the receipt alone can be shown to an outsider or time-stamped without revealing the payload. The bundle holds the payload in plain view and SHOULD be stored as one unit, with access limited accordingly.

Losing a salt never loses funds or identity: the salt is not a key. If it is lost before the action runs, the gate refuses and the human approves again. If it is lost afterwards, the receipt still proves the approval of agent, action type and resource at that time, but the exact payload can no longer be matched.

### 2.2 Audience

`audience` is plain text that each verifier chooses for itself and pins in its own settings (for example its web address). No registry is involved. A gate MUST take its own name from its own configuration, never from the caller, and MUST refuse any receipt whose `audience` is not exactly that text. There is no wildcard. [standard: the audience claim of web tokens]

Limit: nothing stops two verifiers choosing the same name. Using an address the operator controls is a convention, not a proof.

### 2.3 Plain-name rule (no secrets in signed text)

A receipt is signed and may be kept for years, so a secret written into a plain-text field can never be removed. Before asking the human, an approver MUST refuse a request whose `audience`, `resource` or `scope_ref` contains a login (`scheme://user:password@host`) or a query string, and a `description` that contains a URL with either. Such details belong in the payload. This catches obvious shapes only: a guard, not a guarantee. [AT1C choice]

## 3. Canonicalisation and signature

- **Canonical form [standard]:** JSON Canonicalization Scheme, RFC 8785, applied to the whole receipt with `approval.signature` removed. `approval.alg` and `approval.authority` stay inside the signed bytes. Only plain data is accepted: a value that is not a plain object, array, string, safe integer, boolean or null MUST be refused, never serialised as `{}`. A reader of receipt text SHOULD reject duplicate object keys.
- **Algorithm [standard]:** ML-DSA-65, NIST **FIPS 204** (not 203; 203 is ML-KEM). Pure signature. Public key 1952 bytes, signature 3309 bytes.
- **Signing label [standard]:** the FIPS 204 context string is the UTF-8 text `AT1C/receipt/v2`. A signature made under one context fails under any other, so a receipt can never pass as another kind of AT1C record and no other kind can pass as a receipt. Reserved: `AT1C/identity-log/v1`. An approver key MUST NOT sign anything with the empty context.
- **Encoding:** base64url, no padding.
- **Payload hash:** `sha256(JCS(attachment))`, see §2.1.

Interoperability: the vectors in this repo are produced by Python `cryptography` (OpenSSL) and verified by the SDK's `@noble/post-quantum`, labels included (`tests/vectors.test.ts`).

## 4. Trust model for the signing key

The verifier holds a **pinned map** `authority → key record` (`alg`, `public_key`, `valid_from`, `valid_until`, `revoked`), defined in `keys.md`. A receipt from an authority not in the map, or whose key is revoked or outside its window, is rejected. The lookup MUST use the map's own entries only. No registry, DID resolution or chain is needed. [AT1C choice]

Gap (unresolved): key rotation, revocation of a compromised user key, and how a verifier first learns a key. `did:web` resolution is a candidate, but it is not specified here.

## 5. Verification order (normative)

A gate first checks the bundle: a missing attachment returns `NO_ATTACHMENT`; a malformed one returns `SCHEMA`. It computes the fingerprint itself from the attachment it was handed. Then, in order, the first failing check returns its code and the gate MUST NOT execute.

1. `SCHEMA`: all required fields present and well-formed; `version == "2"`.
2. `ALG_NOT_ALLOWED`: `approval.alg` is in the verifier's allowlist (never taken from the receipt alone).
3. `UNKNOWN_AUTHORITY`: authority has a pinned key.
4. `KEY_NOT_VALID`: key is not revoked, its `alg` matches, and the verifier's own clock is within `valid_from ≤ now < valid_until` (see `keys.md`; never use `issued_at` for this).
5. `BAD_SIGNATURE`: signature verifies over the canonical bytes under the context `AT1C/receipt/v2`.
6. `DENIED`: `decision != approved` (a valid denial is logged, never executed).
7. `BAD_TTL`, `NOT_YET_VALID`, `EXPIRED`: `issued_at ≤ now < expires_at` and lifetime ≤ 86400 s.
8. `AUDIENCE_MISMATCH`: `audience` equals the verifier's own name.
9. `CONTEXT_MISMATCH`: `actor.agent_id`, `action.type`, `action.resource` and `action.payload_hash` equal what the gate is about to execute. The payload executed is the one in the attachment, re-parsed from its canonical form.
10. `REVOKED`: `receipt_id` is not revoked.
11. `REPLAY`: atomically check-and-record `nonce`. **This runs last**, so a failed attempt never burns a valid receipt.

Fail closed: if the nonce store or revocation list is unreachable, reject.

## 6. The Five Core Safety Rules mapped to checks

| Rule | Enforced by |
|---|---|
| 1. No Implicit Authority | Steps 3–6: only a pinned human key's `approved` signature grants anything. Agent claims grant nothing. |
| 2. Context Binding | Steps 8 and 9 plus the signed `audience` and `payload_hash`. |
| 3. Proof Integrity | Steps 1, 2, 5: JCS plus a labelled signature over everything but the signature; `alg` is signed and allowlisted. |
| 4. Verification Before Execution | The gate runs §5 before the side effect. Nothing in the receipt can bypass it. The time-proof part of Rule 4 (`docs/protocol.md`) is planned and is not in format 2. |
| 5. Replay Protection | Step 11 (single-use nonce), step 7 (short expiry), step 10 (revocation), step 8 (one gate only). |

## 7. Known gaps (stated, not hidden)

- **Cumulative limits / mosaic attack.** A receipt authorises one action. Spend caps or "N actions per day" need verifier-side state in the scope, and aggregation across sessions is not solved.
- **Nonce store is a hard dependency.** It must be atomic and durable. Gates that share one audience name need a shared store.
- **Post-execution attestation** (proof the action ran as approved) is not in format 2.
- **Time proof** for higher-risk actions is not in format 2.
- **Agent authentication.** `actor.public_key` is not yet proved by the agent. A stolen valid bundle can be presented by any caller at the named gate.
- **Platform/device attestation** is deliberately not a dependency. Optional WebAuthn/passkey attestation at registration is a possible later addition.
- **Anchoring** (any chain, any timestamp service) is an optional adapter that publishes a receipt hash. It is not part of verification.
- **Agent certificates** (`agent-certificate.md`) are still signed without a context label; they use a separate key list and a `type` field for separation.

## 8. Test vectors

`spec/test-vectors/receipt-v2.json` holds 32 receipt vectors (2 accepts, 1 denial, 29 negatives) and 6 attachment vectors (2 accepts, 4 refusals). Each receipt vector lists the receipt, `now`, the gate's expected action, pre-seen nonces and revoked ids, and the expected result code. The key is a deterministic throwaway; **it must never be used for anything real**. Any implementation is conformant only if it reproduces every `expect`. Reference verifier and generator: `tools/at1c_ref.py` (`gen` and `check`).
