# AT1C Agent Certificate — format version 1 (DRAFT)

Companion to `receipt.md` and `keys.md`. A certificate is a registry-signed statement: "this public key belongs to this agent, owned by this owner, with this permission ceiling, until this date."

Items marked **[standard]** use an established pattern. Items marked **[AT1C choice]** are judgment calls specific to this protocol and have not been externally reviewed.

## 1. What a certificate is, and is not

- It **identifies** an agent. It does not **authorise** anything. Permissions in a certificate are a **ceiling, never a grant**: an action still needs a human-signed receipt (Rule 1, No Implicit Authority). A gate MAY refuse a receipt whose `action.type` is outside the agent's certified permissions. [AT1C choice]
- It is a reusable credential, so it has **no nonce**. Revocation is how you stop one early (section 5).
- `agents.json` is registry bookkeeping. Fields such as `status` that sit outside the signed certificate MUST NOT be used for any authorisation decision.

## 2. Structure

All strings, safe integers, booleans, arrays and objects only. **No floats.** Timestamps are `YYYY-MM-DDTHH:MM:SSZ`.

```json
{
  "version": "1",
  "type": "agent_certificate",
  "agent_id": "agent:<32 hex>",
  "agent_alg": "ML-DSA-65",
  "agent_public_key": "<b64url>",
  "name": "Payments bot",
  "owner": "did:web:at1c.com#mora-1",
  "permissions": ["read_balance", "send_payment"],
  "tier": "standard",
  "issued_at": "2026-10-13T09:00:00Z",
  "expires_at": "2027-10-13T09:00:00Z",
  "issuer": "did:web:at1c.com#registry-1",
  "alg": "ML-DSA-65",
  "signature": "<b64url>"
}
```

| Field | Rule |
|---|---|
| `version` | `"1"` |
| `type` | Always `"agent_certificate"`. Domain separation: a certificate can never be mistaken for a receipt, which has no `type` field. |
| `agent_id` | `agent:` + the first 32 hex characters of SHA-256 over the raw `agent_public_key` bytes. Derived, so an ID cannot be claimed for a key it does not match. [AT1C choice] |
| `agent_alg`, `agent_public_key` | The agent's own key. Format 1: `ML-DSA-65`, 1952 bytes, b64url. |
| `name` | Human label. Not trusted for authorisation. |
| `owner` | Authority id of the owning human or organisation (same form as `approval.authority`). |
| `permissions` | Array of action-type strings, **unique and sorted ascending** (arrays keep their order under JCS, so there is exactly one valid form). |
| `tier` | `free`, `standard` or `enterprise`. Anything else is rejected. |
| `issued_at`, `expires_at` | `expires_at > issued_at`; lifetime at most **366 days**. [AT1C choice] |
| `issuer`, `alg` | Registry key id, and `ML-DSA-65`. Both are inside the signed bytes. |
| `signature` | b64url ML-DSA-65 over `JCS(certificate without signature)` (RFC 8785 [standard]). |

Unknown extra fields are ignored by verifiers but are covered by the signature if present.

## 3. Registry keys are a separate trust list

Verifiers pin registry keys in their own list (same record shape as `keys.md`: `alg`, `public_key`, `valid_from`, `valid_until`, `revoked`), kept apart from the approver keys that sign receipts. A key in one list is never accepted from the other. [AT1C choice] Reason: one key signing two kinds of statement invites cross-use; separate lists make that impossible by construction.

## 4. Verification order (normative)

First failure wins:

1. `SCHEMA`: required fields, formats, sorted unique `permissions`, valid `tier`.
2. `ALG_NOT_ALLOWED`: `alg` and `agent_alg` are on the verifier's allowlist.
3. `UNKNOWN_ISSUER`: `issuer` has a pinned registry key.
4. `KEY_NOT_VALID`: registry key not revoked, `alg` matches, verifier's clock inside `valid_from <= now < valid_until`.
5. `BAD_SIGNATURE`.
6. `BAD_VALIDITY`: `expires_at > issued_at` and lifetime <= 366 days.
7. `NOT_YET_VALID` / `EXPIRED`: `issued_at <= now < expires_at` on the verifier's clock.
8. `AGENT_ID_MISMATCH`: `agent_id` equals the value derived from `agent_public_key`.
9. `REVOKED`: `agent_id` is not on the verifier's revocation list.

## 5. Revocation

Verifier-side list of revoked `agent_id` values (and, for a compromised registry key, `revoked: true` on that key, which rejects every certificate it signed). A shared revocation feed is not specified (same gap as `keys.md`).

## 6. Known gaps

- **No proof of possession at registration.** Nothing in format 1 proves the registrant controls the private half of `agent_public_key`. Someone could register another party's public key. Recommended fix: the registrar sends a random challenge and the agent signs it before issuing. Not in format 1.
- **Registry is a single signer.** Compromise of the registry key is handled only by `revoked: true` at each verifier.
- **Ceiling checks are optional** (section 1) and enforced only by gates that choose to.
- **Shared revocation feed** and **owner change / transfer** are unspecified.
