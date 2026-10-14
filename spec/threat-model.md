# AT1C Threat Model — receipt format 1 (DRAFT)

**Status:** draft, not externally reviewed. Companion to `receipt.md`, `keys.md`, `agent-certificate.md`, `gate.md`. Where a threat is not covered it says so; nothing here is rounded up to "secure".

**One-line focus:** AT1C is a human-signed, single-use, scope-bound approval receipt that a gate verifies before an action runs. Any chain is optional.

Labels: **[standard]** established pattern. **[AT1C choice]** judgment call specific to this protocol. **[tested]** a test or vector in this repo exercises it. **[inferred]** reasoning only, not tested.

---

## 1. What AT1C claims, and what it does not

**Claims.** If a gate runs the check in `receipt.md` section 5 before an action, then that action was approved by a holder of a pinned key, for exactly this agent, action type, resource and payload, once, within a short time window, and the human was shown the text whose hash is in the receipt.

**Does not claim:**
- That the human understood or chose well (approval fatigue is not a crypto problem).
- That an agent cannot act outside the gate. AT1C protects only actions routed through a gate.
- That the signing key is safe from the agent. That depends on the **security level** (section 3).
- Anything about legal compliance with any regulation.

## 2. Assets and trust assumptions

| Asset | Where | Who must not touch it |
|---|---|---|
| Approver secret key (ML-DSA-65 seed) | mode-600 file today | the agent |
| Pinned public keys (`trusted-keys.json`) | gate operator | the agent |
| Nonce store (`.at1c/nonces/`) | gate host | the agent |
| Revocation list | gate operator | the agent |
| Target credentials (the thing the action actually uses, e.g. an email API key) | gate host | **the agent** (see T3) |
| Registry key (signs agent certificates) | operator | everyone else |
| Audit log (`receipts.json`) | gate host | the agent |

**Assumptions (each is a way AT1C fails if false):**
- A1. The verifier's clock is honest. [standard]
- A2. The verifier holds the right public keys (first enrolment is manual and out of band; see `keys.md`).
- A3. The gate is the **only** path to the action's side effect (see T3).
- A4. SHA-256, ML-DSA-65 (FIPS 204) and the `@noble/post-quantum` implementation are sound. Whether that library has had an independent audit is **unverified**; check before relying on it.

## 3. Security levels

The same Approver/Gate interface runs at three levels. The Gate does not change.

| Level | Approver runs | Stops | Status |
|---|---|---|---|
| 1. Dev mode | same OS user as the agent | mistakes and bugs | **built** (`approver.ts`, `gate.ts`, `client.ts`) |
| 2. Second OS account | separate user, key unreadable to the agent, request over a local socket | a hijacked agent reading the key | **not built**, design [inferred] |
| 3. Separate device | phone or token shows the request and signs there | malware on the whole computer | **not built**; hardware ML-DSA support unverified |

At level 1, everything the agent's user can write is attackable: the key file, `trusted-keys.json`, `policies.json`, the nonce directory, `receipts.json`, and the `prompt` option passed to `new AT1C()`. Level 1 gives **no** protection against a hijacked agent. It is honest dev mode.

## 4. Adversaries

| ID | Adversary | Capability |
|---|---|---|
| E1 | Mistaken agent | Honest but wrong or over-eager |
| E2 | Hijacked agent | Runs attacker instructions (e.g. prompt injection) with the agent's OS access |
| E3 | Network attacker | Sees or steals a receipt in transit |
| E4 | Malicious or phished approver prompt | Tries to make the human sign something other than what they think |
| E5 | Compromised host (root, malware) | Full control of the machine |
| E6 | Compromised registry | Signs false agent certificates |
| E7 | Platform vendor or relying party | Pushes device attestation as a condition of acceptance |

E5 is **out of scope at levels 1 and 2**. Level 3 narrows it.

## 5. Threats

Status: **COVERED** (mitigated and tested), **PARTIAL**, **OPEN**.

| ID | Threat | Rules | Mitigation and evidence | Status |
|---|---|---|---|---|
| T1 | Forged receipt (no key) | 3 | Signature checked against **verifier-pinned** key, never a key inside the receipt; alg signed and allow-listed [standard]. Vectors `BAD_SIGNATURE`, `UNKNOWN_AUTHORITY`, `ALG_NOT_ALLOWED` [tested]. Old `verifyReceipt` trusted the receipt's own key: now `@deprecated INSECURE`, but still exported, and legacy `verify.js`, `src/crypto/*` remain. | COVERED for format 1; legacy code OPEN |
| T2 | Hijacked agent self-approves (reads key, edits `trusted-keys.json`, passes its own `prompt`) | 1 | Level 2 or 3 required. Nothing at level 1. | **OPEN at level 1** |
| T3 | Agent bypasses the gate (raw shell, direct network, holds the target credential) | 4 | Rule specified in `gate.md`: credential isolation, enforcing vs advisory gates, operator check. The SDK client is an **advisory gate** (runs in the agent's process). No enforcing reference gate is built yet. | PARTIAL (rule written; no enforcing gate) |
| T4 | Replay of a valid receipt | 5 | Single-use 32-byte nonce, atomic create-if-not-exists store, restart-safe; short expiry (max 24 h); revocation by receipt id; nonce consumed **last** so a failed attempt never burns a valid receipt [AT1C choice]. Tests: replay, restart, race-safe `wx` open [tested]. Residual: file store is single host; at level 1 the agent can delete nonce files and replay. | COVERED (single host, level 2+) |
| T5 | Context swap: receipt for payload A used for payload B, other resource, type or agent | 2 | Gate recomputes `payload_hash` from the real payload; `fn` receives the payload re-parsed from its canonical form [tested]. Residual: a `fn` that ignores its argument and acts on some other value defeats this; the gate cannot see inside `fn`. | COVERED, with caller discipline |
| T6 | Tampering with a signed receipt | 3 | JCS (RFC 8785) over everything except the signature [standard]. Tamper vectors [tested]. | COVERED |
| T7 | Display deception: human shown something other than what is signed | 2, 3 | Approver renders the text itself; agent strings go through `JSON.stringify` (escapes control characters, stops fake lines); `display_digest` proves what was shown; agent description is labelled "unverified" [tested]. **Gaps:** lookalike and bidirectional Unicode not filtered; payloads over 2000 characters show only a hash, so the human is approving blind. | PARTIAL |
| T8 | Approval fatigue, rubber-stamping | — | Not solvable by crypto. Partial aids: action `class` label, deny list, short TTL. No rate limiting or batching rules yet. | OPEN |
| T9 | Algorithm confusion or downgrade | 3 | Format 1 allows only ML-DSA-65; `alg` is inside the signed bytes and allow-listed; unknown `version` rejected [tested]. | COVERED |
| T10 | Clock manipulation (expiry and key validity) | 5 | Validity judged by the verifier's clock, never `issued_at`; TTL cap [standard]. If an attacker sets the gate clock (root), expiry and key windows fail with it. | PARTIAL (assumption A1) |
| T11 | Approver key compromise | 1, 5 | `revoked: true` in the verifier's list rejects **all** of that key's receipts, including legitimate past ones; there is no "revoked since" time. No shared revocation feed, no recovery or multi-key scheme (`keys.md` gaps). No encrypted backup of today's keys yet. | PARTIAL |
| T12 | Registry or certificate abuse | 1 | Registry keys are a **separate trust list** from approver keys; certificate permissions are a ceiling, never a grant; `type` field gives domain separation from receipts [tested]. **Gap:** no proof of possession at registration, so someone could register another party's public key. Single registry signer. | PARTIAL |
| T13 | Denial of service via the nonce store or revocation list | 4 | **Fails closed** by design: if either is unavailable the gate refuses [tested]. This trades availability for safety [AT1C choice]. Garbage receipts cannot burn nonces (nonce is last). | COVERED (by design) |
| T14 | Audit log tampering or deletion | — | Every receipt is signed, so entries cannot be forged, but `receipts.json` is a plain file: entries can be deleted or edited, and it is not hash-chained. Corrupt files are never overwritten. Anchoring is an optional adapter, not part of verification. | PARTIAL |
| T15 | Stolen receipt presented by another caller | 2, 4 | Bound to `agent_id` as a string only; `actor.public_key` is informational in format 1, so the agent does not prove it is the named agent. Single use and short expiry limit the window. Future: the agent signs the request. | OPEN |
| T16 | Mosaic attack: many small approved actions add up to a harmful one | 1 | A receipt authorises one action. Spend caps and "N per day" need verifier-side state in the scope; aggregation across sessions is unsolved (`receipt.md` section 7). | OPEN |
| T17 | Secret key at rest | 1 | Seed in a mode-600 JSON file, unencrypted; client refuses a group/world-readable file [tested]. No passphrase, no hardware. | PARTIAL |
| T18 | Vendor or platform capture (attestation as a condition of acceptance) | — | Receipt verification needs only the pinned public key; attestation is not a dependency. Rule written in `gate.md` section 8: no gate may require attestation; optional enrolment-time evidence only; key storage (software, token, phone) is not a ground for refusal. An operator can still impose its own enrolment policy; the protocol cannot prevent that. | PARTIAL (rule written; operator policy not preventable) |
| T19 | Cross-use between receipts and certificates | 3 | Certificates carry `type: "agent_certificate"`; receipts have no `type`; separate key lists [tested]. | COVERED |
| T20 | Supply chain (npm dependencies, build output in Git) | — | One crypto dependency (`@noble/post-quantum`). `dist/` is tracked in Git though it is build output. Lockfile and audit status not reviewed here. | OPEN |

## 6. Prioritised next mitigations (recommendation, in order)

1. ~~Write the credential-isolation rule into the spec (T3).~~ **Done:** `gate.md`. Next for T3: build an enforcing reference gate (a separate process that holds the credential).
2. **Build level 2 (T2).** Separate OS account plus socket; this is the first level that stops a hijacked agent.
3. **Large-payload policy (T7).** Refuse, or require a structured human summary, instead of approving by hash alone.
4. **Key backup and compromise handling (T11, T17).** Encrypted backups; a "revoked since" time so old legitimate receipts are not all invalidated.
5. **Agent-signed request (T15)** and **proof of possession at registration (T12).**
6. **Attestation rule (T18)** and multi-key/recovery design.
7. **Audit log hash chain (T14)** and cumulative limits (T16).

## 7. Out of scope

Host compromise at levels 1 and 2 (E5); the human's judgement; legal compliance; on-chain anchoring; availability beyond fail-closed behaviour.
