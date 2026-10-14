# AT1C Gate Specification — conformance for receipt format 1 (DRAFT)

Companion to `receipt.md` (what a gate checks) and `threat-model.md` (why). This file says **what a gate must control** for its checks to mean anything.

Normative words (MUST, SHOULD) follow RFC 2119. **[standard]** = established pattern. **[AT1C choice]** = judgment call, not externally reviewed.

## 1. The problem this solves

A receipt proves that a human approved an action. It cannot force an agent to ask for approval. If the agent itself holds the means to cause the side effect (an API key, a database password, a wallet key, a direct network path to the target), a hijacked agent skips the gate and no receipt is ever checked. Rule 4 (Verification Before Execution) is then true of the gate and meaningless for the system.

## 2. Credential isolation (the rule)

> **The capability to cause the side effect MUST be held by the gate, or by the target itself, and MUST NOT be readable or usable by the agent.**

The agent submits a request (`agent_id`, action `type`, `resource`, `payload`) and a receipt. The gate verifies (`receipt.md` section 5) and, only then, performs the action with a credential the agent never sees. This is complete mediation by a reference monitor: always invoked, tamper-resistant, small enough to reason about. [standard]

## 3. Two classes of gate

| Class | Meaning | What it can honestly claim |
|---|---|---|
| **Enforcing gate** | Satisfies section 4. | Actions it guards cannot happen without a verified receipt, even if the agent is hijacked (provided the approver key is also out of the agent's reach, see section 6). |
| **Advisory gate** | Runs the same checks, but the agent can reach the credential or a direct path to the target. | Audit trail and protection against mistakes and bugs only. It MUST NOT be described as preventing a hijacked or malicious agent. |

The SDK's in-process `AT1C` client is an **advisory gate** today. [confirmed: it runs inside the agent's process and OS account]

## 4. Requirements for an enforcing gate

1. **Credential custody.** The credential for the side effect lives where the agent cannot read it: a different OS account, process or host, with file permissions or an access-control layer enforcing that. The gate MUST NOT hand the credential to the agent, even temporarily.
2. **Complete mediation.** Every route the agent has to the side effect goes through the gate. Direct egress from the agent to the target MUST be blocked, or the target MUST reject any caller other than the gate (for example a token, client certificate or network rule that only the gate holds).
3. **Execute what was verified.** The gate acts on the payload it hashed and verified, re-parsed from its canonical form, not on a second copy supplied by the agent. [standard, see `payload_hash`]
4. **Order.** Verify, then consume the nonce, then execute. A receipt is spent once verification succeeds, even if execution then fails; a retry needs a new receipt. (Idempotent retry using `receipt_id` is possible but not specified here.) [AT1C choice]
5. **Fail closed.** If the nonce store, revocation list or pinned keys are unavailable, refuse.
6. **Record.** Log the receipt and the outcome (executed, refused with code, or execution error).
7. **Small and separate.** The gate is the highest-value target in the system. Keep it small, run it with least privilege, and do not run agent-supplied code inside it.

## 5. Alternatives weighed

| Option | Strength | Cost | Verdict |
|---|---|---|---|
| **Gate executes the action** (agent never holds the credential) | Strongest; works with any target | Gate must integrate with each target | **Recommended default** |
| **Target verifies the receipt itself** | Strongest of all: no credential to steal; the resource demands the receipt | Target must understand AT1C | Best where you control the target (e.g. the `/v1/verify` pattern) |
| **Gate mints a one-use scoped credential after verifying** | Target needs no AT1C support | Needs scoped, short-lived credentials from the target; minting path becomes critical [inferred] | Acceptable middle path |
| **Rely on sandboxing and agent honesty** | None | A hijacked agent is not honest | Rejected |

## 6. How this combines with approver levels

Two independent protections are needed against a hijacked agent. Having only one gives none of the benefit.

| | Approver key reachable by agent (level 1) | Approver key out of reach (level 2 or 3) |
|---|---|---|
| **Advisory gate** | Mistakes only | Mistakes only (agent bypasses the gate) |
| **Enforcing gate** | Mistakes only (agent signs for itself) | **Protects against a hijacked agent** |

## 7. Operator check (do this before claiming protection)

Run these **as the agent's OS user**:

1. Can it read the credential for the side effect? (If yes: advisory.)
2. Can it reach the target directly, without the gate? (If yes: advisory.)
3. Can it read the approver key, edit the pinned-key list, or delete nonce files? (If yes: not protected against a hijacked agent, whatever the gate class.)

## 8. Attestation is not a condition of acceptance

**Why.** Device or platform attestation lets a relying party demand an approved operating system, vendor or firmware. Left open, it becomes a dial that tightens over time and hands control of who may approve to platform vendors, shuts out Linux and de-Googled devices, and turns a device model into an identifier. AT1C keeps it out of the core on purpose. [AT1C choice]

**Requirements:**

1. **Acceptance depends only on `receipt.md` section 5 and the verifier's pinned keys.** The receipt format has no attestation field. A gate MUST NOT refuse a receipt because it lacks attestation, or because of how or where its key was generated or stored. A software key file, a hardware token and a phone enclave key are equal.
2. **Optional evidence only.** A gate MAY accept and record attestation evidence when a key is enrolled (for audit or its own risk assessment). Absence of that evidence MUST NOT, by itself, make a receipt from an already-pinned key fail.
3. **Conformance.** An implementation whose receipt verification depends on attestation MUST NOT claim conformance to this specification.
4. **Enrolment is the operator's decision** (`keys.md`). An operator MAY apply its own enrolment policy. If that policy depends on attestation or a particular vendor, it SHOULD be published, and SHOULD NOT be the only path in: offer at least one alternative, such as out-of-band enrolment of a user-generated key. [judgment; guidance, not enforceable by the protocol]
5. **No fingerprints as identity.** Browser or device fingerprints MUST NOT be used as an identity or trust signal for approvals.

**Alternatives weighed:**

| Option | Verdict |
|---|---|
| Ban attestation everywhere | Simple, but blocks legitimate enterprise assurance. Rejected as too blunt. |
| **Optional enrolment-time evidence only (this section)** | **Recommended.** Keeps the receipt and conformance independent of vendors while allowing local assurance. |
| Require attestation for irreversible actions | Rejected: vendor capture, device-model leakage, excludes non-mainstream platforms. |

**Honest limit:** a specification cannot stop an operator from adding its own local policy. What it can do, and does here, is make sure the receipt format and conformance never depend on attestation, so nobody can claim the protocol requires it. Multiple keys per authority and key recovery (so no single device is a lock-in) are still unspecified; see `keys.md` gaps.

## 9. What this does not solve

- A hijacked agent can still *ask*, and a rushed human can still approve (threat T8). Enforcement confines the damage to what was approved; it does not judge the approval.
- Cumulative harm from many small approved actions (threat T16).
- Compromise of the gate host itself.
- No reference enforcing gate exists in this repo yet.
