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

## 8. What this does not solve

- A hijacked agent can still *ask*, and a rushed human can still approve (threat T8). Enforcement confines the damage to what was approved; it does not judge the approval.
- Cumulative harm from many small approved actions (threat T16).
- Compromise of the gate host itself.
- No reference enforcing gate exists in this repo yet.
