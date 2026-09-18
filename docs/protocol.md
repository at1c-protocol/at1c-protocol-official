# AT1C Protocol Specification v1.4

**Cryptographic Human Consent for AI Agent Actions**

---

## Abstract

AT1C is an open protocol that makes every AI agent action accountable, consent-based, and cryptographically verifiable.

The protocol is built on one rule:

**No action is valid unless backed by verifiable human approval.**

Every action produces a signed receipt. Every receipt can be independently verified. No trust in AT1C as an intermediary is required — the cryptography is the guarantee.

```
request → approve → proof → verify
```

---

## Core Principle

No system — human or AI — may act on behalf of a user without explicit approval, and that approval must be provable.

All actions performed on behalf of a user must satisfy:

- **Explicit approval** — intentionally granted by the user or authorised authority
- **Bound context** — tied to a specific action, actor, scope, and resource
- **Verifiable proof** — independently verifiable by any system, with no reliance on AT1C

---

## Chapter 1 — Purpose

Modern AI agents execute payments, file documents, manage data, and take automated decisions — with no verifiable record that a human authorised those actions.

Current systems cannot prove:

- who approved an action
- what exactly was approved
- whether the approval was altered
- whether the authorisation was replayed
- whether execution was validly authorised

AT1C provides these primitives. The protocol defines a structured consent flow for AI agent actions using cryptographic receipts and deterministic verification.

AT1C does not replace AI orchestration systems. It is the authorisation and accountability layer that sits alongside them.

---

## Chapter 2 — Core Entities

### 2.1 User (Human Principal)

The User is the root authority within the protocol. The User owns identity, grants approvals, defines authorisation boundaries, and may delegate permissions. The protocol assumes authorisation originates from human-controlled authority.

### 2.2 Agent

The Agent is the autonomous system requesting permission to perform an action. Agents do not self-authorise. All agents must operate within their authorised scope and request approval for actions outside it.

An agent must be registered with the AT1C registry before it can participate in the protocol. Registration binds the agent's identity to a public key — the private key never leaves the agent's device and is never held by AT1C.

### 2.3 Approver

The Approver is the authority responsible for granting or denying requested actions. The Approver may be a human operator, an administrative authority, or a policy engine operating within defined boundaries.

### 2.4 Receipt

The Receipt is a signed cryptographic proof of authorisation. It contains the action metadata, timestamp, nonce, and signature. The Receipt is the central proof object in the protocol — the compliance evidence.

### 2.5 Verifier

The Verifier validates receipt authenticity, payload integrity, signature correctness, replay status, and expiration. Only verified receipts are considered authorised. Any party — the agent, a counterparty, a regulator, or an auditor — can verify independently.

### 2.6 Executor

The Executor performs the approved action after successful verification. Execution without verification is non-compliant under AT1C.

---

## Chapter 3 — Request Model

An Agent constructs a structured request describing the intended action before anything is executed.

```json
{
  "actor": "payment-agent",
  "action": "send_payment",
  "resource": "account_12345",
  "payload": {
    "amount": 250.00,
    "currency": "GBP",
    "recipient": "vendor_abc"
  },
  "timestamp": 1753000000
}
```

The request defines proposed intent only. It does not authorise execution.

---

## Chapter 4 — Approval Model

Approval converts a proposed action into a verifiable authorisation event.

During approval:
- The request is reviewed by the Approver
- Authorisation intent is confirmed
- A receipt is generated and signed

Requests may be approved, denied, or expired. Approval does not imply unlimited authority — authorisation is always context-bound.

---

## Chapter 5 — Receipt Structure

```json
{
  "id": "receipt_uuid",
  "actor": "payment-agent",
  "action": "send_payment",
  "resource": "account_12345",
  "payloadHash": "sha256:abc123...",
  "approvedBy": "user_abc",
  "timestamp": 1753000000,
  "expiresAt": 1753003600,
  "nonce": "7d8a2f...",
  "signature": "ML-DSA-65:..."
}
```

### Required Fields

| Field | Description |
|-------|-------------|
| `id` | Unique receipt identifier |
| `actor` | The requesting agent |
| `action` | The approved action |
| `resource` | The target resource |
| `payloadHash` | SHA-256 hash of the request payload |
| `approvedBy` | Identity of the approving authority |
| `timestamp` | Approval creation timestamp |
| `nonce` | Unique single-use anti-replay value |
| `signature` | ML-DSA-65 signature over the receipt |

Receipts are serialised deterministically before signing to ensure consistent hashing and signature stability.

---


## Chapter 5a — Principal Lifecycle Fields (Reserved — v2.x)

The following fields are reserved in the Receipt schema for v2.x principal lifecycle management. They are optional and undefined in v1.x. Verifiers must ignore unknown fields to maintain forward compatibility.

| Field | Type | Description |
|-------|------|-------------|
| `principalValidUntil` | ISO timestamp | The approving principal's authority expires at this time. Receipts produced after this timestamp should be treated as unattributed. |
| `dissolutionTrigger` | string enum | Event that invalidates this agent's principal: `principal_deceased`, `entity_dissolved`, `key_revoked` |
| `inheritorAgentId` | string | Agent ID that inherits signing authority on the trigger event |
| `postDissolutionPolicy` | string enum | Verifier behaviour after dissolution: `reject` (default), `warn`, `audit_only` |

### Rationale

AI agent proliferation requires the same governance infrastructure as vehicle registration: agents must be registered to a verified principal, and principal termination (death, corporate dissolution) must not produce zombie agents whose receipts remain cryptographically valid with no living principal behind them.

A dissolved corporation's agent producing AT1C receipts does not have a valid principal with legal standing. These fields allow registries and verifiers to enforce principal continuity without requiring a protocol fork for deployments that add them later.

---


## Chapter 6 — Five Core Safety Rules

### Rule 1 — No Implicit Authority
No action may be executed without explicit approval unless pre-authorised within a defined scope.

### Rule 2 — Context Binding
Approval must be bound to a specific action, actor, resource, and scope. Reuse of approval outside its context is invalid.

### Rule 3 — Proof Integrity
Proofs must be tamper-evident, reproducible, and independently verifiable. No trust in the issuer is required after proof generation.

### Rule 4 — Verification Before Execution
Any system receiving a request must verify the receipt before executing the action.

### Rule 5 — Replay Protection
A previously used nonce must not be accepted again. Replay detection prevents repeated execution using reused receipts.

## Chapter 7 — Cryptographic Implementation

AT1C uses **ML-DSA-65** (NIST FIPS 204) for all signatures — a lattice-based post-quantum digital signature scheme, standardised August 2024, resistant to both classical and quantum computer attacks.

**What AT1C guarantees:**
- A valid receipt proves the holder of the private key signed the exact action payload — no one else could have produced that signature
- Nonces are unique and single-use — replay attacks are prevented by construction
- Agent certificates are signed by the AT1C registry root key — agent identity is independently verifiable

**Layered security model:**
AT1C is one layer in a defence-in-depth stack. The receipt proves a specific key signed a specific approval. The question of who holds that key is answered by the authentication layer (passkey, biometric, 2FA) sitting alongside AT1C. Combined, these two layers deliver identity assurance and action accountability.

**Known limitation:** AT1C uses ML-DSA-65 (NIST FIPS 204), a standardised post-quantum digital signature scheme. Receipts issued prior to SDK v1.0.3 used Ed25519, which is not post-quantum secure — migration guidance for pre-v1.0.3 deployments is on the roadmap.

---

## Chapter 8 — Agent Registration

Agents must be registered with the AT1C registry before participating in the protocol.

Registration process:
1. Agent generates an ML-DSA-65 keypair locally — private key never leaves the device
2. Agent submits the public key (SPKI hex DER) to the registry
3. Registry validates the public key and signs a certificate over it
4. Registry returns a signed agent certificate with a unique Agent ID

The registry is live at **registry.at1c.com**. Registration is available at **at1c.com/users/register-agent.php**.

AT1C never holds private keys. The registry is non-custodial by design.

---

## Chapter 9 — Tiered Autonomy (Planned — v2.0)

Not every agent action carries the same risk. AT1C's planned permission model reflects this:

- **Low trust** — explicit human approval required for every action; appropriate for high-value or sensitive actions
- **Medium trust** — agent operates within pre-approved boundaries; alerts trigger on boundary approach
- **High trust** — agent operates within a fully scoped envelope; human oversight via audit log and alarm

This maps directly onto the EU AI Act's risk classification framework.

*Tiered autonomy is a planned feature for AT1C v2.0. Current protocol supports scoped permissions per agent.*

---

## Chapter 10 — EU AI Act Compliance

AT1C addresses the following EU AI Act requirements (enforcement: August 2026):

| Article | Requirement | AT1C Response |
|---------|-------------|---------------|
| Art. 9 | Risk management | Approval checkpoint at every action |
| Art. 13 | Transparency | Request names action and resource explicitly before approval |
| Art. 14 | Human oversight | No action executes without verified human approval |
| Art. 17 | Quality management | Every receipt is a timestamped, tamper-evident audit record |
| Art. 26 | Deployer obligations | Receipt log satisfies the logging requirement without custom infrastructure |

---

## Chapter 11 — SDK

The `@at1c/sdk` npm package exposes the core protocol primitives:

```bash
npm install @at1c/sdk
```

Core functions:
- `createRequest()` — construct a structured action request
- `approveRequest()` — generate approval intent
- `signReceipt()` — produce a signed receipt
- `verifyReceipt()` — verify a receipt before execution
- `detectReplay()` — check nonce against used receipt store
- `storeReceipt()` — persist receipt for audit

Full documentation: **github.com/at1c-protocol/at1c-protocol-official**

---

## Chapter 12 — Roadmap

| Version | Status | Description |
|---------|--------|-------------|
| v1.1 | ✅ Done | Non-custodial agent key registration |
| v1.2 | ✅ Done | Live registry API at registry.at1c.com |
| v1.3 | ✅ Done | Open web registration — personal and entity agents |
| v1.4 | ✅ Done | Browser-side keypair generation — no terminal required |
| v1.5 | Planned | End-user passkey (WebAuthn/FIDO2) onboarding |
| v1.6 | Planned | Hosted receipt storage — 10-year retention paid tier |
| v2.0 | Planned | Tiered autonomy with alarm thresholds |
| v2.1 | Planned | Algorand x402 payment integration |
| v2.2 | Planned | Principal lifecycle — agent inheritance, dissolution triggers, zombie corp protection |
| Future | Roadmap | Agent Manifest per EU AI Act Art 13/14, post-quantum signature migration, IANA well-known URI registration |

---

## Compliance Statement

A system is considered AT1C-compliant if:

1. Actions require valid approval or scoped authorisation
2. Approvals produce verifiable cryptographic proof
3. Proofs are verified before execution

Unattributed or unverifiable agent actions are non-compliant with the protocol.

---

*AT1C Protocol Specification v1.4 · © 2026 AT1C Protocol Contributors · MIT Licence*
