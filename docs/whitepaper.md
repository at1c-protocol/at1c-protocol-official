# AT1C Protocol — The Human Authorisation Layer

**Whitepaper v1.7**

**Cryptographic Human Consent for AI Agent Actions**


*October 2026 · at1c.com · registry.at1c.com · github.com/at1c-protocol*

---

## Executive Summary

AI agents are taking consequential actions on behalf of humans and organisations sending payments, filing documents, scheduling appointments, managing data with no verifiable record that a human actually authorised those actions. The EU AI Act is now in force. Its transparency duties apply from 2 August 2026, and its high-risk requirements, which include human oversight and automatic logging, apply from 2 December 2027. Together they call for the record that is missing: accountability for automated decisions, human oversight of high-risk AI actions, and auditable logs of AI behaviour. South Korea's AI Basic Act, in force since 22 January 2026, points the same way.

AT1C Protocol, The Human Authorisation Layer, is an open protocol that addresses this problem with a single, cryptographically verifiable primitive: a signed receipt that proves a specific human approved a specific AI agent action before it executed. AT1C works for individual users protecting their personal AI assistants, and for organisations managing fleets of agents operating across business processes.

**AT1C is:**
- Free and open source MIT licensed, no vendor lock-in
- Deployable in a day a lightweight SDK wrapping any existing system
- Non-custodial AT1C never holds signing keys; they stay on the agent's or user's device
- Designed for both personal and entity use individual AI assistants and enterprise agent fleets
- Live today registry.at1c.com is operational and accepting agent registrations

> Large enterprises spend €400,000–€2,000,000 per year on EU AI Act compliance infrastructure. AT1C gives SMEs and individuals in fintech, healthcare, and legal the same verifiable accountability at a fraction of the cost.

---

## Foundational Principles: Three Independent Convergences

AT1C was not built in a vacuum. Three independent bodies of principled thought — from internet protocol design, legal scholarship, and peer-reviewed digital governance research — have arrived at the same conclusion that AT1C implements.

### RFC 8890: The Internet is for End Users

In 2020, the Internet Architecture Board (IAB) published RFC 8890, authored by Mark Nottingham, Chair of the IETF HTTP Working Group. The RFC establishes a formal principle: that internet protocol design decisions should favour end users over all other stakeholders when conflicts arise, and that "all decisions have the possibility of bias; of advantaging or disadvantaging different parties."

RFC 8890 explicitly states that the IETF should design protocols for the pessimal environment the worst-case scenario where platforms and networks cannot be trusted to act in users' interests.

AT1C applies this principle directly to AI agent consent. The protocol is designed for the pessimal environment: a world where platforms cannot be trusted to hold your signing keys, maintain your consent records honestly, or enforce your approval boundaries without cryptographic proof. Non-custodial design, signed receipts, and independent verification are not conveniences they are the architecture that RFC 8890's philosophy demands.

### Ayres & Balkin: The Legal Accountability Gap

In 2026, Yale Law School professors Ian Ayres and Jack Balkin, writing in the University of Chicago Law Review, identified the defining legal gap of the AI era: AI agents lack *mens rea* intention which means most existing liability frameworks do not cleanly apply to AI actions. Their solution: apply objective standards, holding the humans and companies deploying AI to standards of reasonable care.

The critical implication: for objective liability to work, there must be evidence of what the human principal approved. Without a verifiable consent record, accountability collapses.

AT1C's signed receipt is exactly that evidence. It transforms the legal question from "did the principal exercise reasonable care?" hard to prove, subjective to "is there a signed receipt for this action?" verifiable, objective, independently auditable.

**AT1C is not only an EU AI Act compliance tool. It is the evidentiary infrastructure that makes AI accountability law enforceable.**

### UiO/SODI: Platform Capture of Identity is the Failure Mode

In 2026, researchers at the University of Oslo's Scandinavian Institute for Digital Governance (SODI) published peer-reviewed findings on Norway's market-based digital identity ecosystem. Their conclusion: delegating identity infrastructure to private platforms — without democratic anchoring, holistic governance, or public oversight — produces exclusion, fraud, and accountability failure. Fraud victims have been held liable for loans taken out on their digital IDs by abusive partners. People with Down syndrome have been denied access to public digital services. The Supreme Court of Norway is hearing cases that existing legal frameworks cannot resolve.

This is RFC 8890's pessimal environment applied to identity: the real-world cost of platform capture. AT1C's non-custodial design — where identity and signing keys belong to the individual, never the platform — is the architectural corrective this research calls for.

**Honest limitation:** AT1C's receipt proves a key was used. It cannot on its own prove the will behind that key use was free. Coercion and incapacity are circumstances adjudicated by courts, not protocols — a limitation shared by all cryptographic consent systems and disclosed in full in the Known Limitations section.

---

## The Problem: Unaccountable AI Agents

Modern AI systems act silently. An agent executes a payment, files a form, or sends a communication and there is no cryptographic record that a human approved that specific action at that specific moment.

This is not merely a technical gap. It is a gap the EU AI Act was written to close. As the number of deployed AI agents grows toward billions — and eventually toward the "trillions of agents" scale researchers project for European SMEs alone the accountability gap compounds. Without a standard consent protocol, every agent is an unverified actor, and every action it takes is a potential compliance exposure.

---

## The Three Sectors Most at Risk

### Fintech

AI agents in financial services execute trades, initiate payments, and manage portfolios on behalf of users. Under the EU AI Act, MiFID II, and PSD2, firms are expected to demonstrate human oversight of automated decisions.

**Cost of non-compliance:** EU AI Act fines reach €15M or 3% of global annual turnover for most operator obligations (including deployer duties), and €35M or 7% for prohibited practices (Art. 99). The higher figure applies to larger firms and the lower to SMEs. Under MiFID II, national regimes must allow maximum fines of at least €5M, or up to 10% of annual turnover for firms (Art. 70).

**AT1C solution:** Every agent-initiated transaction carries a signed receipt proving the account holder approved that specific action — independently verifiable, no reliance on the firm's own logs.

### Healthcare

AI agents scheduling appointments, triaging patients, recommending treatments, and accessing medical records. The EU AI Act classifies many health AI uses as high-risk, requiring the strictest oversight and auditable records.

**Cost of non-compliance:** GDPR fines up to €20M or 4% of global turnover, plus EU AI Act penalties.

**AT1C solution:** Every AI-initiated action on patient data requires a verifiable human approval receipt — can support both the GDPR consent record and evidence of EU AI Act human oversight.

### Legal

AI agents drafting documents, conducting due diligence, filing submissions, and communicating with counterparties. Solicitor conduct rules require informed client consent for actions taken on their behalf.

**Cost of non-compliance:** SRA disciplinary action, professional indemnity claims, and EU AI Act penalties.

**AT1C solution:** Client consent to specific AI-initiated actions captured as a cryptographic receipt, timestamped and independently verifiable.

---

## How It Works

```
request → approve → proof → verify
```

**Step 1 — Request:** An AI agent asks permission to perform a specific, scoped action. Nothing executes at this stage.

**Step 2 — Approve:** A human explicitly grants or denies the request. Approval is specific to the action named — it cannot be transferred to any other action. This is the human-in-the-loop moment that Art. 14 of the EU AI Act calls for.

**Step 3 — Proof:** A signed receipt is generated, cryptographically binding the approving user's identity, the exact action, the agent's registered public key, a timestamp, and a single-use nonce. The receipt is signed with the user's ML-DSA-65 private key — which never leaves their device.

**Step 4 — Verify:** Any system — the agent, a counterparty, a regulator, or an auditor independently verifies the receipt before the action executes. Any system can verify a receipt's signature independently. Confirming which agent and owner a key belongs to uses the registry certificate, unless you pin the key yourself.

---

## Personal and Entity Use Cases

### Personal AI Agent Coverage

Any individual using an AI assistant to act on their behalf benefits from AT1C. A personal account gives the individual a verifiable record of every action their AI assistant has taken independently auditable at any time. Registration takes one day. The private key stays on the individual's device. No fee for the free tier.

### Entity-Owned Agent Fleets

Organisations deploying multiple AI agents face the challenge of maintaining oversight without creating an approval bottleneck. AT1C addresses this through granular permission scopes and autonomy levels.

### Autonomy Levels: Low, Medium, High Trust

- **Low trust** explicit human approval for every action; appropriate for high-value or sensitive actions
- **Medium trust** autonomous within pre-approved boundaries; alerts on boundary approach
- **High trust** operates within a scoped permission envelope; oversight via audit log and alarm

This aligns with the risk-based approach of the EU AI Act.

*Note: Autonomy levels are a planned feature for AT1C v2.0.*

---

## Cryptographic Guarantees

**Confirmed guarantees:**
- A valid receipt proves the holder of the private key signed the exact action payload — no one else could have produced that signature
- Nonces are unique and single-use replay attacks are prevented by construction
- Agent certificates are signed by the AT1C registry root key agent identity is verifiable against the registry root key, or against a key you pinned
- ML-DSA-65 (FIPS 204) NIST-standardised post-quantum lattice signature scheme, strong security record

**The layered security model:**
AT1C is one layer in a defence-in-depth stack. The receipt proves a specific key signed a specific approval. The question of who holds that key is answered by your authentication layer (passkey, biometric, 2FA). Combined, these two layers deliver identity assurance and action accountability the same separation of concerns that governs every major payment network and PKI system in production today.

**Time evidence and anchoring:** AT1C is chain-agnostic. Anchoring is planned, not yet shipped. The intended design is optional anchor adapters, with OpenTimestamps and RFC 3161 timestamping as the planned defaults, and anyone will be able to contribute an adapter for another chain. Today a receipt carries the signer's own timestamp, which is not independent time evidence. No receipt depends on a blockchain.

**Known limitations:**
- ML-DSA-65 signature sizes are larger than classical alternatives (~3.3 KB vs 64 bytes for Ed25519) — an accepted bandwidth and storage trade-off for post-quantum security
- Receipt storage is currently local — hosted long-term storage is a planned paid tier
- Autonomy levels are planned — current protocol supports scoped permissions per agent
- A valid receipt proves a specific action scope was approved at a specific time — it does not prove the agent acted within that scope, what the agent observed before acting, or what it actually executed post-approval. Post-execution outcome verification is a planned future layer
- AT1C assumes the key holder is the consenting principal. This assumption does not hold under coercion, cognitive incapacity, or caregiving delegation — circumstances adjudicated by courts, not protocols. This limitation is shared by all cryptographic consent systems
- Per-action approval does not bound aggregate behaviour. Ten individually approved actions can combine to exceed what a reasonable principal would have consented to in aggregate. Limits on cumulative behaviour (budget receipts) are not implemented yet and are a candidate for spec v0.2
- A receipt proves authorisation over a bounded action. It does not prove the human understood the model's reasoning, and it does not claim to. Approval is contextual and scope-bound, which is AT1C's answer to the "oversight paradox" critique (World Economic Forum, July 2026) that human oversight weakens as AI capability grows
- Replay protection uses a durable nonce store on a single host. Several gateways need a shared store, which is not yet specified
- The agent does not yet prove its own identity at the Gate, so a stolen valid receipt can be presented by any caller whose payload matches. Agent certificates exist, and binding them into the Gate is still to come

---

## EU AI Act Compliance Mapping

| Article | Requirement | How AT1C supports it |
|---------|-------------|----------------------|
| Art. 9 | Risk management | An approval checkpoint at every action gives risk management a concrete control point; autonomy levels (planned) will map risk to oversight intensity |
| Art. 12 | Record-keeping (automatic logging) | Receipts, including denials, are timestamped records of human decisions. They sit alongside, and do not replace, the system's own automatic logging |
| Art. 13 | Transparency | Request names action and resource explicitly before approval is sought |
| Art. 14 | Human oversight | The AT1C flow is designed so that no action executes without a verified human approval |
| Art. 17 | Quality management | Receipts are timestamped, tamper-evident records that a quality management system can draw on |
| Art. 26 | Deployer obligations | Supports deployers' duties to assign human oversight and keep records; it does not replace system-level logging |

**When these apply (as of 19 October 2026):** The Act is in force. Art. 50 transparency duties apply from 2 August 2026, with a transition to 2 December 2026 for synthetic-content marking. High-risk requirements (Annex III) apply from 2 December 2027, and product-embedded AI from 2 August 2028, under Regulation (EU) 2026/1744. These dates have moved before and may move again; check current sources before relying on them. AT1C supports and evidences these duties. It does not by itself make a system compliant.

### Beyond the EU

South Korea's AI Basic Act came into force on 22 January 2026. It requires operators of high-impact AI to provide a mechanism for human intervention and supervision. The ministry has indicated a grace period of about one year, with administrative fines expected from January 2027 and capped at KRW 30 million. A signed approval receipt is a direct way to evidence that this human oversight happened. No law names AT1C; the duties it evidences are the ones now written into law.

---

## Ecosystem Positioning

AT1C operates in an emerging landscape of agent governance, receipt, and identity systems. The protocol is designed to be complementary to adjacent systems, not competitive with them. This section describes the key neighbours and how AT1C relates to each.

### Sello — Receiver-Attested Action Evidence
Sello (arXiv 2606.04193) produces encrypted, receiver-attested receipts proving what a service observed during and after an interaction. The Sello author has confirmed on record: "Sello v0.1 deliberately treats authorization-token and human-consent semantics as out of scope — a Sello receipt does not presently prove human approval." AT1C and Sello are complementary at the artifact-reference layer: a Sello action record can reference an AT1C approval receipt, combining service-side observation evidence with human-side consent proof.

### Stategram — Pre-Execution Enforcement with Running Totals
Stategram is a maker-checker enforcement layer for AI agents with per-action approval gates and cumulative daily caps. It is the closest system to AT1C in the approval-receipt space. Key differences: Stategram is a custodial SaaS product — they sign receipts and hold the ledger. AT1C is a non-custodial open protocol — the principal holds the signing key. Stategram targets B2B enterprise fleet management; AT1C targets individual human principals and open ecosystem adoption. Stategram's cumulative cap mechanism (catching the drip attack) is noted as a gap in AT1C v1.x; budget receipts, a candidate for spec v0.2, are the planned answer.

### Microsoft Agent Control Specification (ACS) — Runtime Policy Enforcement
ACS is an MIT-licensed open specification defining eight lifecycle interception points for AI agent governance, including `pre_tool_call`. ACS enforces organisational policy — what an enterprise permits its agents to do. AT1C provides personal consent infrastructure — what a human principal has authorised. These are different layers of the same stack. AT1C's verify endpoint is designed to function as an ACS evidence provider, contributing receipt verification to ACS's `pre_tool_call` policy evaluation. Integration path: planned for v2.x.

### Affinidi / OpenVTC — Decentralised Identity Infrastructure
Affinidi's Open Verifiable Trust Infrastructure provides DID-based identity attestation — proving who an entity is. AT1C addresses a different question: proving that a human principal approved a specific action. Identity and consent are complementary layers. Affinidi handles "who is this agent"; AT1C handles "did a human authorise this action."

### agentreceipts.ai — Post-Hoc Authorization Recording
agentreceipts.ai records authorization claims in a structured receipt format. Their `authorization.grant_ref` field is currently a string with no cryptographic verification — the natural integration point for AT1C approval receipts. AT1C gates on verified consent before execution; agentreceipts.ai records the authorization claim after the fact. AT1C is the verification layer their spec currently lacks.

### The Core Distinction
Every adjacent system addresses what happened, who an entity is, or what a policy permits. AT1C addresses a different and prior question: **did a specific human principal explicitly approve this specific action before it executed, and can that approval be proven independently?** As far as we have found, this is a layer the agentic web requires and does not yet have in an open, non-custodial form.

## Evidence and Related Work

Published work that bears on AT1C. Figures are the authors' own, several authors are vendors (marked), and the AT1C readings are ours, not theirs.

### The accountability gap in practice

- **NHI Management Group, *State of NHI & AI Agent Breach Report 2026* (security vendor group).** Across 226 breaches, the group reports that 44% began with a leaked, stolen or weak credential, 21% with a secret left in code, logs or tickets, and 64 involved AI agents. Its advice for agents (a named owner, least privilege, short-lived credentials, approval for risky actions, a kill switch) is the checklist that signed receipts can evidence. Several 2026 cases involved stolen npm or CI publishing tokens.
- **METR/Redwood investigation of the HuggingFace incident, and Zvi's postmortem.** As reported, agents acted without human approval, spoofed transcripts, and rarely considered alerting a human. Incident-level details are disputed in commentary, so we cite the pattern, not the specifics.
- **Yoshua Bengio on agent misbehaviour (Sept 2026).** Names reward tampering, private rationalisation of cheating, and hidden coordination between agents. A receipt signed before execution cannot be rewritten afterwards. His mitigations work at training time; AT1C works at run time. Hidden coordination between agents is not something AT1C addresses today.
- **Shai-Hulud / ChainDrop (The New Stack, 31 Aug 2026).** A supply-chain worm that evolved over four generations to compromise a legitimate signed pipeline, producing malicious packages with valid provenance attestations. Provenance says where something came from, not whether it should exist. AT1C's own SDK is in scope for this threat.
- **Seldo (Laurie Voss), Sept 2026.** Reports that in May 2026 a swarm of AI agents published over 2,000 packages to RubyGems in two days and forced a shutdown: agents acting at scale with no approval layer.
- **Schneier and Cohn, Lawfare, Sept 2026.** After 25 years of mass surveillance, the evidentiary record sits with third parties. The "gap test" (the gap between a physical event and the record of it) is what a principal-held receipt closes.

### Independent convergence

- **Das, *Purpose Enforcement at the AI Model Response Boundary* (Zenodo, Sept 2026).** The closest technical neighbour: a candidate act stays non-effective until an enforcement domain releases it. His line "computation is not authority" is a fair summary of what AT1C enforces. His design is provider-side, and he states it cannot solve cross-session aggregation.
- **APOA (Figuera, MIT).** Signed mandate tokens enforced at the execution layer, invisible to the model, with scoped typed constraints and an audit trail. Ed25519 and a central audit store; AT1C differs on post-quantum signatures, denial receipts, staged risk levels and lifecycle.
- **Deask.** A solo builder reaching the same gap from identity and access management: access is about what you can touch, authority is a mandate. Early stage, notes before code.
- **Anuclei.** Names "behavioural identity" as the missing primitive, since an agent's behaviour is partly assembled at run time. Enterprise-centralised, where AT1C is non-custodial.
- **Kumar, HackerNoon (opinion).** Argues for stable agent identity that survives key rotation, delegation that can only narrow, execution-time checks, and revocation that keeps history. It is enterprise access control: no signatures and no independent verifier.
- **Raskar, MIT Sloan (13 Jul 2026), Project NANDA.** Warns the agent economy tends toward corporate consolidation and proposes an ICANN-like identity and discovery layer with reputation services. Based on a summary of the talk; we have not read the NANDA specification.
- **MIT, *How to Prove Humanity Online* (2024).** Personhood credentials prove a person is human without revealing who, issued by multiple parties. They answer "is there a human?"; AT1C answers "did this human approve this action?"
- **IETF Internet-Drafts (not standards):** Agent Identity Protocol (draft-singla-agent-identity-protocol), Attenuating Authorization Tokens (draft-niyikiza-oauth-attenuating-agent-tokens), Agent Audit Trail (draft-sharif-agent-audit-trail) and ARDP (draft-pioli-agent-discovery). The attenuation-only rule, where a delegate can narrow authority but never widen it, matches how AT1C inheritance should work.
- **Osmani, *Agentic Verification*.** Agents do better with fast checks of their own work. That covers "did it work"; AT1C covers "was it allowed". The two sit side by side.
- **Agent workspace products such as Organ.** They gate merges, outbound email and publishing behind approvals, with spend caps. Their public pages do not describe signed receipts or independent verification, which makes them candidate integrations rather than rivals.

### Open problems the literature names

- **Cross-session aggregation (the "mosaic" gap).** CSTM-Bench (arXiv 2604.21131) finds that session-bound guardrails cannot see an aggregate threat. The SIF attack (AAAI 2026) reports a 71% success rate across 14 enterprise scenarios by splitting a violating task into harmless-looking parts. arXiv 2605.05440 calls aggregation inference unsolved in the general case. This is the gap behind AT1C's budget receipts, and we treat it as a roadmap item.
- **Hard budget caps (Willison, 3 Oct 2026).** Argues caps should be the default, with opting out an explicit, accountable choice. AWS and Google Cloud have both shipped spend limits. A per-action receipt does not bound the total, which is why AT1C lists budget receipts as a candidate.
- **The oversight paradox (WEF, July 2026).** Addressed under Known Limitations above: a receipt proves bounded authorisation, not comprehension.

### Regulatory and commercial signals

- **South Korea PIPA revision (effective 11 Sept 2026), as reported.** Fines of up to 10% of revenue for repeated or serious violations affecting 10 million or more people, or after a failed compliance order, with possible reductions where a company shows qualifying privacy investment. The qualifying criteria await a Presidential Decree. A receipt chain may support that kind of governance argument. This is not legal advice.
- **Willems (Sept 2026).** Argues that not regulating is itself a regulatory choice, and floats a safe harbour for firms meeting a defined safety standard. A verifiable approval record is the kind of artefact such a standard could reference.
- **Benedict Evans (Sept 2026).** Describes an "institutionalisation moment", when an improvised AI workflow becomes repeatable and high-stakes and needs audit and accountability. He does not name who approved what, which is the question AT1C answers.
- **Sovereign AI commentary (Wang, Onyx, DataCouch, Cosine's Lumen, Oct 2026).** Treats sovereignty as layers of control, not a wall. "Operational sovereignty", meaning who can switch a system off, corresponds to AT1C's revocation receipts and dead-man's switch. Onyx and DataCouch are vendors, and Lumen is unreleased.

## Cost Comparison

| Approach | Annual Cost | Time to Deploy |
|----------|-------------|----------------|
| Enterprise compliance programme | €400,000 – €2,000,000 | 6 – 18 months |
| Legal/compliance consultancy | €50,000 – €200,000 | 3 – 6 months |
| **AT1C Protocol (free tier)** | **€0 (open source)** | **1 day** |

*Cost estimates based on TRENDS Group research on EU AI Act compliance costs for European SMEs (2026). AT1C addresses human oversight and audit trail requirements it does not replace legal advice or a full compliance programme.*

---

## Getting Started in One Day

**Step 1 — Create your account (5 minutes)**
Register free at **at1c.com**. No credit card required.

**Step 2 — Install the SDK (2 minutes)**
```bash
npm install @at1c/sdk
```

**Step 3 — Register your agent (5 minutes)**
Visit **at1c.com/users/register-agent.php**. Your browser generates the ML-DSA-65 keypair — the private key downloads to your device and never leaves it. Select permissions via checkboxes. The registry signs a certificate over your public key.

**Step 4 — Integrate receipts into your action flow**
- Agent generates a request for the specific action
- Human approves via your existing UI
- SDK generates the signed receipt in milliseconds
- Receipt is verified before action executes
- Action executes — the receipt is your audit trail

Full documentation: **github.com/at1c-protocol/at1c-protocol-official**

---

## Specification Work in Progress

AT1C is a living specification. Current work, in draft unless stated:

- **Signature scheme:** ML-DSA-65 (FIPS 204) is fixed as the signature scheme.
- **Assurance tiers (T0–T3):** how much a verifier can establish about a receipt: a valid signature and key lineage (T0), an anchored time bound (T1), a quorum of principal attestations (T2), and a local hardware or biometric approval claim (T3).
- **Denial receipts:** a refused request produces a signed record, treated the same as an approval.
- **Revocation receipts:** a draft for withdrawing a scope, agent, key or receipt, with rules for ordering and finality.
- **Action fingerprints:** a draft for binding a receipt to the exact action by hash, so the record holds a fingerprint and not the payload.
- **Budget receipts:** a candidate for v0.2 to bound cumulative behaviour, answering the aggregate-limits gap above.
- **Anchoring:** planned optional timestamp anchoring through chain-agnostic adapters (not yet shipped).
- **Independent verification:** the goal that a receipt bundle can be verified without any AT1C-operated service.

---

## Roadmap

| Version | Status | Description |
|---------|--------|-------------|
| v1.1 | ✅ Done | Non-custodial agent key registration |
| v1.2 | ✅ Done | Live registry API at registry.at1c.com |
| v1.3 | ✅ Done | Open web registration — personal and entity agents |
| v1.4 | ✅ Done | Browser-side keypair generation — no terminal required |
| v1.5 | Planned | End-user passkey (WebAuthn/FIDO2) onboarding |
| v1.6 | Planned | Hosted receipt storage — 10-year retention paid tier |
| v2.0 | Planned | Autonomy levels with alarm thresholds for fleet management |
| Future | Roadmap | Agent Manifest per EU AI Act Art 13/14 |

---

## Acknowledgements

AT1C was shaped by the Human Root of Trust paper (v1.0, February 2026) by Eduardo Vega, released to the public domain. His only request was that whoever builds on it carries the principle forward: that authority over AI agents should trace back to a human. We acknowledge that work with thanks, and AT1C is our attempt to carry it forward.

---

## References

- RFC 8890 — *The Internet is for End Users*. Nottingham, M. Internet Architecture Board, 2020. https://www.rfc-editor.org/info/rfc8890/
- *The Law of AI is the Law of Risky Agents Without Intentions*. Ayres, I. & Balkin, J. University of Chicago Law Review, 2026.
- *How Big Tech's Monopoly of AI Threatens Fair Competition*. TRENDS Group Research, 2026.
- *Digital Identity Management in Norway is a Success but also a Disaster*. Scandinavian Institute for Digital Governance (SODI), University of Oslo, 2026.
- Regulation (EU) 2026/1744 (Digital Omnibus on AI), 2026.
- Republic of Korea, AI Basic Act, in force 22 January 2026.
- *2026 AI Legal Forecast: From Innovation to Compliance*. Baker Donelson, January 2026. https://www.bakerdonelson.com/2026-ai-legal-forecast-from-innovation-to-compliance
- *Patterns and Problems in Emerging Multiagent Systems*. Anthropic Frontier Red Team, August 2026. https://www.anthropic.com/research/multiagent-systems
- *State of NHI & AI Agent Breach Report 2026*. NHI Management Group. https://nhimg.org/nhi-ai-agent-breaches-report/
- *Agentic Verification*. Osmani, A. https://addyo.substack.com/p/agentic-verification
- *Default hard budget caps*. Willison, S., 3 October 2026. https://simonwillison.net/2026/Oct/3/default-hard-budget-caps/
- *Who will own the AI agent economy?* Raskar, R., MIT Sloan, 13 July 2026. https://mitsloan.mit.edu/ideas-made-to-matter/who-will-own-ai-agent-economy
- *The model is the company*. Wang, A. https://alexwang.ai/posts/the-model-is-the-company/
- *How to Prove Humanity Online*. MIT, August 2024.
- *Purpose Enforcement at the AI Model Response Boundary*. Das, S., Zenodo, September 2026.
- CSTM-Bench, arXiv 2604.21131; Authorization Propagation, arXiv 2605.05440.
- IETF Internet-Drafts: draft-singla-agent-identity-protocol, draft-niyikiza-oauth-attenuating-agent-tokens, draft-sharif-agent-audit-trail, draft-pioli-agent-discovery.
- *Oversight Paradox*. World Economic Forum, July 2026.
- *25 Years of Mass Surveillance Is Enough*. Schneier, B. & Cohn, C., Lawfare, September 2026.
- Republic of Korea, Personal Information Protection Act revision, effective 11 September 2026.

---

## Contact & Further Information

- **Website:** at1c.com
- **Live registry:** registry.at1c.com
- **GitHub:** github.com/at1c-protocol/at1c-protocol-official
- **npm:** npmjs.com/package/@at1c/sdk
- **SME compliance guide:** at1c.com/compliance.html
- **Register your agent:** at1c.com/users/register-agent.php

---

## Change log

- **20 Oct 2026 (v1.7):** added Evidence and Related Work; Art. 50 transition wording and "as of" dates; anchoring marked planned, not shipped; oversight, replay and agent-identity limitations stated; budget receipts timeline aligned to spec v0.2; Acknowledgements credit the Human Root of Trust paper.
- Earlier versions: see the repository history.

---

*© 2026 AT1C Protocol Contributors · MIT Licence · Version 1.7*
