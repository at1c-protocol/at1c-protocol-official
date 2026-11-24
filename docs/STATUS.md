# AT1C: what works today, and what's coming

Last updated: 24 November 2026.

AT1C is a human-signed, single-use, scope-bound approval receipt that a gate checks before an AI agent's action runs. No receipt, no action. Any blockchain is optional.

## What works today

- **Receipt format 2** (`spec/receipt.md`): post-quantum signatures (ML-DSA-65, FIPS 204) with their own signing label, a salted payload fingerprint, a named audience, single use, and expiry within 24 hours. Denials are signed receipts too.
- **The SDK, `@at1c/sdk` 3.0** (`packages/sdk`): an Approver that signs, a Gate that verifies before anything runs, a durable single-use store that fails closed, and agent certificates. 176 tests, plus conformance vectors (`spec/test-vectors/`) checked against an independent Python reference (`tools/at1c_ref.py`).
- **No device permission needed.** Acceptance depends only on the receipt and the keys the verifier chose to trust. No gate may require device attestation from Apple, Google or anyone else (`spec/gate.md` section 8). Any phone, laptop or operating system can take part.
- **A public second opinion**: anyone can ask `registry.at1c.com` whether a receipt is valid. It checks; it never stores, and nothing depends on it.
- **New: repository receipts, step 1.** The SDK can build the exact "finished files" fingerprint a human approves before a code merge (`packages/sdk/src/repo.ts`).

## Protection that grows with you

AT1C is built as a ladder. The Gate stays the same at every level.

1. **Level 1, dev mode: available now.** The Approver runs in the same OS account as the agent. It stops mistakes and bugs: nothing runs through the Gate without a receipt signed for that exact action and payload.
2. **Level 2, separate OS account: coming.** The Approver moves to its own account, so the agent cannot reach the signing key.
3. **Level 3, separate device: coming.** The Approver moves to a device of the user's choice.

## Coming next

- Repository receipts: the merge gate and an audit command for past receipts ("no human-signed receipt, no merge", for any git host).
- An enforcing reference gate: a separate process that holds the credential, so the agent has no way around it.
- Proof of time for higher-risk actions (Rule 4, planned).
- Limits on repeated actions, an identity log, more than one key per person, and key recovery.

## Good to know

- Today every gate in this repo is advisory: it protects actions routed through it. Protection against a hijacked agent needs an enforcing gate together with level 2 or 3 (`spec/gate.md` sections 3 and 6). Until then, level 1 protects against mistakes, not a hijacked agent.
- `spec/` is the source of truth. If another document disagrees with it, `spec/` wins. Some older documents in `docs/` still describe earlier formats and are being brought up to date.

## Run the checks

- SDK tests: `cd packages/sdk && npm test`
- Type check: `cd packages/sdk && npx tsc --noEmit -p tsconfig.sdk.json`
