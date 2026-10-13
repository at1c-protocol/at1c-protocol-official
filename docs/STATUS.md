# AT1C status (read this first in any new chat)

Last updated: 13 Oct 2026. One-line focus: **AT1C is a human-signed, single-use, scope-bound approval receipt that a gate verifies before an action runs. Any chain is optional.**

## Source of truth
- `spec/receipt.md` is the canonical receipt (format version `"1"`). If any other doc disagrees, it loses.
- `spec/keys.md` is the key trust model (verifier-pinned keys, validity window judged by the verifier's clock).
- `spec/test-vectors/receipt-v1.json` is 22 conformance vectors. Any verifier must reproduce every `expect`.
- Reference verifiers: `tools/at1c_ref.py` (Python, checks all vectors) and `packages/sdk/src/verify.ts` (SDK, tests in `packages/sdk/tests/`).
- Versioning: only the `version` field in a receipt is the protocol version. "v1.4", "v1.6", "v0.1" in old docs are document revisions.

## Done
- Canonical spec, key model, 22 vectors; SDK verifier passes all of them (merged to main).
- FIPS 203 corrected to FIPS 204 (ML-DSA) in README, docs/README, scripts.
- Stray pasted text that broke `generate-agent-keys.js` and `src/crypto/signAgentAction.js` removed.
- Old `verifyReceipt` marked deprecated and INSECURE (it trusts the key inside the receipt).
- `server.js` rewritten to use `verifyReceiptV1` and a trusted-keys file (see Deploy below).

## Known problems, in priority order
1. DONE 12 Oct 2026: live `/v1/verify` on registry.at1c.com runs the new server.js (trusted keys, receipt v1). Old files kept there as `server.OLD-insecure.js` and `package.OLD.json`; delete them once happy.
2. DONE 13 Oct 2026: registry key rotated to ML-DSA-65 (registry-1); agent certificates v1 done (spec/agent-certificate.md, 21 vectors, register-agent.js rewritten). Ed25519 key recorded as retired in REGISTRY_KEYS.md.
3. `packages/sdk/src/client.ts` (`AT1C.enforce`) still uses the old flat receipt, generates a new key in memory each start, and verifies with the insecure verifier. Needs a rewrite onto receipt v1.
4. Docs still on old schemas: `docs/protocol.md` ch.5, `docs/receipts.md` (retire), `docs/verification.md`, `docs/scopes.md`, `docs/signatures.md` (stub), whitepaper. Regenerate from `spec/`, one term list at a time, never a blanket replace.
5. Licence mismatch: root `package.json` ISC, `packages/sdk/package.json` MIT, homepage says MIT.
6. Algorand / x402 should move out of headline docs into an adapters folder (optional chain adapter only).
7. Legacy code to retire: root `verify.js`, `src/crypto/verifyReceipt.js`.
8. Canonical acronym is "The Human Authorisation Layer"; whitepaper and SDK header use another expansion. HRT credit missing from whitepaper references.
9. Not yet written: threat model, reference gate demo, key rotation feed, cumulative/budget limits (spec section 7 lists the gaps).
10. Secrets tidy-up: encrypted backups of mora-1 and registry-1 (none yet); remove plaintext files that sit beside .gpg copies once the .gpg ones are proven to decrypt; chmod 600 retired-registry-key.json.
11. Delete the old files in the cPanel app folder: server.OLD-insecure.js and package.OLD.json.

## Run the checks
- Spec vectors, Python: `python3 tools/run_vectors.py spec/test-vectors/receipt-v1.json` (needs `cryptography` >= 48)
- SDK + server tests: `cd packages/sdk && npx vitest run`
- Type check: `cd packages/sdk && npx tsc --noEmit -p tsconfig.sdk.json`

## Deploy the verify endpoint (cPanel, registry.at1c.com)
1. On your computer: `cd packages/sdk && npx tsc -p tsconfig.sdk.json` (writes `dist/`).
2. Make your approver key: `node tools/new-authority-key.mjs "did:web:at1c.com#<yourname>-1"`. The secret goes to `~/at1c-secrets`. Copy the printed public record into a new `trusted-keys.json` (see `trusted-keys.example.json`).
3. Upload `server.js`, `trusted-keys.json`, `packages/sdk/dist/` and its dependencies to the registry app. Keep the same relative paths, or set `AT1C_SDK_VERIFY` and `AT1C_TRUSTED_KEYS`. Restart the Node app. (Exact cPanel Node steps are not recorded here.)
4. Check: `curl https://registry.at1c.com/health` shows `"receipt_format":"1"`, and a forged receipt returns `UNKNOWN_AUTHORITY`.

## Working rules
- One change at a time; branch, test, pull request, merge.
- Run the vectors before and after any change touching receipts or verification.
- Mark claims as confirmed or inferred. Say what is a standard pattern and what is an AT1C judgment call.

## Hosting notes
- Live verify app: cPanel > Setup Node.js App; root /home/titanic1/registry.at1c.com, startup file server.js, Node 20.20.2, runs under Passenger.
- Passenger loads server.js itself, so server.js must call listen when PhusionPassenger is defined (it does now). Without this the app hangs.
- Live folder holds: server.js, trusted-keys.json, package.json, packages/sdk/dist/src/verify.js, agents.json, index.html.
- Approver key authority did:web:at1c.com#mora-1; secret seed in ~/at1c-secrets (back it up, never commit). Valid until 12 Oct 2027.
- Open: packages/sdk/dist/ is tracked in Git but is build output. Decide whether to untrack and gitignore it.
