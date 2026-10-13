# AT1C status (read this first in any new chat)

Last updated: 13 Oct 2026. One-line focus: **AT1C is a human-signed, single-use, scope-bound approval receipt that a gate verifies before an action runs. Any chain is optional.**

## Source of truth
- `spec/receipt.md` is the canonical receipt (format version `"1"`). If any other doc disagrees, it loses.
- `spec/keys.md` is the key trust model (verifier-pinned keys, validity window judged by the verifier's clock).
- `spec/agent-certificate.md` is the registry-signed agent certificate (format `"1"`). Permissions are a ceiling, never a grant.
- `spec/gate.md` is the gate conformance draft: credential isolation, enforcing vs advisory gates. The SDK client is an ADVISORY gate.
- `spec/threat-model.md` is the draft threat model (adversaries, 20 threats, status of each, prioritised next mitigations).
- `spec/test-vectors/receipt-v1.json` (22) and `agent-certificate-v1.json` (21) are conformance vectors. Any verifier must reproduce every `expect`.
- Reference verifiers: `packages/sdk/src/verify.ts` and `agentCert.ts` (SDK, tests in `packages/sdk/tests/`). The Python references (`tools/at1c_ref.py` etc.) are NOT committed yet, see problem 12.
- Versioning: only the `version` field in a receipt is the protocol version. "v1.4", "v1.6", "v0.1" in old docs are document revisions.

## Security levels (what protects against what)
1. **Level 1, dev mode: DONE.** `AT1C` client = `LocalKeyApprover` + `Gate`. Approver key is in the same OS account as the agent. Stops mistakes and bugs, NOT a hijacked agent (it can read the key and self-approve).
2. **Level 2, second OS account: NOT BUILT.** Approver daemon as a separate user, Unix socket, daemon renders what is signed, prompt on a channel the agent cannot answer. Design is inferred, not tested. Needs sudo, a systemd unit, SELinux contexts on Fedora.
3. **Level 3, separate device: NOT BUILT.** Hardware ML-DSA-65 support is unverified: iOS 26 `SecureEnclave.MLDSA65` reported by ONE developer blog on one iPhone 15 Pro; Android 17 Keystore ML-DSA announced with no release date; hardware tokens unknown. TOTP is not suitable (shared secret, signs nothing about the action).
- Premise to remember: the Gate protects only actions routed through it. An agent with a raw shell or direct network access can bypass it.

## Done
- Canonical spec, key model, 22 vectors; SDK verifier passes all of them.
- FIPS 203 corrected to FIPS 204 (ML-DSA) in README, docs/README, scripts.
- Old `verifyReceipt` marked deprecated and INSECURE (it trusts the key inside the receipt).
- Live `/v1/verify` on registry.at1c.com runs the new `server.js` (12 Oct).
- Registry key rotated to ML-DSA-65 (registry-1); agent certificates v1 (spec, 21 vectors, `register-agent.js` rewritten) (13 Oct).
- Level 1 `Approver` and `Gate` (`src/approver.ts`, `src/gate.ts`, durable atomic nonce store, fail closed) (13 Oct).
- `client.ts` rewritten on Approver + Gate. BREAKING: `new AT1C({authority})`; `enforce()` needs `agentId`, `action`, `resource`, `payload`; `checkReceipt` removed; `getPublicKey` returns base64url. A broken `policies.json` is an error; an allow policy does not skip the human (13 Oct).
- SDK README and `examples/receipts-viewer.ts` rewritten for format 1; unverified EU AI Act compliance claims removed (13 Oct).
- Threat model draft (`spec/threat-model.md`) and gate spec (`spec/gate.md`, credential isolation) (13 Oct).
- 112 SDK tests passing.

## Known problems, in priority order
1. DONE: live verify endpoint on new server.js. (Delete old cPanel files, see 11.)
2. DONE: registry key rotation and agent certificates.
3. DONE: `client.ts` rewrite. NOT YET RUN against a real key: smoke-test `examples/ai-agent-demo` with the mora-1 key (key file name pattern `<sanitised authority>.mldsa65.json` is inferred from the folder listing).
4. Docs still on old schemas: `docs/protocol.md` ch.5, `docs/receipts.md` (retire), `docs/verification.md`, `docs/scopes.md`, `docs/signatures.md` (stub), whitepaper, plus the other docs that mention `AT1C`/`enforce`. Regenerate from `spec/`, one term list at a time, never a blanket replace.
5. Licence mismatch: root `package.json` ISC, `packages/sdk/package.json` MIT, homepage and SDK README say MIT.
6. Algorand / x402 should move out of headline docs into an adapters folder (optional chain adapter only).
7. Legacy code to retire: root `verify.js`, `src/crypto/verifyReceipt.js`, `src/crypto/enforce.js`, `src/crypto/signAgentAction.js` (check what uses them first).
8. Canonical acronym: SDK header and README now say "The Human Authorisation Layer"; whitepaper uses another expansion. Decide, then align. HRT credit missing from whitepaper references.
9. Threat model DRAFT written: `spec/threat-model.md` (20 threats, prioritised mitigations; credential-isolation rule now written in `spec/gate.md`; next is an enforcing reference gate, item 17). Not yet written: reference gate demo, shared revocation feed, cumulative/budget limits (spec section 7 lists the gaps).
10. Secrets tidy-up: encrypted backups of mora-1 and registry-1 (none yet); remove plaintext files that sit beside .gpg copies once the .gpg ones are proven to decrypt; chmod 600 retired-registry-key.json.
11. Delete the old files in the cPanel app folder: server.OLD-insecure.js and package.OLD.json.
12. Python reference files never committed: `tools/at1c_ref.py`, `gen_vectors.py`, `run_vectors.py`. `tools/at1c_cert_ref.py` imports `at1c_ref` and cannot run from the repo; `spec/receipt.md` section 8 names them. Add them or fix the references.
13. Spec rule to add: **no gate may require device or platform attestation** to accept a receipt (a gate may record it, never require it). Software and hardware user-generated keys are both first-class. Also unspecified: multiple keys per authority and recovery (a single device-bound key is a lock-in and loss risk). Context: passkey-attestation lock-in concerns (Apple/Google).
14. Decide level 3 algorithm policy after testing a real device: stay ML-DSA-65 only (software key if no hardware), allow hybrid (classical + ML-DSA, both required), or classical-only (not recommended; breaks the post-quantum promise). Not decided.
15. Unverified claims to confirm: `@at1c/sdk` is published on npm; whether `npm run demo -- --html/--pdf` scripts exist (removed from the README until confirmed); terminal display does not filter lookalike or bidirectional Unicode.
16. Decide whether to untrack `packages/sdk/dist/` (build output tracked in Git; `tsc` rebuilds modify it). Never `git add` it; add explicit file paths only.
17. Build an ENFORCING reference gate (a separate process that holds the credential; the agent has no path around it). Until then every gate in this repo is advisory. It only matters together with a level 2 or 3 approver (see `spec/gate.md` section 6).

## Run the checks
- Spec vectors, Python: `python3 tools/run_vectors.py spec/test-vectors/receipt-v1.json` (needs `cryptography` >= 48; files not committed yet, see 12)
- SDK + server tests: `cd packages/sdk && npx vitest run`
- Type check: `cd packages/sdk && npx tsc --noEmit -p tsconfig.sdk.json`

## Deploy the verify endpoint (cPanel, registry.at1c.com)
1. On your computer: `cd packages/sdk && npx tsc -p tsconfig.sdk.json` (writes `dist/`).
2. Make your approver key: `node tools/new-authority-key.mjs "did:web:at1c.com#<yourname>-1"`. The secret goes to `~/at1c-secrets`. Copy the printed public record into a new `trusted-keys.json` (see `trusted-keys.example.json`).
3. Upload `server.js`, `trusted-keys.json`, `packages/sdk/dist/` and its dependencies to the registry app. Keep the same relative paths, or set `AT1C_SDK_VERIFY` and `AT1C_TRUSTED_KEYS`. Restart the Node app. (Exact cPanel Node steps are not recorded here.)
4. Check: `curl https://registry.at1c.com/health` shows `"receipt_format":"1"`, and a forged receipt returns `UNKNOWN_AUTHORITY`.

## Working rules
- One change at a time; branch, test, pull request, merge. The user reads slowly: one step per message, short, exact commands, say what output to paste back.
- Use single quotes around git commit messages (a `!` inside double quotes triggers bash history expansion).
- Run the vectors before and after any change touching receipts or verification.
- Mark claims as confirmed or inferred. Say what is a standard pattern and what is an AT1C judgment call.

## Hosting notes
- Live verify app: cPanel > Setup Node.js App; root /home/titanic1/registry.at1c.com, startup file server.js, Node 20.20.2, runs under Passenger.
- Passenger loads server.js itself, so server.js must call listen when PhusionPassenger is defined (it does now). Without this the app hangs.
- Live folder holds: server.js, trusted-keys.json, package.json, packages/sdk/dist/src/verify.js, agents.json, index.html.
- Approver key authority did:web:at1c.com#mora-1; secret seed in ~/at1c-secrets (back it up, never commit). Valid until 12 Oct 2027.
