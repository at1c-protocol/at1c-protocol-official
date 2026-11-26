# AT1C Repository Receipts — no human-signed receipt, no merge (DRAFT)

**Status:** Draft. Built in `@at1c/sdk` 3.1 (`repo.ts`, `repoGate.ts`, `repoDisplay.ts`). The audit command (section 7) is not built yet.

Builds on `receipt.md` (format 2) and `gate.md`. Uses format 2 unchanged: no new receipt fields. Where this file and `receipt.md` disagree on the receipt itself, `receipt.md` wins.

Normative words (MUST, SHOULD) follow RFC 2119. **[standard]** = established pattern. **[AT1C choice]** = judgment call, not externally reviewed.

## 1. What it does

AI agents now write code. A repository merge gate refuses to move a protected branch unless a valid format 2 receipt, signed by a human, approves exactly the files that would land. Change one byte after approval and the merge is refused. It works with any git repository and any host, because it uses only git itself.

## 2. The flow

1. The agent does its work on its own branch.
2. The finished files are read from git (section 4) and shown to the human as a readable list (section 5). The human approves or denies.
3. The bundle (receipt and attachment) is saved as **one new file**, `.at1c/receipts/<receipt_id>.json`, committed on top of the agent's work. The record travels inside the change and is kept by the developer in the repository, not by any service. [AT1C choice]
4. The gate rebuilds the file list from git itself, checks the receipt, and only then moves the branch forward. **Fast-forward only:** what lands is byte for byte what was approved. [AT1C choice]

`registry.at1c.com`, or any other verifier, MAY be used as an optional second opinion. It is never the store.

## 3. Receipt fields (format 2, how they are filled)

| Field | Value for a repository merge |
|---|---|
| `action.type` | `repo.merge` |
| `action.resource` | plain repository name and target branch, e.g. `at1c-protocol-official:main`. Both come from the gate's own settings and the request, never a URL (`receipt.md` section 2.3) |
| `action.class` | `compensable` (a merge can be reverted). A verifier MAY treat it as stricter, never looser |
| `audience` | the gate's own name, from its own settings (`gate.md` section 4, item 3a) |
| `actor.agent_id` | the agent that asks; MUST match the agent named in the merge request |
| `action.payload_hash` | as `receipt.md` section 2.1: SHA-256 over JCS of `{ payload, salt }` |
| `action.description` | a plain count written by the agent, e.g. "3 files added or changed, 0 removed". Shown, but labelled as the agent's claim and not trusted |

## 4. The payload: "the finished files"

```json
{
  "kind": "at1c.repo.files.v1",
  "base": "<commit id of the target branch tip>",
  "files":   [ { "path": "src/a.ts", "mode": "100644", "sha256": "<64 hex>" } ],
  "deleted": [ "old/b.ts" ]
}
```

Rules:

1. **Bytes.** Each file's bytes exactly as git stores them (the blob, after git's own line-ending rules), hashed with SHA-256. Not git's own object ID, which is SHA-1 in most repositories. [AT1C choice; SHA-256 is standard]
2. **Which files.** Every path that differs between the target branch tip (`base`) and the commit to be landed: added or changed in `files`, removed in `deleted`. A rename counts as a removal plus an addition.
3. **Order.** `files` and `deleted` sorted by path in UTF-8 byte order. JCS (RFC 8785) fixes the rest. [standard]
4. **Mode.** `100644` normal, `100755` executable, `120000` shortcut (symlink; the link text is hashed). A permission change counts as a change.
5. **Left out.** The receipts folder `.at1c/receipts/` is excluded from its own fingerprint.
6. **Refused.** Submodules; paths that are not valid UTF-8; absolute paths or paths with empty, `.` or `..` parts; the same path twice; a change that touches nothing outside the receipts folder (a receipt for nothing is not issued).
7. **Base is a label.** `base` records where the change was made. Because the gate is fast-forward only (section 6), it also pins the starting point: a receipt made on an older `base` cannot land.

## 5. What the human sees

The Approver, not the agent, renders the prompt, from the canonical copy that is signed. [AT1C choice; closes threat T7 for merges]

- Every path is shown by name, with executables and shortcuts marked, removals listed, and the base commit shown, followed by a reminder to read the diff.
- Paths are quoted; control, invisible and direction-changing characters are written as `\u{XXXX}`, so a file name cannot hide, reorder or fake text on screen.
- A `repo.merge` payload with any field beyond those in section 4 is refused, because an extra field would be signed but not shown.
- **Too big to read is refused, not shown blind.** A change of more than **100 files** (added, changed and removed together), or a list longer than **20,000 characters**, is refused before the human is asked. The agent MUST split it into smaller changes. [AT1C choice; owner decision 26 Nov 2026. The limits are adjustable]

## 6. The gate check (normative order)

The gate MUST run on the host's own **bare** copy of the repository, as an OS user the agent is not (section 8).

1. **Request shape.** The repository name comes from the gate's settings. The branch name MUST be a valid git branch name and MUST NOT start with `-`. Otherwise refuse (`BAD_BRANCH`). A non-bare copy is refused (`NOT_BARE`).
2. **Read the change from git.** From the current branch tip to the requested commit, using git's raw output. The agent's description of the change is never used.
3. **Fast-forward only.** The branch tip MUST be an ancestor of the requested commit (`NOT_FAST_FORWARD`).
4. **Exactly one new receipt.** In `.at1c/receipts/` the change MUST add exactly one file and MUST NOT edit or remove any existing one (`NO_RECEIPT`, `MORE_THAN_ONE_RECEIPT`, `RECEIPT_CHANGED`). The file MUST be named `<receipt_id>.json` for the receipt inside it, be a normal file (mode `100644`), be valid JSON and be at most 4 MiB (`BAD_RECEIPT_FILE`).
5. **Rebuild and compare.** Build the payload (section 4) from git, leaving the receipts folder out. More than 100 files is refused again here (`TOO_MANY_FILES`), so a lax Approver cannot let a big change through. It MUST be identical (JCS) to the attachment's payload (`PAYLOAD_MISMATCH`). A bundle without an attachment is refused (`NO_ATTACHMENT`).
6. **Format 2 checks.** The standard Gate verifies the receipt (`receipt.md` section 5): signature, pinned key, gate name, agent, `repo.merge`, resource, fingerprint, expiry, revocation, and single use. The nonce is checked and recorded last, in the gate's own store, not in the repository. Fail closed if the store, revocation list or pinned keys are unavailable (`gate.md` section 4).
7. **Move the branch atomically.** Compare-and-swap: the branch moves to the requested commit only if it still points where step 2 found it. If it moved in between, refuse (`BRANCH_MOVED`).

On any refusal the branch is not moved. A receipt that passed step 6 is spent even if step 7 then fails: the agent rebuilds and asks the human again (`gate.md` section 4, item 4). Any unexpected error refuses (`GATE_ERROR`).

The gate checks only the new receipt, never the old ones in the folder. That is the audit command's job.

## 7. Audit command (not built yet)

Anyone can run it at any time over `.at1c/receipts/`. For each receipt it SHOULD check the signature, that the key was pinned and valid at `issued_at`, and that the fingerprint matches the merge that receipt landed. It skips expiry and replay, because old receipts are expired and spent by design. If a key has since been revoked, it MUST say so, never silently pass.

## 8. Honest limits

- **Enforcing only if the agent cannot get round it.** The gate protects a branch only if the agent has no other way to push to it (`gate.md` sections 3 and 7). A local git hook is advisory: the agent can skip it.
- **The approver key must also be out of the agent's reach** (`gate.md` section 6), or this protects against mistakes only.
- **Names and fingerprints, not contents.** The human approves file names and a fingerprint of their bytes. They SHOULD read the diff before approving.
- **Finished files, not history.** Commit messages, authors and in-between commits are not approved; only the files that land are.
- **Lookalike letters** from other alphabets (Cyrillic "а" for Latin "a") in file names are not detected yet.
- **Expiry.** A receipt lives 5 minutes by default in the SDK and at most 24 hours (`receipt.md` section 2), so approve close to the merge.
- **A pressed button is not a proven person** (threat T21): an operating-system AI agent with access to the approval screen could approve. A physical approval act at level 3 is the planned answer.

## 9. Not yet decided

- Where the first enforcing gate runs (which host).
- A packaged plug-in for agents (for example MCP): its name and npm location.
