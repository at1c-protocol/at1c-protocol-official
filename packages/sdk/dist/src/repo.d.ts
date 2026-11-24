export declare const REPO_PAYLOAD_KIND = "at1c.repo.files.v1";
/** Receipts kept in the repo live here. This folder is left out of its own fingerprint. */
export declare const RECEIPTS_DIR = ".at1c/receipts/";
export interface RepoFileEntry {
    path: string;
    mode: '100644' | '100755' | '120000';
    sha256: string;
}
export interface RepoPayload {
    kind: typeof REPO_PAYLOAD_KIND;
    /** Commit id of the target branch tip. A label: it says where the change was made, it is not what is approved. */
    base: string;
    /** Every added or changed file, with its final bytes' SHA-256, sorted by path (UTF-8 byte order). */
    files: RepoFileEntry[];
    /** Every removed path, sorted the same way. */
    deleted: string[];
}
/** One change as the gate sees it: a file with its final bytes (as git stores them), or a removed path. */
export type RepoChange = {
    path: string;
    mode: string;
    bytes: Uint8Array;
} | {
    path: string;
    deleted: true;
};
export type RepoErrorCode = 'BAD_BASE' | 'BAD_PATH' | 'DUPLICATE_PATH' | 'BAD_MODE' | 'SUBMODULE' | 'NO_CHANGES' | 'BAD_REF' | 'GIT_FAILED';
export declare class RepoPayloadError extends Error {
    readonly code: RepoErrorCode;
    constructor(code: RepoErrorCode, message: string);
}
/**
 * Build the payload from a list of changes. Pure: no git, no disk.
 * Refuses: bad paths, the same path twice, submodules, unknown file modes, and a change that touches nothing
 * (after the receipts folder is left out) — a receipt for nothing is not issued.
 */
export declare function makeRepoPayload(base: string, changes: RepoChange[]): RepoPayload;
/**
 * Read the changes between the target branch tip (`base`) and the merge result (`result`) from git,
 * with each file's bytes exactly as git stores them (the blob, after git's own line-ending rules).
 * Renames are reported as a removal plus an addition. Paths that are not valid UTF-8 are refused.
 */
export declare function readRepoChanges(repoDir: string, base: string, result: string): {
    base: string;
    changes: RepoChange[];
};
/** The whole job in one call: the payload for merging `result` onto `base`. */
export declare function repoPayloadFor(repoDir: string, base: string, result: string): RepoPayload;
//# sourceMappingURL=repo.d.ts.map