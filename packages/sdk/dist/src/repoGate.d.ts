import { type VerifyCode } from './verify';
import type { Gate } from './gate';
import type { ApprovalRequest } from './approver';
import { type RepoErrorCode, type RepoPayload } from './repo';
export declare const REPO_MERGE_TYPE = "repo.merge";
export type RepoGateCode = VerifyCode | RepoErrorCode | 'GATE_ERROR' | 'NO_ATTACHMENT' | 'NOT_BARE' | 'BAD_BRANCH' | 'NOT_FAST_FORWARD' | 'NO_RECEIPT' | 'MORE_THAN_ONE_RECEIPT' | 'RECEIPT_CHANGED' | 'BAD_RECEIPT_FILE' | 'PAYLOAD_MISMATCH' | 'BRANCH_MOVED';
export type RepoGateResult = {
    status: 'merged';
    receipt_id: string;
    from: string;
    to: string;
} | {
    status: 'refused';
    code: RepoGateCode;
    detail?: string;
};
export interface RepoGateOptions {
    /** Path to the gate's own BARE copy of the repository (the one the host serves). */
    repoDir: string;
    /** Plain repository name, from the gate's settings, e.g. "at1c-protocol-official". Never from the caller. */
    repo: string;
    /** The existing format 2 Gate: its audience, pinned keys, nonce store and revocation list. */
    gate: Gate;
}
export interface MergeRequest {
    /** Target branch name, e.g. "main". */
    branch: string;
    /** The commit to fast-forward the branch to: the agent's work plus the one new receipt file on top. */
    source: string;
    /** The agent that asks. Must match the receipt's actor.agent_id. */
    agent_id: string;
}
/**
 * Merge `source` into `branch` only if exactly one new receipt in .at1c/receipts/ approves exactly the finished
 * files that would land. Never moves the branch on any failure. A receipt that verifies is spent even if the final
 * branch move then fails (spec/gate.md section 4.4): the agent must rebuild and ask the human again.
 */
export declare function mergeWithReceipt(o: RepoGateOptions, req: MergeRequest): Promise<RepoGateResult>;
/** The approval request for a merge, ready for any Approver. `payload` comes from repoPayloadFor(base, agent's work).
 *  The description is a plain count, labelled to the human as the agent's claim; the payload itself is what is signed. */
export declare function repoApprovalRequest(o: {
    audience: string;
    repo: string;
    branch: string;
    agent_id: string;
    agent_public_key: string;
    payload: RepoPayload;
}): ApprovalRequest;
/** Where the bundle goes in the change: .at1c/receipts/<receipt_id>.json */
export declare const receiptPathFor: (receipt_id: string) => string;
//# sourceMappingURL=repoGate.d.ts.map