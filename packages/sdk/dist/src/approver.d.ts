import { type Attachment, type KeyRecord } from './verify';
export type ActionClass = 'compensable' | 'retriable' | 'irreversible';
export interface ApprovalRequest {
    audience: string;
    agent_id: string;
    agent_public_key: string;
    type: string;
    class: ActionClass;
    resource: string;
    payload: unknown;
    scope_ref?: string;
    description?: string;
}
export interface ReceiptV2 {
    version: '2';
    receipt_id: string;
    decision: 'approved' | 'denied';
    issued_at: string;
    expires_at: string;
    audience: string;
    actor: {
        agent_id: string;
        public_key: string;
    };
    action: {
        type: string;
        class: ActionClass;
        resource: string;
        payload_hash: string;
        scope_ref?: string;
        description?: string;
    };
    display_digest: string;
    approval: {
        authority: string;
        alg: 'ML-DSA-65';
        signature: string;
    };
    nonce: string;
}
/** What an Approver returns and a Gate takes: the signed receipt plus the attachment it fingerprints.
 *  The two travel together ("no travel without salt"): a Gate refuses a receipt without its attachment.
 *  The bundle holds the payload in plain view. To show a receipt to an outsider, or to time-stamp it,
 *  hand over `receiptOnly(bundle)`: the salted fingerprint reveals nothing about the payload. */
export interface Bundle {
    receipt: ReceiptV2;
    attachment: Attachment;
}
/** The shareable half of a bundle: the signed receipt without the payload or the salt. */
export declare const receiptOnly: (bundle: Bundle) => ReceiptV2;
/** Shows `text` to the human and returns their decision. The Approver, not the agent, produces `text`. */
export type Prompt = (text: string) => Promise<boolean>;
/** Anything that can turn a request into a signed receipt. Level 1, 2 and 3 all implement this. */
export interface Approver {
    readonly authority: string;
    approve(req: ApprovalRequest): Promise<Bundle>;
}
/** ULID: 48-bit millisecond time + 80 random bits, Crockford base32, 26 chars. */
export declare function newReceiptId(now: Date, rand?: (n: number) => Uint8Array): string;
/** The exact text the human is shown. Agent-supplied strings go through JSON.stringify, which escapes
 *  control characters (e.g. ESC), so an agent cannot inject terminal escape codes or fake extra lines.
 *  A repo merge is shown as a readable file list (repoDisplay.ts); a merge too big to read throws, so the
 *  human is never asked. Gap: lookalike Unicode is not filtered (bidirectional characters are, in file lists). */
export declare function renderRequest(req: ApprovalRequest, payloadHash: string): string;
export interface LocalKeyApproverOptions {
    authority: string;
    seed: Uint8Array;
    prompt: Prompt;
    now?: () => Date;
    ttlSeconds?: number;
    rand?: (n: number) => Uint8Array;
}
export declare class LocalKeyApprover implements Approver {
    readonly authority: string;
    private readonly secretKey;
    private readonly publicKey;
    private readonly prompt;
    private readonly now;
    private readonly ttl;
    private readonly rand;
    constructor(o: LocalKeyApproverOptions);
    /** The public record a verifier pins. Safe to share. */
    publicRecord(valid_from: string, valid_until: string): KeyRecord;
    approve(req: ApprovalRequest): Promise<Bundle>;
}
//# sourceMappingURL=approver.d.ts.map