import { type KeyRecord } from './verify';
export type ActionClass = 'compensable' | 'retriable' | 'irreversible';
export interface ApprovalRequest {
    agent_id: string;
    agent_public_key: string;
    type: string;
    class: ActionClass;
    resource: string;
    payload: unknown;
    scope_ref?: string;
    description?: string;
}
export interface ReceiptV1 {
    version: '1';
    receipt_id: string;
    decision: 'approved' | 'denied';
    issued_at: string;
    expires_at: string;
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
/** Shows `text` to the human and returns their decision. The Approver, not the agent, produces `text`. */
export type Prompt = (text: string) => Promise<boolean>;
/** Anything that can turn a request into a signed receipt. Level 1, 2 and 3 all implement this. */
export interface Approver {
    readonly authority: string;
    approve(req: ApprovalRequest): Promise<ReceiptV1>;
}
/** ULID: 48-bit millisecond time + 80 random bits, Crockford base32, 26 chars. */
export declare function newReceiptId(now: Date, rand?: (n: number) => Uint8Array): string;
/** The exact text the human is shown. Agent-supplied strings go through JSON.stringify, which escapes
 *  control characters (e.g. ESC), so an agent cannot inject terminal escape codes or fake extra lines.
 *  Gap: lookalike and bidirectional Unicode are not filtered. */
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
    approve(req: ApprovalRequest): Promise<ReceiptV1>;
}
//# sourceMappingURL=approver.d.ts.map