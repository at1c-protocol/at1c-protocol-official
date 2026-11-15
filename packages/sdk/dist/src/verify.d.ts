export type VerifyCode = 'OK' | 'SCHEMA' | 'ALG_NOT_ALLOWED' | 'UNKNOWN_AUTHORITY' | 'KEY_NOT_VALID' | 'BAD_SIGNATURE' | 'DENIED' | 'BAD_TTL' | 'NOT_YET_VALID' | 'EXPIRED' | 'AUDIENCE_MISMATCH' | 'CONTEXT_MISMATCH' | 'REVOKED' | 'REPLAY';
export interface KeyRecord {
    alg: string;
    public_key: string;
    valid_from: string;
    valid_until: string;
    revoked: boolean;
}
export interface ExpectedAction {
    audience: string;
    agent_id: string;
    type: string;
    resource: string;
    payload_hash: string;
}
/** What travels beside a receipt: the exact payload and the random salt mixed into its fingerprint.
 *  The receipt signs sha256(JCS(attachment)); without the whole attachment nobody can check or guess the payload. */
export interface Attachment {
    payload: unknown;
    salt: string;
}
/** Must be atomic and durable in production. Returns true if the nonce was new (and records it). */
export interface NonceStore {
    checkAndRecord(nonce: string): boolean;
}
export interface VerifyContext {
    now: Date;
    pinned: Record<string, KeyRecord>;
    allowedAlgs: string[];
    expected: ExpectedAction;
    nonces: NonceStore;
    revoked: Set<string>;
}
/** Signing labels (FIPS 204 context strings). A signature made under one label fails under any other, so one kind
 *  of signed thing can never be passed off as another. The approver key MUST NOT sign anything unlabelled. */
export declare const RECEIPT_CONTEXT = "AT1C/receipt/v2";
export declare const IDENTITY_LOG_CONTEXT = "AT1C/identity-log/v1";
/** RFC 8785 (JCS) for the value types receipts may contain: strings, safe integers, booleans, null, arrays, objects.
 *  Floats are rejected on purpose (spec/receipt.md section 2). Keys sort by UTF-16 code unit, as RFC 8785 requires. */
export declare function jcs(v: unknown): string;
/** The payload_hash of format 2: sha256 over the JCS form of the WHOLE attachment `{ payload, salt }`.
 *  Throws if the attachment is malformed or holds a value jcs() refuses. A gate computes this itself from the
 *  attachment it was handed; it never trusts a hash supplied next to it. */
export declare function attachmentHashOf(attachment: unknown): string;
/** Returns a code; ok is true only for 'OK'. First failing check wins; the nonce is consumed last. */
export declare function verifyReceiptV2(receipt: any, ctx: VerifyContext): {
    ok: boolean;
    code: VerifyCode;
};
//# sourceMappingURL=verify.d.ts.map