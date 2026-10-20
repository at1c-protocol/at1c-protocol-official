export type VerifyCode = 'OK' | 'SCHEMA' | 'ALG_NOT_ALLOWED' | 'UNKNOWN_AUTHORITY' | 'KEY_NOT_VALID' | 'BAD_SIGNATURE' | 'DENIED' | 'BAD_TTL' | 'NOT_YET_VALID' | 'EXPIRED' | 'CONTEXT_MISMATCH' | 'REVOKED' | 'REPLAY';
export interface KeyRecord {
    alg: string;
    public_key: string;
    valid_from: string;
    valid_until: string;
    revoked: boolean;
}
export interface ExpectedAction {
    agent_id: string;
    type: string;
    resource: string;
    payload_hash: string;
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
/** RFC 8785 (JCS) for the value types receipts may contain: strings, safe integers, booleans, null, arrays, objects.
 *  Floats are rejected on purpose (spec/receipt.md section 2). Keys sort by UTF-16 code unit, as RFC 8785 requires. */
export declare function jcs(v: unknown): string;
/** The payload_hash a gate must compute from the real payload it is about to execute. */
export declare function payloadHashOf(payload: unknown): string;
/** Returns a code; ok is true only for 'OK'. First failing check wins; the nonce is consumed last. */
export declare function verifyReceiptV1(receipt: any, ctx: VerifyContext): {
    ok: boolean;
    code: VerifyCode;
};
//# sourceMappingURL=verify.d.ts.map