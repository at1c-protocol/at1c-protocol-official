export interface KeyPair {
    secretKey: Uint8Array;
    publicKey: Uint8Array;
}
export interface ReceiptPayload {
    receiptId: string;
    nonce: string;
    version: string;
    algorithm: 'ML-DSA-65';
    status: 'approved' | 'denied';
    userId: string;
    agentId: string;
    action: string;
    timestamp: string;
    expiresAt: string;
    principalValidUntil?: string;
    dissolutionTrigger?: 'principal_deceased' | 'entity_dissolved' | 'key_revoked';
    inheritorAgentId?: string;
    postDissolutionPolicy?: 'reject' | 'warn' | 'audit_only';
}
export interface SignedReceipt extends ReceiptPayload {
    signature: string;
    publicKey: string;
}
export interface VerifyResult {
    valid: boolean;
    reason?: string;
}
export declare function generateKeyPair(): KeyPair;
export declare function publicKeyToHex(publicKey: Uint8Array): string;
export declare function hexToPublicKey(hex: string): Uint8Array;
export declare function secretKeyToHex(secretKey: Uint8Array): string;
export declare function hexToSecretKey(hex: string): Uint8Array;
export declare function canonicalise(payload: ReceiptPayload): Uint8Array;
/** @deprecated Pre-v1 format. Use the Approver and Gate instead. */
export declare function signReceipt(payload: ReceiptPayload, keyPair: KeyPair): SignedReceipt;
/** @deprecated INSECURE: trusts the public key inside the receipt, so anyone can forge a valid receipt. Use verifyReceiptV1 (spec/receipt.md). */
export declare function verifyReceipt(receipt: SignedReceipt): VerifyResult;
/** @deprecated Pre-v1 format. Use the Approver and Gate instead. */
export declare function buildReceipt(config: {
    userId: string;
    agentId: string;
    action: string;
    status: 'approved' | 'denied';
    ttlSeconds?: number;
    principalValidUntil?: string;
    dissolutionTrigger?: 'principal_deceased' | 'entity_dissolved' | 'key_revoked';
    inheritorAgentId?: string;
    postDissolutionPolicy?: 'reject' | 'warn' | 'audit_only';
}, keyPair: KeyPair): SignedReceipt;
//# sourceMappingURL=crypto.d.ts.map