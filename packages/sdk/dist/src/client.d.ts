import { type ActionClass, type Prompt, type ReceiptV1 } from './approver';
export interface AT1COptions {
    /** Authority id of the human approver, e.g. "did:web:example.com#user-1". Must be pinned in trustedKeysFile. */
    authority: string;
    /** Secret key file (mode 600). Default: env AT1C_APPROVER_KEY_FILE, else ~/at1c-secrets/<authority>.mldsa65.json */
    keyFile?: string;
    /** Pinned public keys (same shape as trusted-keys.example.json). Default: env AT1C_TRUSTED_KEYS, else ./trusted-keys.json */
    trustedKeysFile?: string;
    /** Durable single-use nonce store. Default: ./.at1c/nonces */
    nonceDir?: string;
    /** Deny list. Missing file = no rules. A file that exists but cannot be parsed is an error. Default: ./policies.json */
    policiesFile?: string;
    /** Audit log of every receipt signed, approved or denied. Default: ./receipts.json */
    receiptsFile?: string;
    prompt?: Prompt;
    now?: () => Date;
    ttlSeconds?: number;
}
export interface EnforceConfig {
    agentId: string;
    action: string;
    resource: string;
    payload: unknown;
    class?: ActionClass;
    scopeRef?: string;
    description?: string;
    agentPublicKey?: string;
}
export type EnforceResult = {
    status: 'approved';
    result: any;
    receipt: ReceiptV1;
} | {
    status: 'denied';
    reason: string;
    receipt?: ReceiptV1;
};
/** Safe file-name form of an authority id, matching tools/new-authority-key.mjs. */
export declare const sanitiseAuthority: (a: string) => string;
/** Terminal y/n. Fails closed when stdin is not a terminal, so piped input cannot approve anything. */
export declare const terminalPrompt: Prompt;
export declare class AT1C {
    private readonly approver;
    private readonly gate;
    private readonly policies;
    private readonly receiptsFile;
    private readonly publicKey;
    private approvalLog;
    constructor(o: AT1COptions);
    /** Public key (base64url) of the approver. */
    getPublicKey(): string;
    /** Receipts signed during this process, approved and denied. */
    getApprovalLog(): ReceiptV1[];
    /** Ask the human, then run `fn(payload)` only if a receipt for exactly this action verifies. */
    enforce(config: EnforceConfig, fn: (payload: any) => Promise<any> | any): Promise<EnforceResult>;
    private saveReceipt;
}
//# sourceMappingURL=client.d.ts.map