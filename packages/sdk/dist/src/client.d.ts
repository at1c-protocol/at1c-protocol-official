import { type ActionClass, type Bundle, type Prompt, type ReceiptV2 } from './approver';
export interface AT1COptions {
    /** Authority id of the human approver, e.g. "did:web:example.com#user-1". Must be pinned in trustedKeysFile. */
    authority: string;
    /** REQUIRED (format 2). The name of this gate, for example its web address. Every receipt is made for exactly
     *  this name and the gate refuses receipts made for any other. */
    audience: string;
    /** Secret key file (mode 600). Default: env AT1C_APPROVER_KEY_FILE, else ~/at1c-secrets/<authority>.mldsa65.json */
    keyFile?: string;
    /** Pinned public keys (same shape as trusted-keys.example.json). Default: env AT1C_TRUSTED_KEYS, else ./trusted-keys.json */
    trustedKeysFile?: string;
    /** Durable single-use nonce store. Default: ./.at1c/nonces */
    nonceDir?: string;
    /** Optional: your own revoked-receipt list. If not given, the list is read from revokedFile on every check. */
    revoked?: () => Set<string>;
    /** Default: revoked.json beside the nonce folder (.at1c/revoked.json). Created empty if missing; unreadable = refuse. */
    revokedFile?: string;
    /** Deny list. Missing file = no rules. A file that exists but cannot be parsed is an error. Default: ./policies.json */
    policiesFile?: string;
    /** Audit log of every bundle signed, approved or denied: the receipt AND its attachment (payload and salt),
     *  kept together so the evidence can always be matched. It holds payloads in plain view (file mode 600);
     *  share `receiptOnly(bundle)` with outsiders. Default: ./receipts.json */
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
    receipt: ReceiptV2;
    bundle: Bundle;
} | {
    status: 'denied';
    reason: string;
    receipt?: ReceiptV2;
    bundle?: Bundle;
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
    private readonly audience;
    private approvalLog;
    constructor(o: AT1COptions);
    /** Public key (base64url) of the approver. */
    getPublicKey(): string;
    /** Receipts signed during this process, approved and denied (without payloads or salts). */
    getApprovalLog(): ReceiptV2[];
    /** The full bundles signed during this process: each receipt with its attachment. Holds payloads. */
    getBundles(): Bundle[];
    /** Ask the human, then run `fn(payload)` only if a receipt for exactly this action verifies. */
    enforce(config: EnforceConfig, fn: (payload: any) => Promise<any> | any): Promise<EnforceResult>;
    /** One file, receipt and attachment together, so the two halves cannot be separated by accident. */
    private saveBundle;
}
//# sourceMappingURL=client.d.ts.map