import { type KeyRecord, type NonceStore, type VerifyCode } from './verify';
import type { Approver, ApprovalRequest, Bundle } from './approver';
/** In-memory nonce store. Tests and single-process dev only: it forgets on restart. */
export declare class MemoryNonceStore implements NonceStore {
    private seen;
    checkAndRecord(nonce: string): boolean;
}
/** Durable, atomic nonce store: one file per nonce, created with O_EXCL ('wx'), so two racing callers
 *  cannot both succeed. Survives restarts. Single host only (multi-gateway needs a shared store; spec gap).
 *  Throws on anything unexpected, so the Gate fails closed. */
export declare class FileNonceStore implements NonceStore {
    private readonly dir;
    constructor(dir: string);
    checkAndRecord(nonce: string): boolean;
}
export interface GateOptions {
    /** REQUIRED (format 2). This gate's own name, chosen by its operator (for example its web address). A receipt is
     *  accepted only if its signed `audience` is exactly this text. It comes from the gate's settings, never from
     *  the caller, so a receipt made for one gate cannot be used at another. No wildcard. */
    audience: string;
    pinned: Record<string, KeyRecord>;
    allowedAlgs: string[];
    nonces: NonceStore;
    /** REQUIRED (since 2.0.0). Returns the revoked receipt ids; called on every check so a fresh list is used.
     *  If you really have no revocations, say so explicitly with `revoked: NO_REVOCATIONS`. */
    revoked: () => Set<string>;
    now?: () => Date;
}
/** Explicit opt-out: this Gate has no revocation list. Use only when that is a deliberate choice. */
export declare const NO_REVOCATIONS: () => Set<string>;
/** Revocation list kept in a JSON file: an array of revoked receipt ids, e.g. ["at1c_..."].
 *  Creates the file empty (mode 600) if it does not exist yet, so there is always a visible place to revoke.
 *  Re-read on every check. If the file later goes missing, or is not a JSON array of strings, the read throws
 *  and the Gate refuses (GATE_ERROR): hard-fail, never "treat as nothing revoked". */
export declare function fileRevocationList(file: string): () => Set<string>;
/** What the gate's caller says is about to run. The payload is NOT here: it comes only from the bundle's
 *  attachment, whose fingerprint the human signed. */
export interface GateAction {
    agent_id: string;
    type: string;
    resource: string;
}
export type GateResult<T> = {
    status: 'executed';
    result: T;
} | {
    status: 'refused';
    code: VerifyCode | 'GATE_ERROR' | 'NO_ATTACHMENT';
};
export declare class Gate {
    private readonly o;
    constructor(o: GateOptions);
    /** Verify the bundle's receipt against what is about to run, then run `fn`. Never runs `fn` on any failure.
     *  The payload comes from the bundle's attachment, never from the caller: the gate fingerprints the whole
     *  attachment itself and the receipt must carry that fingerprint. `fn` receives the payload re-parsed from its
     *  canonical form, so what executes is exactly what was hashed.
     *  A receipt without its attachment is refused (NO_ATTACHMENT): no travel without salt.
     *  The nonce is consumed by a successful verification; if `fn` throws, the receipt is still spent (single use). */
    run<T>(action: GateAction, bundle: unknown, fn: (payload: any) => T | Promise<T>): Promise<GateResult<T>>;
}
/** Convenience: ask the Approver, then let the Gate decide. `fn` runs only if the human approved and the
 *  receipt verifies. The agent never touches a key. */
export declare function approveAndRun<T>(approver: Approver, gate: Gate, req: ApprovalRequest, fn: (payload: any) => T | Promise<T>): Promise<GateResult<T> & {
    bundle: Bundle;
}>;
//# sourceMappingURL=gate.d.ts.map