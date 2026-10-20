import { type KeyRecord, type NonceStore, type VerifyCode } from './verify';
import type { Approver, ApprovalRequest, ReceiptV1 } from './approver';
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
    pinned: Record<string, KeyRecord>;
    allowedAlgs: string[];
    nonces: NonceStore;
    revoked?: () => Set<string>;
    now?: () => Date;
}
export interface GateAction {
    agent_id: string;
    type: string;
    resource: string;
    payload: unknown;
}
export type GateResult<T> = {
    status: 'executed';
    result: T;
} | {
    status: 'refused';
    code: VerifyCode | 'GATE_ERROR';
};
export declare class Gate {
    private readonly o;
    constructor(o: GateOptions);
    /** Verify `receipt` against what is about to run, then run `fn`. Never runs `fn` on any failure.
     *  `fn` receives the payload re-parsed from its canonical form, so what executes is exactly what was hashed.
     *  The nonce is consumed by a successful verification; if `fn` throws, the receipt is still spent (single use). */
    run<T>(action: GateAction, receipt: unknown, fn: (payload: any) => T | Promise<T>): Promise<GateResult<T>>;
}
/** Convenience: ask the Approver, then let the Gate decide. `fn` runs only if the human approved and the
 *  receipt verifies. The agent never touches a key. */
export declare function approveAndRun<T>(approver: Approver, gate: Gate, req: ApprovalRequest, fn: (payload: any) => T | Promise<T>): Promise<GateResult<T> & {
    receipt: ReceiptV1;
}>;
//# sourceMappingURL=gate.d.ts.map