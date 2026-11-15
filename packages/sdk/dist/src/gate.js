"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.Gate = exports.NO_REVOCATIONS = exports.FileNonceStore = exports.MemoryNonceStore = void 0;
exports.fileRevocationList = fileRevocationList;
exports.approveAndRun = approveAndRun;
// AT1C Gate (receipt format 2). Runs spec/receipt.md section 5 before any side effect (Rule 4, Verification Before Execution).
// The Gate holds only PUBLIC keys. It never sees a secret key.
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const verify_1 = require("./verify");
/** In-memory nonce store. Tests and single-process dev only: it forgets on restart. */
class MemoryNonceStore {
    constructor() {
        this.seen = new Set();
    }
    checkAndRecord(nonce) {
        if (this.seen.has(nonce))
            return false;
        this.seen.add(nonce);
        return true;
    }
}
exports.MemoryNonceStore = MemoryNonceStore;
/** Durable, atomic nonce store: one file per nonce, created with O_EXCL ('wx'), so two racing callers
 *  cannot both succeed. Survives restarts. Single host only (multi-gateway needs a shared store; spec gap).
 *  Throws on anything unexpected, so the Gate fails closed. */
class FileNonceStore {
    constructor(dir) {
        this.dir = dir;
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    checkAndRecord(nonce) {
        if (!/^[A-Za-z0-9_-]{43}$/.test(nonce))
            throw new Error('invalid nonce'); // 32 bytes b64url; also blocks path tricks
        try {
            fs.closeSync(fs.openSync(path.join(this.dir, nonce), 'wx', 0o600));
            return true;
        }
        catch (e) {
            if (e && e.code === 'EEXIST')
                return false;
            throw e;
        }
    }
}
exports.FileNonceStore = FileNonceStore;
/** Explicit opt-out: this Gate has no revocation list. Use only when that is a deliberate choice. */
const NO_REVOCATIONS = () => new Set();
exports.NO_REVOCATIONS = NO_REVOCATIONS;
/** Revocation list kept in a JSON file: an array of revoked receipt ids, e.g. ["at1c_..."].
 *  Creates the file empty (mode 600) if it does not exist yet, so there is always a visible place to revoke.
 *  Re-read on every check. If the file later goes missing, or is not a JSON array of strings, the read throws
 *  and the Gate refuses (GATE_ERROR): hard-fail, never "treat as nothing revoked". */
function fileRevocationList(file) {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    try {
        fs.writeFileSync(file, '[]\n', { flag: 'wx', mode: 0o600 });
    }
    catch (e) {
        if (!e || e.code !== 'EEXIST')
            throw e;
    }
    return () => {
        const list = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (!Array.isArray(list) || !list.every((x) => typeof x === 'string')) {
            throw new Error(`${file}: must be a JSON array of receipt ids`);
        }
        return new Set(list);
    };
}
class Gate {
    constructor(o) {
        this.o = o;
        // Fail at start-up, not silently at check time: a Gate without a revocation list would never refuse a revoked receipt.
        if (typeof o?.revoked !== 'function') {
            throw new Error('AT1C Gate: `revoked` is required and must be a function returning a Set of receipt ids. ' +
                'If this Gate deliberately has no revocations, pass `revoked: NO_REVOCATIONS`.');
        }
        // Same reasoning: a Gate without its own name would accept receipts made for any gate.
        if (typeof o.audience !== 'string' || o.audience.length === 0) {
            throw new Error('AT1C Gate: `audience` is required: the name of this gate, which receipts must be made for.');
        }
    }
    /** Verify the bundle's receipt against what is about to run, then run `fn`. Never runs `fn` on any failure.
     *  The payload comes from the bundle's attachment, never from the caller: the gate fingerprints the whole
     *  attachment itself and the receipt must carry that fingerprint. `fn` receives the payload re-parsed from its
     *  canonical form, so what executes is exactly what was hashed.
     *  A receipt without its attachment is refused (NO_ATTACHMENT): no travel without salt.
     *  The nonce is consumed by a successful verification; if `fn` throws, the receipt is still spent (single use). */
    async run(action, bundle, fn) {
        const b = bundle;
        if (b === null || typeof b !== 'object' || Array.isArray(b) || b.receipt === undefined) {
            return { status: 'refused', code: 'SCHEMA' };
        }
        if (b.attachment === undefined || b.attachment === null)
            return { status: 'refused', code: 'NO_ATTACHMENT' };
        let canonical;
        let expectedHash;
        try {
            expectedHash = (0, verify_1.attachmentHashOf)(b.attachment); // throws on a malformed attachment or a value jcs() refuses
            canonical = (0, verify_1.jcs)(b.attachment.payload);
        }
        catch {
            return { status: 'refused', code: 'SCHEMA' };
        }
        let verdict;
        try {
            const revoked = this.o.revoked();
            if (!(revoked instanceof Set))
                throw new Error('revoked() must return a Set'); // fail closed below
            verdict = (0, verify_1.verifyReceiptV2)(b.receipt, {
                now: (this.o.now ?? (() => new Date()))(),
                pinned: this.o.pinned,
                allowedAlgs: this.o.allowedAlgs,
                expected: {
                    audience: this.o.audience, // this gate's own name, from its own settings
                    agent_id: action.agent_id,
                    type: action.type,
                    resource: action.resource,
                    payload_hash: expectedHash,
                },
                nonces: this.o.nonces,
                revoked,
            });
        }
        catch {
            return { status: 'refused', code: 'GATE_ERROR' }; // fail closed: nonce store or revocation list unavailable
        }
        if (!verdict.ok)
            return { status: 'refused', code: verdict.code };
        return { status: 'executed', result: await fn(JSON.parse(canonical)) };
    }
}
exports.Gate = Gate;
/** Convenience: ask the Approver, then let the Gate decide. `fn` runs only if the human approved and the
 *  receipt verifies. The agent never touches a key. */
async function approveAndRun(approver, gate, req, fn) {
    const bundle = await approver.approve(req);
    const out = await gate.run({ agent_id: req.agent_id, type: req.type, resource: req.resource }, bundle, fn);
    return { ...out, bundle };
}
//# sourceMappingURL=gate.js.map