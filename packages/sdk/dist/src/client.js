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
exports.AT1C = exports.terminalPrompt = exports.sanitiseAuthority = void 0;
// AT1C client (level 1, "dev mode"): a thin wrapper over LocalKeyApprover + Gate.
//
// SECURITY NOTE: the Approver key is read from a file owned by the same OS user that runs the agent.
// This stops mistakes and bugs, not a hijacked agent (see docs/STATUS.md, levels 2 and 3).
// What this class does guarantee: nothing runs without a human-signed, single-use, payload-bound receipt
// that the Gate verified against the operator's pinned public key (Rules 1 to 5).
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const path = __importStar(require("path"));
const readline = __importStar(require("readline"));
const approver_1 = require("./approver");
const gate_1 = require("./gate");
/** Safe file-name form of an authority id, matching tools/new-authority-key.mjs. */
const sanitiseAuthority = (a) => a.replace(/[^A-Za-z0-9._-]/g, '_');
exports.sanitiseAuthority = sanitiseAuthority;
/** Terminal y/n. Fails closed when stdin is not a terminal, so piped input cannot approve anything. */
const terminalPrompt = (text) => {
    if (!process.stdin.isTTY)
        return Promise.resolve(false);
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise((resolve) => {
        rl.question(`\n${text}\n\nApprove? (y/n): `, (answer) => {
            rl.close();
            resolve(answer.trim().toLowerCase() === 'y');
        });
    });
};
exports.terminalPrompt = terminalPrompt;
function loadSeed(file, authority) {
    const st = fs.statSync(file);
    if (process.platform !== 'win32' && (st.mode & 0o077) !== 0) {
        throw new Error(`key file ${file} is readable by others; run: chmod 600 "${file}"`);
    }
    const j = JSON.parse(fs.readFileSync(file, 'utf-8'));
    if (j.alg !== 'ML-DSA-65')
        throw new Error('key file is not ML-DSA-65');
    if (j.authority !== authority)
        throw new Error(`key file is for a different authority (${String(j.authority)})`);
    if (typeof j.seed_hex !== 'string' || !/^[0-9a-f]{64}$/.test(j.seed_hex))
        throw new Error('key file has no valid seed_hex');
    return Uint8Array.from(Buffer.from(j.seed_hex, 'hex'));
}
function loadTrusted(file) {
    const j = JSON.parse(fs.readFileSync(file, 'utf-8')); // missing or invalid file throws: fail closed
    if (!Array.isArray(j.allowed_algs) || typeof j.keys !== 'object' || j.keys === null) {
        throw new Error(`${file} must contain allowed_algs and keys`);
    }
    return { allowed_algs: j.allowed_algs, keys: j.keys };
}
function loadPolicies(file) {
    if (!fs.existsSync(file))
        return [];
    const j = JSON.parse(fs.readFileSync(file, 'utf-8')); // unparseable file throws: never silently drop deny rules
    if (!Array.isArray(j))
        throw new Error(`${file} must be a JSON array`);
    return j;
}
class AT1C {
    constructor(o) {
        this.approvalLog = [];
        const keyFile = o.keyFile ??
            process.env.AT1C_APPROVER_KEY_FILE ??
            path.join(os.homedir(), 'at1c-secrets', `${(0, exports.sanitiseAuthority)(o.authority)}.mldsa65.json`);
        const trusted = loadTrusted(o.trustedKeysFile ?? process.env.AT1C_TRUSTED_KEYS ?? 'trusted-keys.json');
        this.policies = loadPolicies(o.policiesFile ?? 'policies.json');
        this.receiptsFile = o.receiptsFile ?? 'receipts.json';
        this.approver = new approver_1.LocalKeyApprover({
            authority: o.authority,
            seed: loadSeed(keyFile, o.authority),
            prompt: o.prompt ?? exports.terminalPrompt,
            now: o.now,
            ttlSeconds: o.ttlSeconds,
        });
        this.publicKey = this.approver.publicRecord('1970-01-01T00:00:00Z', '9999-12-31T23:59:59Z').public_key;
        const pinned = trusted.keys[o.authority];
        if (!pinned || pinned.public_key !== this.publicKey) {
            throw new Error('the key file does not match the key pinned for this authority in trusted-keys');
        }
        this.gate = new gate_1.Gate({
            pinned: trusted.keys,
            allowedAlgs: trusted.allowed_algs,
            nonces: new gate_1.FileNonceStore(o.nonceDir ?? path.join('.at1c', 'nonces')),
            now: o.now,
            revoked: o.revoked ?? (0, gate_1.fileRevocationList)(o.revokedFile ?? path.join(path.dirname(o.nonceDir ?? path.join('.at1c', 'nonces')), 'revoked.json')),
        });
    }
    /** Public key (base64url) of the approver. */
    getPublicKey() {
        return this.publicKey;
    }
    /** Receipts signed during this process, approved and denied. */
    getApprovalLog() {
        return this.approvalLog;
    }
    /** Ask the human, then run `fn(payload)` only if a receipt for exactly this action verifies. */
    async enforce(config, fn) {
        const policy = this.policies.find((p) => p.action === config.action);
        if (policy?.decision === 'deny')
            return { status: 'denied', reason: 'blocked_policy' };
        // A policy decision of "allow" does not skip the receipt. Authority comes only from a human signature (Rule 1).
        const receipt = await this.approver.approve({
            agent_id: config.agentId,
            agent_public_key: config.agentPublicKey ?? 'unspecified',
            type: config.action,
            class: config.class ?? 'irreversible',
            resource: config.resource,
            payload: config.payload,
            scope_ref: config.scopeRef,
            description: config.description,
        });
        this.approvalLog.push(receipt);
        this.saveReceipt(receipt); // before running anything: if the audit write fails, fn does not run
        const out = await this.gate.run({ agent_id: config.agentId, type: config.action, resource: config.resource, payload: config.payload }, receipt, fn);
        if (out.status === 'executed')
            return { status: 'approved', result: out.result, receipt };
        return { status: 'denied', reason: out.code === 'DENIED' ? 'user_rejected' : out.code, receipt };
    }
    saveReceipt(receipt) {
        let list = [];
        if (fs.existsSync(this.receiptsFile)) {
            const j = JSON.parse(fs.readFileSync(this.receiptsFile, 'utf-8')); // corrupt file throws; never overwrite it
            if (!Array.isArray(j))
                throw new Error(`${this.receiptsFile} must be a JSON array`);
            list = j;
        }
        list.push(receipt);
        const tmp = `${this.receiptsFile}.tmp-${process.pid}`;
        fs.writeFileSync(tmp, JSON.stringify(list, null, 2), { mode: 0o600 });
        fs.renameSync(tmp, this.receiptsFile);
    }
}
exports.AT1C = AT1C;
//# sourceMappingURL=client.js.map