"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LocalKeyApprover = void 0;
exports.newReceiptId = newReceiptId;
exports.renderRequest = renderRequest;
// AT1C Approver (level 1, "dev mode"). Implements the signing side of spec/receipt.md.
//
// SECURITY NOTE (read this): in level 1 the Approver runs in the SAME OS account as the agent.
// Anything the agent can run can read the key and approve itself. This stops mistakes and bugs,
// not a hijacked agent. Level 2 (separate OS account) and level 3 (separate device) run this same
// interface elsewhere; the Gate does not change. See docs/STATUS.md.
const ml_dsa_js_1 = require("@noble/post-quantum/ml-dsa.js");
const crypto_1 = require("crypto");
const verify_1 = require("./verify");
const MAX_TTL_SECONDS = 86400;
const MAX_DISPLAY_PAYLOAD = 2000;
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const CLASSES = ['compensable', 'retriable', 'irreversible'];
const fmt = (d) => d.toISOString().slice(0, 19) + 'Z';
const sha256 = (s) => 'sha256:' + (0, crypto_1.createHash)('sha256').update(s, 'utf8').digest('hex');
/** ULID: 48-bit millisecond time + 80 random bits, Crockford base32, 26 chars. */
function newReceiptId(now, rand = crypto_1.randomBytes) {
    let t = BigInt(now.getTime());
    let time = '';
    for (let i = 0; i < 10; i++) {
        time = CROCKFORD[Number(t % 32n)] + time;
        t /= 32n;
    }
    let r = 0n;
    for (const b of rand(10))
        r = (r << 8n) | BigInt(b);
    let rnd = '';
    for (let i = 0; i < 16; i++) {
        rnd = CROCKFORD[Number(r % 32n)] + rnd;
        r /= 32n;
    }
    return 'at1c_' + time + rnd;
}
/** The exact text the human is shown. Agent-supplied strings go through JSON.stringify, which escapes
 *  control characters (e.g. ESC), so an agent cannot inject terminal escape codes or fake extra lines.
 *  Gap: lookalike and bidirectional Unicode are not filtered. */
function renderRequest(req, payloadHash) {
    const canonical = (0, verify_1.jcs)(req.payload);
    const shown = canonical.length <= MAX_DISPLAY_PAYLOAD
        ? canonical
        : `(too large to display, ${canonical.length} chars; hash only) ${payloadHash}`;
    const lines = [
        'AT1C approval request',
        `Agent:    ${JSON.stringify(req.agent_id)}`,
        `Action:   ${JSON.stringify(req.type)} (${req.class})`,
        `Resource: ${JSON.stringify(req.resource)}`,
        `Payload:  ${shown}`,
    ];
    if (req.scope_ref !== undefined)
        lines.push(`Scope:    ${JSON.stringify(req.scope_ref)}`);
    if (req.description !== undefined)
        lines.push(`Agent says (unverified): ${JSON.stringify(req.description)}`);
    return lines.join('\n');
}
class LocalKeyApprover {
    constructor(o) {
        if (!o.authority)
            throw new Error('authority required');
        if (o.seed.length !== 32)
            throw new Error('seed must be 32 bytes');
        const ttl = o.ttlSeconds ?? 300;
        if (!Number.isInteger(ttl) || ttl <= 0 || ttl > MAX_TTL_SECONDS)
            throw new Error('ttlSeconds must be 1..86400');
        const kp = ml_dsa_js_1.ml_dsa65.keygen(o.seed);
        this.secretKey = kp.secretKey;
        this.publicKey = kp.publicKey;
        this.authority = o.authority;
        this.prompt = o.prompt;
        this.now = o.now ?? (() => new Date());
        this.ttl = ttl;
        this.rand = o.rand ?? crypto_1.randomBytes;
    }
    /** The public record a verifier pins. Safe to share. */
    publicRecord(valid_from, valid_until) {
        return {
            alg: 'ML-DSA-65',
            public_key: Buffer.from(this.publicKey).toString('base64url'),
            valid_from,
            valid_until,
            revoked: false,
        };
    }
    async approve(req) {
        if (!req || typeof req.agent_id !== 'string' || !req.agent_id)
            throw new Error('bad request: agent_id');
        if (typeof req.agent_public_key !== 'string')
            throw new Error('bad request: agent_public_key');
        if (typeof req.type !== 'string' || !req.type)
            throw new Error('bad request: type');
        if (typeof req.resource !== 'string')
            throw new Error('bad request: resource');
        if (!CLASSES.includes(req.class))
            throw new Error('bad request: class');
        const payloadHash = (0, verify_1.payloadHashOf)(req.payload); // throws on floats / unsupported values, before any prompt
        const text = renderRequest(req, payloadHash);
        const approved = await this.prompt(text);
        const issued = this.now();
        const action = {
            type: req.type,
            class: req.class,
            resource: req.resource,
            payload_hash: payloadHash,
        };
        if (req.scope_ref !== undefined)
            action.scope_ref = req.scope_ref;
        if (req.description !== undefined)
            action.description = req.description;
        const unsigned = {
            version: '1',
            receipt_id: newReceiptId(issued, this.rand),
            decision: approved ? 'approved' : 'denied',
            issued_at: fmt(issued),
            expires_at: fmt(new Date(issued.getTime() + this.ttl * 1000)),
            actor: { agent_id: req.agent_id, public_key: req.agent_public_key },
            action,
            display_digest: sha256(text),
            approval: { authority: this.authority, alg: 'ML-DSA-65' },
            nonce: Buffer.from(this.rand(32)).toString('base64url'),
        };
        const sig = ml_dsa_js_1.ml_dsa65.sign(new TextEncoder().encode((0, verify_1.jcs)(unsigned)), this.secretKey);
        return {
            ...unsigned,
            approval: { ...unsigned.approval, signature: Buffer.from(sig).toString('base64url') },
        };
    }
}
exports.LocalKeyApprover = LocalKeyApprover;
//# sourceMappingURL=approver.js.map