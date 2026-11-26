"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LocalKeyApprover = exports.receiptOnly = void 0;
exports.newReceiptId = newReceiptId;
exports.renderRequest = renderRequest;
// AT1C Approver (level 1, "dev mode"). Implements the signing side of spec/receipt.md (receipt format 2).
//
// SECURITY NOTE (read this): in level 1 the Approver runs in the SAME OS account as the agent.
// Anything the agent can run can read the key and approve itself. This stops mistakes and bugs,
// not a hijacked agent. Level 2 (separate OS account) and level 3 (separate device) run this same
// interface elsewhere; the Gate does not change. See docs/STATUS.md.
const ml_dsa_js_1 = require("@noble/post-quantum/ml-dsa.js");
const crypto_1 = require("crypto");
const verify_1 = require("./verify");
const repoDisplay_1 = require("./repoDisplay");
/** The shareable half of a bundle: the signed receipt without the payload or the salt. */
const receiptOnly = (bundle) => bundle.receipt;
exports.receiptOnly = receiptOnly;
const MAX_TTL_SECONDS = 86400;
const MAX_DISPLAY_PAYLOAD = 2000;
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const CLASSES = ['compensable', 'retriable', 'irreversible'];
const fmt = (d) => d.toISOString().slice(0, 19) + 'Z';
// Plain-name rule. A receipt is signed and may be kept for years, so a secret written into one of its plain-text
// fields can never be taken out again. These checks run BEFORE the human is asked, so they cover denials too.
// They catch the obvious shapes only (a login inside a URL, a query string): a guard, not a guarantee.
const RE_URL_LOGIN = /[a-z][a-z0-9+.-]*:\/\/[^\s/?#]*@/i; // scheme://user:password@host
const RE_URL_QUERY = /:\/\/[^\s#]*\?/; // a URL carrying a query string
function assertPlainText(field, s, isName) {
    if (RE_URL_LOGIN.test(s) || RE_URL_QUERY.test(s) || (isName && s.includes('?'))) {
        throw new Error(`bad request: ${field} must not contain a login or a query string (put such details in the payload)`);
    }
}
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
 *  A repo merge is shown as a readable file list (repoDisplay.ts); a merge too big to read throws, so the
 *  human is never asked. Gap: lookalike Unicode is not filtered (bidirectional characters are, in file lists). */
function renderRequest(req, payloadHash) {
    let shown;
    if (req.type === repoDisplay_1.REPO_MERGE_TYPE) {
        if (!(0, repoDisplay_1.isRepoPayload)(req.payload))
            throw new Error('bad request: a repo.merge payload must be exactly the repository file list');
        shown = (0, repoDisplay_1.renderRepoFiles)(req.payload);
    }
    else {
        const canonical = (0, verify_1.jcs)(req.payload);
        shown =
            canonical.length <= MAX_DISPLAY_PAYLOAD
                ? canonical
                : `(too large to display, ${canonical.length} chars; hash only) ${payloadHash}`;
    }
    const lines = [
        'AT1C approval request',
        `For gate: ${JSON.stringify(req.audience)}`,
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
        if (typeof req.audience !== 'string' || !req.audience)
            throw new Error('bad request: audience');
        if (typeof req.agent_public_key !== 'string')
            throw new Error('bad request: agent_public_key');
        if (typeof req.type !== 'string' || !req.type)
            throw new Error('bad request: type');
        if (typeof req.resource !== 'string')
            throw new Error('bad request: resource');
        if (!CLASSES.includes(req.class))
            throw new Error('bad request: class');
        if (req.scope_ref !== undefined && typeof req.scope_ref !== 'string')
            throw new Error('bad request: scope_ref');
        if (req.description !== undefined && typeof req.description !== 'string')
            throw new Error('bad request: description');
        assertPlainText('audience', req.audience, true);
        assertPlainText('resource', req.resource, true);
        if (req.scope_ref !== undefined)
            assertPlainText('scope_ref', req.scope_ref, true);
        if (req.description !== undefined)
            assertPlainText('description', req.description, false);
        // The attachment is what the receipt fingerprints. The payload is copied through its canonical form, so the
        // bundle cannot change if the caller later alters its own object. jcs() throws on floats and on anything that
        // is not plain data, before any prompt. Every receipt gets a fresh random salt; no exceptions.
        const attachment = {
            payload: JSON.parse((0, verify_1.jcs)(req.payload)),
            salt: Buffer.from(this.rand(32)).toString('base64url'),
        };
        const payloadHash = (0, verify_1.attachmentHashOf)(attachment);
        // Shown from the canonical copy that is signed, never from the caller's own object a second time.
        const text = renderRequest({ ...req, payload: attachment.payload }, payloadHash);
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
            version: '2',
            receipt_id: newReceiptId(issued, this.rand),
            decision: approved ? 'approved' : 'denied',
            issued_at: fmt(issued),
            expires_at: fmt(new Date(issued.getTime() + this.ttl * 1000)),
            audience: req.audience,
            actor: { agent_id: req.agent_id, public_key: req.agent_public_key },
            action,
            display_digest: sha256(text),
            approval: { authority: this.authority, alg: 'ML-DSA-65' },
            nonce: Buffer.from(this.rand(32)).toString('base64url'),
        };
        // Signed under the receipt label, never unlabelled: a signature made here cannot pass as any other kind of
        // AT1C record, and no other kind can pass as a receipt.
        const sig = ml_dsa_js_1.ml_dsa65.sign(new TextEncoder().encode((0, verify_1.jcs)(unsigned)), this.secretKey, {
            context: new TextEncoder().encode(verify_1.RECEIPT_CONTEXT),
        });
        const receipt = {
            ...unsigned,
            approval: { ...unsigned.approval, signature: Buffer.from(sig).toString('base64url') },
        };
        return { receipt, attachment };
    }
}
exports.LocalKeyApprover = LocalKeyApprover;
//# sourceMappingURL=approver.js.map