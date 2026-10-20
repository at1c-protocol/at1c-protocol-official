"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.jcs = jcs;
exports.payloadHashOf = payloadHashOf;
exports.verifyReceiptV1 = verifyReceiptV1;
// AT1C receipt verifier, format version 1. Implements spec/receipt.md section 5 and spec/keys.md.
// Tested against spec/test-vectors/receipt-v1.json (tests/vectors.test.ts). No dependency beyond @noble/post-quantum.
const ml_dsa_js_1 = require("@noble/post-quantum/ml-dsa.js");
const crypto_1 = require("crypto");
const MAX_TTL_SECONDS = 86400;
const RE_ID = /^at1c_[0-9A-HJKMNP-TV-Z]{26}$/;
const RE_HASH = /^sha256:[0-9a-f]{64}$/;
const RE_B64U = /^[A-Za-z0-9_-]+$/;
const RE_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const CLASSES = ['compensable', 'retriable', 'irreversible'];
/** RFC 8785 (JCS) for the value types receipts may contain: strings, safe integers, booleans, null, arrays, objects.
 *  Floats are rejected on purpose (spec/receipt.md section 2). Keys sort by UTF-16 code unit, as RFC 8785 requires. */
function jcs(v) {
    if (v === null)
        return 'null';
    switch (typeof v) {
        case 'string': return JSON.stringify(v);
        case 'boolean': return v ? 'true' : 'false';
        case 'number':
            if (!Number.isSafeInteger(v))
                throw new Error('floats and unsafe integers are not allowed');
            return String(v);
        case 'object': {
            if (Array.isArray(v))
                return '[' + v.map(jcs).join(',') + ']';
            const o = v;
            const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
            return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(o[k])).join(',') + '}';
        }
        default: throw new Error('unsupported value type');
    }
}
/** The payload_hash a gate must compute from the real payload it is about to execute. */
function payloadHashOf(payload) {
    return 'sha256:' + (0, crypto_1.createHash)('sha256').update(jcs(payload), 'utf8').digest('hex');
}
const b64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
const ts = (s) => Date.parse(s);
const isStr = (x) => typeof x === 'string' && x.length > 0;
function schemaOk(r) {
    try {
        return (r.version === '1' && RE_ID.test(r.receipt_id) &&
            (r.decision === 'approved' || r.decision === 'denied') &&
            RE_TS.test(r.issued_at) && RE_TS.test(r.expires_at) &&
            isStr(r.actor?.agent_id) &&
            CLASSES.includes(r.action?.class) && RE_HASH.test(r.action?.payload_hash) &&
            typeof r.action?.type === 'string' && typeof r.action?.resource === 'string' &&
            RE_HASH.test(r.display_digest) &&
            isStr(r.approval?.authority) && isStr(r.approval?.alg) && RE_B64U.test(r.approval?.signature) &&
            RE_B64U.test(r.nonce) && b64u(r.nonce).length === 32);
    }
    catch {
        return false;
    }
}
/** Returns a code; ok is true only for 'OK'. First failing check wins; the nonce is consumed last. */
function verifyReceiptV1(receipt, ctx) {
    const fail = (code) => ({ ok: false, code });
    if (!schemaOk(receipt))
        return fail('SCHEMA');
    const ap = receipt.approval;
    if (ap.alg !== 'ML-DSA-65' || !ctx.allowedAlgs.includes(ap.alg))
        return fail('ALG_NOT_ALLOWED');
    const rec = ctx.pinned[ap.authority]; // key comes from the verifier's list, never from the receipt
    if (!rec)
        return fail('UNKNOWN_AUTHORITY');
    const now = ctx.now.getTime();
    if (rec.alg !== ap.alg || rec.revoked || !(ts(rec.valid_from) <= now && now < ts(rec.valid_until))) {
        return fail('KEY_NOT_VALID');
    }
    const unsigned = structuredClone(receipt);
    delete unsigned.approval.signature;
    let bytes;
    try {
        bytes = new TextEncoder().encode(jcs(unsigned));
    }
    catch {
        return fail('SCHEMA'); // e.g. a float in an extra field
    }
    let sigOk = false;
    try {
        sigOk = ml_dsa_js_1.ml_dsa65.verify(b64u(ap.signature), bytes, b64u(rec.public_key));
    }
    catch {
        sigOk = false;
    }
    if (!sigOk)
        return fail('BAD_SIGNATURE');
    if (receipt.decision !== 'approved')
        return fail('DENIED');
    const iat = ts(receipt.issued_at);
    const exp = ts(receipt.expires_at);
    if (exp <= iat || (exp - iat) / 1000 > MAX_TTL_SECONDS)
        return fail('BAD_TTL');
    if (now < iat)
        return fail('NOT_YET_VALID');
    if (now >= exp)
        return fail('EXPIRED');
    const e = ctx.expected;
    const a = receipt.action;
    if (receipt.actor.agent_id !== e.agent_id || a.type !== e.type ||
        a.resource !== e.resource || a.payload_hash !== e.payload_hash)
        return fail('CONTEXT_MISMATCH');
    if (ctx.revoked.has(receipt.receipt_id))
        return fail('REVOKED');
    if (!ctx.nonces.checkAndRecord(receipt.nonce))
        return fail('REPLAY');
    return { ok: true, code: 'OK' };
}
//# sourceMappingURL=verify.js.map