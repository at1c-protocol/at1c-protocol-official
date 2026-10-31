"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateKeyPair = generateKeyPair;
exports.publicKeyToHex = publicKeyToHex;
exports.hexToPublicKey = hexToPublicKey;
exports.secretKeyToHex = secretKeyToHex;
exports.hexToSecretKey = hexToSecretKey;
exports.canonicalise = canonicalise;
exports.signReceipt = signReceipt;
exports.verifyReceipt = verifyReceipt;
exports.buildReceipt = buildReceipt;
const ml_dsa_js_1 = require("@noble/post-quantum/ml-dsa.js");
const utils_1 = require("@noble/hashes/utils");
const _usedNonces = new Set();
function generateKeyPair() {
    const seed = (0, utils_1.randomBytes)(32);
    const keys = ml_dsa_js_1.ml_dsa65.keygen(seed);
    return {
        secretKey: keys.secretKey,
        publicKey: keys.publicKey,
    };
}
function publicKeyToHex(publicKey) {
    return Buffer.from(publicKey).toString('hex');
}
function hexToPublicKey(hex) {
    return Uint8Array.from(Buffer.from(hex, 'hex'));
}
function secretKeyToHex(secretKey) {
    return Buffer.from(secretKey).toString('hex');
}
function hexToSecretKey(hex) {
    return Uint8Array.from(Buffer.from(hex, 'hex'));
}
function canonicalise(payload) {
    const sorted = Object.keys(payload)
        .sort()
        .reduce((acc, key) => {
        const val = payload[key];
        if (val !== undefined)
            acc[key] = val;
        return acc;
    }, {});
    return new TextEncoder().encode(JSON.stringify(sorted));
}
/** @deprecated Pre-v1 format. Use the Approver and Gate instead. */
function signReceipt(payload, keyPair) {
    const bytes = canonicalise(payload);
    const sigBytes = ml_dsa_js_1.ml_dsa65.sign(bytes, keyPair.secretKey);
    return {
        ...payload,
        algorithm: 'ML-DSA-65',
        signature: Buffer.from(sigBytes).toString('hex'),
        publicKey: Buffer.from(keyPair.publicKey).toString('hex'),
    };
}
/** @deprecated INSECURE: trusts the public key inside the receipt, so anyone can forge a valid receipt. Use verifyReceiptV1 (spec/receipt.md). */
function verifyReceipt(receipt) {
    if (receipt.algorithm !== 'ML-DSA-65') {
        return { valid: false, reason: 'unsupported_algorithm' };
    }
    const now = new Date();
    const expiresAt = new Date(receipt.expiresAt);
    if (now > expiresAt) {
        return { valid: false, reason: 'expired' };
    }
    if (receipt.status !== 'approved') {
        return { valid: false, reason: 'not_approved' };
    }
    if (receipt.principalValidUntil) {
        const principalExpiry = new Date(receipt.principalValidUntil);
        if (now > principalExpiry) {
            const policy = receipt.postDissolutionPolicy ?? 'reject';
            if (policy === 'reject') {
                return { valid: false, reason: 'principal_expired' };
            }
        }
    }
    try {
        const payload = {
            receiptId: receipt.receiptId,
            nonce: receipt.nonce,
            version: receipt.version,
            algorithm: receipt.algorithm,
            status: receipt.status,
            userId: receipt.userId,
            agentId: receipt.agentId,
            action: receipt.action,
            timestamp: receipt.timestamp,
            expiresAt: receipt.expiresAt,
            ...(receipt.principalValidUntil && { principalValidUntil: receipt.principalValidUntil }),
            ...(receipt.dissolutionTrigger && { dissolutionTrigger: receipt.dissolutionTrigger }),
            ...(receipt.inheritorAgentId && { inheritorAgentId: receipt.inheritorAgentId }),
            ...(receipt.postDissolutionPolicy && { postDissolutionPolicy: receipt.postDissolutionPolicy }),
        };
        const bytes = canonicalise(payload);
        const sigBytes = Uint8Array.from(Buffer.from(receipt.signature, 'hex'));
        const pubKeyBytes = hexToPublicKey(receipt.publicKey);
        const valid = ml_dsa_js_1.ml_dsa65.verify(sigBytes, bytes, pubKeyBytes);
        if (!valid) {
            return { valid: false, reason: 'invalid_signature' };
        }
    }
    catch {
        return { valid: false, reason: 'malformed_receipt' };
    }
    if (_usedNonces.has(receipt.nonce)) {
        return { valid: false, reason: 'replay_detected' };
    }
    _usedNonces.add(receipt.nonce);
    return { valid: true };
}
/** @deprecated Pre-v1 format. Use the Approver and Gate instead. */
function buildReceipt(config, keyPair) {
    const now = new Date();
    const ttl = config.ttlSeconds ?? 300;
    const payload = {
        receiptId: crypto.randomUUID(),
        nonce: crypto.randomUUID(),
        version: '1.6',
        algorithm: 'ML-DSA-65',
        status: config.status,
        userId: config.userId,
        agentId: config.agentId,
        action: config.action,
        timestamp: now.toISOString(),
        expiresAt: new Date(now.getTime() + ttl * 1000).toISOString(),
        ...(config.principalValidUntil && { principalValidUntil: config.principalValidUntil }),
        ...(config.dissolutionTrigger && { dissolutionTrigger: config.dissolutionTrigger }),
        ...(config.inheritorAgentId && { inheritorAgentId: config.inheritorAgentId }),
        ...(config.postDissolutionPolicy && { postDissolutionPolicy: config.postDissolutionPolicy }),
    };
    return signReceipt(payload, keyPair);
}
//# sourceMappingURL=crypto.js.map