"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateKeyPair = generateKeyPair;
exports.publicKeyToHex = publicKeyToHex;
exports.hexToPublicKey = hexToPublicKey;
exports.secretKeyToHex = secretKeyToHex;
exports.hexToSecretKey = hexToSecretKey;
const ml_dsa_js_1 = require("@noble/post-quantum/ml-dsa.js");
const utils_1 = require("@noble/hashes/utils");
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
//# sourceMappingURL=crypto.js.map