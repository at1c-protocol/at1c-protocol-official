export interface KeyPair {
    secretKey: Uint8Array;
    publicKey: Uint8Array;
}
export declare function generateKeyPair(): KeyPair;
export declare function publicKeyToHex(publicKey: Uint8Array): string;
export declare function hexToPublicKey(hex: string): Uint8Array;
export declare function secretKeyToHex(secretKey: Uint8Array): string;
export declare function hexToSecretKey(hex: string): Uint8Array;
//# sourceMappingURL=crypto.d.ts.map