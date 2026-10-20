import { KeyRecord } from './verify';
export type CertCode = 'OK' | 'SCHEMA' | 'ALG_NOT_ALLOWED' | 'UNKNOWN_ISSUER' | 'KEY_NOT_VALID' | 'BAD_SIGNATURE' | 'BAD_VALIDITY' | 'NOT_YET_VALID' | 'EXPIRED' | 'AGENT_ID_MISMATCH' | 'REVOKED';
export interface CertContext {
    now: Date;
    pinned: Record<string, KeyRecord>;
    allowedAlgs: string[];
    revoked: Set<string>;
}
/** agent_id must be derived from the agent's key: "agent:" + first 32 hex of SHA-256(raw public key). */
export declare function agentIdFor(agentPublicKeyB64u: string): string;
export declare function verifyAgentCertificateV1(cert: any, ctx: CertContext): {
    ok: boolean;
    code: CertCode;
};
//# sourceMappingURL=agentCert.d.ts.map