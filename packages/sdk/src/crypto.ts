import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { randomBytes } from '@noble/hashes/utils'

const _usedNonces = new Set<string>()

export interface KeyPair {
  secretKey: Uint8Array
  publicKey: Uint8Array
}

export interface ReceiptPayload {
  receiptId: string
  nonce: string
  version: string
  algorithm: 'ML-DSA-65'
  status: 'approved' | 'denied'
  userId: string
  agentId: string
  action: string
  timestamp: string
  expiresAt: string
  principalValidUntil?: string
  dissolutionTrigger?: 'principal_deceased' | 'entity_dissolved' | 'key_revoked'
  inheritorAgentId?: string
  postDissolutionPolicy?: 'reject' | 'warn' | 'audit_only'
}

export interface SignedReceipt extends ReceiptPayload {
  signature: string
  publicKey: string
}

export interface VerifyResult {
  valid: boolean
  reason?: string
}

export function generateKeyPair(): KeyPair {
  const seed = randomBytes(32)
  const keys = ml_dsa65.keygen(seed)
  return {
    secretKey: keys.secretKey,
    publicKey: keys.publicKey,
  }
}

export function publicKeyToHex(publicKey: Uint8Array): string {
  return Buffer.from(publicKey).toString('hex')
}

export function hexToPublicKey(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'))
}

export function secretKeyToHex(secretKey: Uint8Array): string {
  return Buffer.from(secretKey).toString('hex')
}

export function hexToSecretKey(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'))
}

export function canonicalise(payload: ReceiptPayload): Uint8Array {
  const sorted = Object.keys(payload)
    .sort()
    .reduce((acc: Record<string, unknown>, key) => {
      const val = (payload as unknown as Record<string, unknown>)[key]
      if (val !== undefined) acc[key] = val
      return acc
    }, {})
  return new TextEncoder().encode(JSON.stringify(sorted))
}export function signReceipt(
  payload: ReceiptPayload,
  keyPair: KeyPair
): SignedReceipt {
  const bytes = canonicalise(payload)
  const sigBytes = ml_dsa65.sign(bytes, keyPair.secretKey)
  return {
    ...payload,
    algorithm: 'ML-DSA-65',
    signature: Buffer.from(sigBytes).toString('hex'),
    publicKey: Buffer.from(keyPair.publicKey).toString('hex'),
  }
}

/** @deprecated INSECURE: trusts the public key inside the receipt, so anyone can forge a valid receipt. Use verifyReceiptV1 (spec/receipt.md). */
export function verifyReceipt(receipt: SignedReceipt): VerifyResult {
  if (receipt.algorithm !== 'ML-DSA-65') {
    return { valid: false, reason: 'unsupported_algorithm' }
  }
  const now = new Date()
  const expiresAt = new Date(receipt.expiresAt)
  if (now > expiresAt) {
    return { valid: false, reason: 'expired' }
  }
  if (receipt.status !== 'approved') {
    return { valid: false, reason: 'not_approved' }
  }
  if (receipt.principalValidUntil) {
    const principalExpiry = new Date(receipt.principalValidUntil)
    if (now > principalExpiry) {
      const policy = receipt.postDissolutionPolicy ?? 'reject'
      if (policy === 'reject') {
        return { valid: false, reason: 'principal_expired' }
      }
    }
  }
  try {
    const payload: ReceiptPayload = {
      receiptId:   receipt.receiptId,
      nonce:       receipt.nonce,
      version:     receipt.version,
      algorithm:   receipt.algorithm,
      status:      receipt.status,
      userId:      receipt.userId,
      agentId:     receipt.agentId,
      action:      receipt.action,
      timestamp:   receipt.timestamp,
      expiresAt:   receipt.expiresAt,
      ...(receipt.principalValidUntil   && { principalValidUntil:   receipt.principalValidUntil }),
      ...(receipt.dissolutionTrigger    && { dissolutionTrigger:    receipt.dissolutionTrigger }),
      ...(receipt.inheritorAgentId      && { inheritorAgentId:      receipt.inheritorAgentId }),
      ...(receipt.postDissolutionPolicy && { postDissolutionPolicy: receipt.postDissolutionPolicy }),
    }
    const bytes       = canonicalise(payload)
    const sigBytes    = Uint8Array.from(Buffer.from(receipt.signature, 'hex'))
    const pubKeyBytes = hexToPublicKey(receipt.publicKey)
    const valid = ml_dsa65.verify(sigBytes, bytes, pubKeyBytes)
    if (!valid) {
      return { valid: false, reason: 'invalid_signature' }
    }
  } catch {
    return { valid: false, reason: 'malformed_receipt' }
  }
  if (_usedNonces.has(receipt.nonce)) {
    return { valid: false, reason: 'replay_detected' }
  }
  _usedNonces.add(receipt.nonce)
  return { valid: true }
}

export function buildReceipt(
  config: {
    userId: string
    agentId: string
    action: string
    status: 'approved' | 'denied'
    ttlSeconds?: number
    principalValidUntil?: string
    dissolutionTrigger?: 'principal_deceased' | 'entity_dissolved' | 'key_revoked'
    inheritorAgentId?: string
    postDissolutionPolicy?: 'reject' | 'warn' | 'audit_only'
  },
    keyPair: KeyPair
): SignedReceipt {
  const now = new Date()
  const ttl = config.ttlSeconds ?? 300
  const payload: ReceiptPayload = {
    receiptId: crypto.randomUUID(),
    nonce:     crypto.randomUUID(),
    version:   '1.6',
    algorithm: 'ML-DSA-65',
    status:    config.status,
    userId:    config.userId,
    agentId:   config.agentId,
    action:    config.action,
    timestamp: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttl * 1000).toISOString(),
    ...(config.principalValidUntil   && { principalValidUntil:   config.principalValidUntil }),
    ...(config.dissolutionTrigger    && { dissolutionTrigger:    config.dissolutionTrigger }),
    ...(config.inheritorAgentId      && { inheritorAgentId:      config.inheritorAgentId }),
    ...(config.postDissolutionPolicy && { postDissolutionPolicy: config.postDissolutionPolicy }),
  }
    return signReceipt(payload, keyPair)
}
