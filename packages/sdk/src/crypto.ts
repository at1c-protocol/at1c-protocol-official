import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { randomBytes } from '@noble/hashes/utils'

export interface KeyPair {
  secretKey: Uint8Array
  publicKey: Uint8Array
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
