import { describe, it, expect } from 'vitest'
import { generateKeyPair, publicKeyToHex } from '../src/crypto'

// ─── Key Generation ──────────────────────────────────────
// The pre-v1 receipt functions were removed in 2.0.0. Replay protection is tested in approverGate.test.ts.

describe('generateKeyPair', () => {
  it('generates a keypair with correct byte lengths', () => {
    const { secretKey, publicKey } = generateKeyPair()
    expect(secretKey).toBeInstanceOf(Uint8Array)
    expect(publicKey).toBeInstanceOf(Uint8Array)
    expect(secretKey.length).toBe(4032)
    expect(publicKey.length).toBe(1952)
  })

  it('generates unique keypairs each time', () => {
    const a = generateKeyPair()
    const b = generateKeyPair()
    expect(publicKeyToHex(a.publicKey)).not.toBe(publicKeyToHex(b.publicKey))
  })
})
