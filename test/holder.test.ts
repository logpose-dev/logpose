import { describe, it, expect } from 'vitest';
import { createHolderBinding, generateKeypair, bytesToHex, hexToBytes } from '../src/index.js';
import { verify } from '../src/identity/keypair.js';

describe('createHolderBinding', () => {
  it('returns correct shape', () => {
    const kp = generateKeypair();
    const binding = createHolderBinding(kp, 'test-challenge');

    expect(binding.type).toBe('Ed25519HolderBinding');
    expect(binding.challenge).toBe('test-challenge');
    expect(binding.signature).toMatch(/^[0-9a-f]+$/);
  });

  it('signature is verifiable with the keypair public key', () => {
    const kp = generateKeypair();
    const binding = createHolderBinding(kp, 'verify-me');

    const message = new TextEncoder().encode('verify-me');
    const sig = hexToBytes(binding.signature);
    expect(verify(sig, message, kp.publicKey)).toBe(true);
  });

  it('different challenges produce different signatures', () => {
    const kp = generateKeypair();
    const a = createHolderBinding(kp, 'challenge-a');
    const b = createHolderBinding(kp, 'challenge-b');
    expect(a.signature).not.toBe(b.signature);
  });

  it('different keypairs produce different signatures for same challenge', () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    const a = createHolderBinding(kp1, 'same-challenge');
    const b = createHolderBinding(kp2, 'same-challenge');
    expect(a.signature).not.toBe(b.signature);
  });
});
