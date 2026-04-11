import { describe, it, expect } from 'vitest';
import { createHolderBinding, generateKeypair, bytesToHex, hexToBytes } from '../src/index.js';
import { verify } from '../src/identity/keypair.js';

describe('createHolderBinding', () => {
  it('returns correct shape', async () => {
    const kp = await generateKeypair();
    const binding = await createHolderBinding(kp, 'test-challenge');

    expect(binding.type).toBe('Ed25519HolderBinding');
    expect(binding.challenge).toBe('test-challenge');
    expect(binding.signature).toMatch(/^[0-9a-f]+$/);
  });

  it('signature is verifiable with the keypair public key', async () => {
    const kp = await generateKeypair();
    const binding = await createHolderBinding(kp, 'verify-me');

    const message = new TextEncoder().encode('verify-me');
    const sig = hexToBytes(binding.signature);
    expect(await verify(sig, message, kp.publicKey)).toBe(true);
  });

  it('different challenges produce different signatures', async () => {
    const kp = await generateKeypair();
    const a = await createHolderBinding(kp, 'challenge-a');
    const b = await createHolderBinding(kp, 'challenge-b');
    expect(a.signature).not.toBe(b.signature);
  });

  it('different keypairs produce different signatures for same challenge', async () => {
    const kp1 = await generateKeypair();
    const kp2 = await generateKeypair();
    const a = await createHolderBinding(kp1, 'same-challenge');
    const b = await createHolderBinding(kp2, 'same-challenge');
    expect(a.signature).not.toBe(b.signature);
  });
});
