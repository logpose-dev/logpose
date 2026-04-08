import { describe, it, expect } from 'vitest';
import {
  generateKeypair,
  keypairFromPrivateKey,
  bytesToHex,
  createDID,
  parseDID,
  isValidDID,
} from '../src/index.js';

describe('keypair', () => {
  it('generates a keypair with 32-byte keys', () => {
    const kp = generateKeypair();
    expect(kp.privateKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey).toBeInstanceOf(Uint8Array);
    expect(kp.publicKey.length).toBe(32);
  });

  it('restores a keypair from hex private key', () => {
    const original = generateKeypair();
    const hex = bytesToHex(original.privateKey);
    const restored = keypairFromPrivateKey(hex);
    expect(bytesToHex(restored.publicKey)).toBe(bytesToHex(original.publicKey));
  });

  it('throws on invalid hex input', () => {
    expect(() => keypairFromPrivateKey('not-hex')).toThrow();
    expect(() => keypairFromPrivateKey('')).toThrow();
  });
});

describe('DID', () => {
  it('round-trips: createDID → parseDID returns the same public key', () => {
    const kp = generateKeypair();
    const did = createDID(kp.publicKey);
    const parsed = parseDID(did);
    expect(bytesToHex(parsed)).toBe(bytesToHex(kp.publicKey));
  });

  it('creates a did:key starting with did:key:z', () => {
    const kp = generateKeypair();
    const did = createDID(kp.publicKey);
    expect(did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
  });

  it('isValidDID returns true for valid DIDs', () => {
    const kp = generateKeypair();
    const did = createDID(kp.publicKey);
    expect(isValidDID(did)).toBe(true);
  });

  it('isValidDID returns false for garbage input', () => {
    expect(isValidDID('')).toBe(false);
    expect(isValidDID('did:key:z')).toBe(false);
    expect(isValidDID('did:web:example.com')).toBe(false);
    expect(isValidDID('not-a-did')).toBe(false);
  });

  it('parseDID throws on non-did:key input', () => {
    expect(() => parseDID('did:web:example.com')).toThrow('Invalid did:key format');
  });

  it('parseDID throws on wrong multicodec prefix', () => {
    // Encode a key with wrong prefix (0x00, 0x00 instead of 0xed, 0x01)
    expect(() => parseDID('did:key:z11111111111111111111111111111111111')).toThrow();
  });

  it('createDID throws on wrong-length public key', () => {
    expect(() => createDID(new Uint8Array(16))).toThrow('Expected 32-byte');
    expect(() => createDID(new Uint8Array(64))).toThrow('Expected 32-byte');
  });

  it('parseDID throws on truncated key (wrong length after decode)', () => {
    // Manually create a DID with multicodec prefix + only 10 bytes
    const { base58 } = require('@scure/base') as typeof import('@scure/base');
    const short = new Uint8Array([0xed, 0x01, ...new Array(10).fill(0)]);
    const fakeDID = `did:key:z${base58.encode(short)}`;
    expect(() => parseDID(fakeDID)).toThrow('Invalid Ed25519 public key length');
  });
});
