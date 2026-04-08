import { describe, it, expect } from 'vitest';
import canonicalize from 'canonicalize';
import { createCredential, generateKeypair, createDID } from '../src/index.js';

describe('canonicalize', () => {
  it('produces deterministic output regardless of key insertion order', () => {
    const a = { z: 1, a: 2, m: 3 };
    const b = { a: 2, m: 3, z: 1 };
    expect(canonicalize(a)).toBe(canonicalize(b));
    expect(canonicalize(a)).toBe('{"a":2,"m":3,"z":1}');
  });
});

describe('createCredential', () => {
  it('creates credentials with valid URN UUIDs', () => {
    const keypair = generateKeypair();
    const credential = createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    expect(credential.id).toMatch(
      /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it('self-attests when no subject provided', () => {
    const keypair = generateKeypair();
    const credential = createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    expect(credential.credentialSubject.id).toBe(credential.issuer);
  });

  it('uses provided subject DID when given', () => {
    const issuerKeypair = generateKeypair();
    const subjectKeypair = generateKeypair();
    const subjectDID = createDID(subjectKeypair.publicKey);

    const credential = createCredential({
      keypair: issuerKeypair,
      subject: subjectDID,
      payload: { task: 'audit', outcome: 'clean' },
    });

    expect(credential.credentialSubject.id).toBe(subjectDID);
    expect(credential.credentialSubject.id).not.toBe(credential.issuer);
  });

  it('omits evidence from credentialSubject when not provided', () => {
    const keypair = generateKeypair();
    const credential = createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    expect(credential.credentialSubject).not.toHaveProperty('evidence');
  });
});
