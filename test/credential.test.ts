import { describe, it, expect } from 'vitest';
import { jcs } from '../src/jcs.js';
import {
  createCredential,
  createHolderBinding,
  generateKeypair,
  createDID,
} from '../src/index.js';

describe('jcs (canonicalize)', () => {
  it('produces deterministic output regardless of key insertion order', () => {
    const a = { z: 1, a: 2, m: 3 };
    const b = { a: 2, m: 3, z: 1 };
    expect(jcs(a)).toBe(jcs(b));
    expect(jcs(a)).toBe('{"a":2,"m":3,"z":1}');
  });

  it('handles nested objects deterministically', () => {
    const a = { b: { z: 1, a: 2 }, a: 1 };
    const b = { a: 1, b: { a: 2, z: 1 } };
    expect(jcs(a)).toBe(jcs(b));
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

  it('includes validUntil when provided', () => {
    const keypair = generateKeypair();
    const expiry = new Date(Date.now() + 3600_000).toISOString();
    const credential = createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
      validUntil: expiry,
    });

    expect(credential.validUntil).toBe(expiry);
  });

  it('omits validUntil when not provided', () => {
    const keypair = generateKeypair();
    const credential = createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    expect(credential).not.toHaveProperty('validUntil');
  });

  it('generates unique IDs for each credential', () => {
    const keypair = generateKeypair();
    const payload = { task: 'test', outcome: 'pass' };
    const a = createCredential({ keypair, payload });
    const b = createCredential({ keypair, payload });
    expect(a.id).not.toBe(b.id);
  });

  it('includes credentialStatus with matching id', () => {
    const keypair = generateKeypair();
    const credential = createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    expect(credential.credentialStatus).toEqual({
      type: 'LogposeRevocation',
      id: credential.id,
    });
  });

  it('includes holderBinding in credentialSubject when provided', () => {
    const issuerKp = generateKeypair();
    const subjectKp = generateKeypair();
    const binding = createHolderBinding(subjectKp, 'my-challenge');

    const credential = createCredential({
      keypair: issuerKp,
      subject: createDID(subjectKp.publicKey),
      payload: { task: 'audit', outcome: 'clean' },
      holderBinding: binding,
    });

    expect(credential.credentialSubject.holderBinding).toEqual(binding);
  });

  it('omits holderBinding when not provided', () => {
    const keypair = generateKeypair();
    const credential = createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    expect(credential.credentialSubject).not.toHaveProperty('holderBinding');
  });
});
