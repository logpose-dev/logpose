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
  it('creates credentials with valid URN UUIDs', async () => {
    const keypair = await generateKeypair();
    const credential = await createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    expect(credential.id).toMatch(
      /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
  });

  it('self-attests when no subject provided', async () => {
    const keypair = await generateKeypair();
    const credential = await createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    expect(credential.credentialSubject.id).toBe(credential.issuer);
  });

  it('uses provided subject DID when given', async () => {
    const issuerKeypair = await generateKeypair();
    const subjectKeypair = await generateKeypair();
    const subjectDID = createDID(subjectKeypair.publicKey);

    const credential = await createCredential({
      keypair: issuerKeypair,
      subject: subjectDID,
      payload: { task: 'audit', outcome: 'clean' },
    });

    expect(credential.credentialSubject.id).toBe(subjectDID);
    expect(credential.credentialSubject.id).not.toBe(credential.issuer);
  });

  it('omits evidence from credentialSubject when not provided', async () => {
    const keypair = await generateKeypair();
    const credential = await createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    expect(credential.credentialSubject).not.toHaveProperty('evidence');
  });

  it('includes validUntil when provided', async () => {
    const keypair = await generateKeypair();
    const expiry = new Date(Date.now() + 3600_000).toISOString();
    const credential = await createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
      validUntil: expiry,
    });

    expect(credential.validUntil).toBe(expiry);
  });

  it('omits validUntil when not provided', async () => {
    const keypair = await generateKeypair();
    const credential = await createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    expect(credential).not.toHaveProperty('validUntil');
  });

  it('generates unique IDs for each credential', async () => {
    const keypair = await generateKeypair();
    const payload = { task: 'test', outcome: 'pass' };
    const a = await createCredential({ keypair, payload });
    const b = await createCredential({ keypair, payload });
    expect(a.id).not.toBe(b.id);
  });

  it('includes credentialStatus with matching id', async () => {
    const keypair = await generateKeypair();
    const credential = await createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    expect(credential.credentialStatus).toEqual({
      type: 'LogposeRevocation',
      id: credential.id,
    });
  });

  it('includes holderBinding in credentialSubject when provided', async () => {
    const issuerKp = await generateKeypair();
    const subjectKp = await generateKeypair();
    const binding = await createHolderBinding(subjectKp, 'my-challenge');

    const credential = await createCredential({
      keypair: issuerKp,
      subject: createDID(subjectKp.publicKey),
      payload: { task: 'audit', outcome: 'clean' },
      holderBinding: binding,
    });

    expect(credential.credentialSubject.holderBinding).toEqual(binding);
  });

  it('omits holderBinding when not provided', async () => {
    const keypair = await generateKeypair();
    const credential = await createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    expect(credential.credentialSubject).not.toHaveProperty('holderBinding');
  });

  it('includes aud claim when audience is provided', async () => {
    const keypair = await generateKeypair();
    const credential = await createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
      audience: 'https://verifier.example',
    });

    expect(credential.aud).toBe('https://verifier.example');
  });

  it('aud takes precedence over audience when both are provided', async () => {
    const keypair = await generateKeypair();
    const credential = await createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
      audience: 'https://wrong.example',
      aud: 'https://right.example',
    });

    expect(credential.aud).toBe('https://right.example');
  });
});
