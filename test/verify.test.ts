import { describe, it, expect, beforeEach } from 'vitest';
import {
  createCredential,
  generateKeypair,
  verifyCredential,
  trustIssuer,
  untrustIssuer,
  loadRegistry,
  createDID,
} from '../src/index.js';
import type { Credential } from '../src/index.js';

function makeCredential(): Credential {
  const keypair = generateKeypair();
  return createCredential({
    keypair,
    payload: { task: 'test', outcome: 'pass' },
  });
}

describe('verifyCredential', () => {
  beforeEach(() => {
    loadRegistry([]);
  });

  it('validates a correctly signed credential', () => {
    const credential = makeCredential();
    const result = verifyCredential(credential);
    expect(result.valid).toBe(true);
  });

  it('rejects a credential with tampered payload', () => {
    const credential = makeCredential();
    const tampered = {
      ...credential,
      credentialSubject: { ...credential.credentialSubject, outcome: 'fail' },
    };
    const result = verifyCredential(tampered);
    expect(result.valid).toBe(false);
  });

  it('rejects a credential with tampered signature', () => {
    const credential = makeCredential();
    const tampered = {
      ...credential,
      proof: { ...credential.proof, proofValue: '00'.repeat(64) },
    };
    const result = verifyCredential(tampered);
    expect(result.valid).toBe(false);
  });

  it('returns issuerTrusted=false for untrusted issuer', () => {
    const keypair = generateKeypair();
    const credential = createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    const otherKeypair = generateKeypair();
    trustIssuer(createDID(otherKeypair.publicKey));

    const result = verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.issuerTrusted).toBe(false);
  });

  it('returns issuerTrusted=true when registry is empty (permissive mode)', () => {
    const credential = makeCredential();
    const result = verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.issuerTrusted).toBe(true);
  });
});
