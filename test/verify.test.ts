import { describe, it, expect, beforeEach } from 'vitest';
import {
  createCredential,
  createHolderBinding,
  generateKeypair,
  verifyCredential,
  trustIssuer,
  loadRegistry,
  exportRegistry,
  createDID,
  MemoryStore,
} from '../src/index.js';
import type { Credential } from '../src/index.js';

function makeCredential(opts?: { validUntil?: string }): Credential {
  const keypair = generateKeypair();
  return createCredential({
    keypair,
    payload: { task: 'test', outcome: 'pass' },
    validUntil: opts?.validUntil,
  });
}

describe('verifyCredential', () => {
  beforeEach(() => {
    loadRegistry([]);
  });

  it('validates a correctly signed credential', async () => {
    const credential = makeCredential();
    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.expired).toBe(false);
    expect(result.revoked).toBe(false);
    expect(result.holderVerified).toBe(true); // self-attestation
  });

  it('rejects a credential with tampered payload', async () => {
    const credential = makeCredential();
    const tampered = {
      ...credential,
      credentialSubject: { ...credential.credentialSubject, outcome: 'fail' },
    };
    const result = await verifyCredential(tampered);
    expect(result.valid).toBe(false);
  });

  it('rejects a credential with tampered signature', async () => {
    const credential = makeCredential();
    const tampered = {
      ...credential,
      proof: { ...credential.proof, proofValue: '00'.repeat(64) },
    };
    const result = await verifyCredential(tampered);
    expect(result.valid).toBe(false);
  });

  it('validates a credential after JSON round-trip', async () => {
    const credential = makeCredential();
    const roundTripped = JSON.parse(JSON.stringify(credential)) as Credential;
    const result = await verifyCredential(roundTripped);
    expect(result.valid).toBe(true);
  });

  it('returns valid=false for a credential with garbage issuer DID', async () => {
    const credential = makeCredential();
    const tampered = { ...credential, issuer: 'did:key:zGARBAGE' };
    const result = await verifyCredential(tampered);
    expect(result.valid).toBe(false);
  });
});

describe('trust registry (global)', () => {
  beforeEach(() => {
    loadRegistry([]);
  });

  it('returns issuerTrusted=true when registry is empty (permissive mode)', async () => {
    const credential = makeCredential();
    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.issuerTrusted).toBe(true);
  });

  it('returns issuerTrusted=false for untrusted issuer', async () => {
    const otherKeypair = generateKeypair();
    trustIssuer(createDID(otherKeypair.publicKey));

    const credential = makeCredential();
    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.issuerTrusted).toBe(false);
  });

  it('exportRegistry returns all trusted DIDs', () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    const did1 = createDID(kp1.publicKey);
    const did2 = createDID(kp2.publicKey);

    trustIssuer(did1);
    trustIssuer(did2);

    const exported = exportRegistry();
    expect(exported).toContain(did1);
    expect(exported).toContain(did2);
    expect(exported).toHaveLength(2);
  });

  it('loadRegistry replaces existing entries', () => {
    const kp = generateKeypair();
    const did = createDID(kp.publicKey);
    trustIssuer(did);
    expect(exportRegistry()).toHaveLength(1);

    loadRegistry([]);
    expect(exportRegistry()).toHaveLength(0);
  });
});

describe('injectable trust (options.trustedIssuers)', () => {
  beforeEach(() => {
    loadRegistry([]);
  });

  it('uses injected array instead of global registry', async () => {
    const keypair = generateKeypair();
    const credential = createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    const otherDID = createDID(generateKeypair().publicKey);
    const result = await verifyCredential(credential, { trustedIssuers: [otherDID] });
    expect(result.valid).toBe(true);
    expect(result.issuerTrusted).toBe(false);
  });

  it('uses injected Set instead of global registry', async () => {
    const keypair = generateKeypair();
    const credential = createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    const issuerDID = createDID(keypair.publicKey);
    const result = await verifyCredential(credential, {
      trustedIssuers: new Set([issuerDID]),
    });
    expect(result.valid).toBe(true);
    expect(result.issuerTrusted).toBe(true);
  });

  it('empty injected set is permissive (matches global behavior)', async () => {
    const credential = makeCredential();
    const result = await verifyCredential(credential, { trustedIssuers: [] });
    expect(result.issuerTrusted).toBe(true);
  });

  it('injected trust does not affect global registry', async () => {
    const keypair = generateKeypair();
    const did = createDID(keypair.publicKey);

    await verifyCredential(makeCredential(), { trustedIssuers: [did] });
    expect(exportRegistry()).toHaveLength(0);
  });
});

describe('expiry (validUntil)', () => {
  beforeEach(() => {
    loadRegistry([]);
  });

  it('credential without validUntil is not expired', async () => {
    const credential = makeCredential();
    const result = await verifyCredential(credential);
    expect(result.expired).toBe(false);
  });

  it('credential with future validUntil is not expired', async () => {
    const credential = makeCredential({
      validUntil: new Date(Date.now() + 86400_000).toISOString(),
    });
    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.expired).toBe(false);
  });

  it('credential with past validUntil is expired', async () => {
    const credential = makeCredential({
      validUntil: new Date(Date.now() - 1000).toISOString(),
    });
    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.expired).toBe(true);
  });

  it('expiry check can be disabled via checkExpiry: false', async () => {
    const credential = makeCredential({
      validUntil: new Date(Date.now() - 1000).toISOString(),
    });
    const result = await verifyCredential(credential, { checkExpiry: false });
    expect(result.expired).toBe(false);
  });
});

describe('revocation', () => {
  beforeEach(() => {
    loadRegistry([]);
  });

  it('credential is not revoked by default (no store)', async () => {
    const credential = makeCredential();
    const result = await verifyCredential(credential);
    expect(result.revoked).toBe(false);
  });

  it('credential is not revoked when store says no', async () => {
    const store = new MemoryStore();
    const credential = makeCredential();
    await store.save(credential);

    const result = await verifyCredential(credential, { store });
    expect(result.revoked).toBe(false);
  });

  it('credential is revoked after store.revoke()', async () => {
    const store = new MemoryStore();
    const credential = makeCredential();
    await store.save(credential);
    await store.revoke(credential.id);

    const result = await verifyCredential(credential, { store });
    expect(result.valid).toBe(true);
    expect(result.revoked).toBe(true);
  });
});

describe('holder binding', () => {
  beforeEach(() => {
    loadRegistry([]);
  });

  it('self-attestation without binding: holderVerified=true', async () => {
    const credential = makeCredential();
    const result = await verifyCredential(credential);
    expect(result.holderVerified).toBe(true);
  });

  it('third-party attestation without binding: holderVerified=false', async () => {
    const issuerKp = generateKeypair();
    const subjectKp = generateKeypair();
    const credential = createCredential({
      keypair: issuerKp,
      subject: createDID(subjectKp.publicKey),
      payload: { task: 'audit', outcome: 'clean' },
    });

    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.holderVerified).toBe(false);
  });

  it('third-party attestation with valid binding: holderVerified=true', async () => {
    const issuerKp = generateKeypair();
    const subjectKp = generateKeypair();
    const binding = createHolderBinding(subjectKp, 'consent-challenge-123');

    const credential = createCredential({
      keypair: issuerKp,
      subject: createDID(subjectKp.publicKey),
      payload: { task: 'audit', outcome: 'clean' },
      holderBinding: binding,
    });

    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.holderVerified).toBe(true);
  });

  it('third-party attestation with wrong-key binding: holderVerified=false', async () => {
    const issuerKp = generateKeypair();
    const subjectKp = generateKeypair();
    const wrongKp = generateKeypair();
    // Binding signed by wrong key (not the subject)
    const binding = createHolderBinding(wrongKp, 'consent-challenge');

    const credential = createCredential({
      keypair: issuerKp,
      subject: createDID(subjectKp.publicKey),
      payload: { task: 'audit', outcome: 'clean' },
      holderBinding: binding,
    });

    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.holderVerified).toBe(false);
  });

  it('binding with tampered challenge: valid credential but holderVerified=false', async () => {
    const issuerKp = generateKeypair();
    const subjectKp = generateKeypair();
    const binding = createHolderBinding(subjectKp, 'original-challenge');

    // Tamper challenge BEFORE signing — credential sig is valid,
    // but holder binding sig was for 'original-challenge'
    const credential = createCredential({
      keypair: issuerKp,
      subject: createDID(subjectKp.publicKey),
      payload: { task: 'audit', outcome: 'clean' },
      holderBinding: { ...binding, challenge: 'tampered-challenge' },
    });

    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.holderVerified).toBe(false);
  });
});
