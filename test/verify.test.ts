import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  createCredential,
  createHolderBinding,
  generateKeypair,
  verifyCredential,
  verifyBatch,
  trustIssuer,
  loadRegistry,
  exportRegistry,
  createDID,
  MemoryStore,
} from '../src/index.js';
import type { Credential } from '../src/index.js';

async function makeCredential(opts?: {
  validUntil?: string;
  audience?: string;
  aud?: string;
}): Promise<Credential> {
  const keypair = await generateKeypair();
  return createCredential({
    keypair,
    payload: { task: 'test', outcome: 'pass' },
    validUntil: opts?.validUntil,
    audience: opts?.audience,
    aud: opts?.aud,
  });
}

describe('verifyCredential', () => {
  beforeEach(() => {
    loadRegistry([]);
  });

  it('validates a correctly signed credential', async () => {
    const credential = await makeCredential();
    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.expired).toBe(false);
    expect(result.revoked).toBe(false);
    expect(result.holderVerified).toBe(true);
  });

  it('rejects a credential with tampered payload', async () => {
    const credential = await makeCredential();
    const tampered = {
      ...credential,
      credentialSubject: { ...credential.credentialSubject, outcome: 'fail' },
    };
    const result = await verifyCredential(tampered);
    expect(result.valid).toBe(false);
  });

  it('rejects a credential with tampered signature', async () => {
    const credential = await makeCredential();
    const tampered = {
      ...credential,
      proof: { ...credential.proof, proofValue: '00'.repeat(64) },
    };
    const result = await verifyCredential(tampered);
    expect(result.valid).toBe(false);
  });

  it('validates a credential after JSON round-trip', async () => {
    const credential = await makeCredential();
    const roundTripped = JSON.parse(JSON.stringify(credential)) as Credential;
    const result = await verifyCredential(roundTripped);
    expect(result.valid).toBe(true);
  });

  it('returns valid=false for a credential with garbage issuer DID', async () => {
    const credential = await makeCredential();
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
    const credential = await makeCredential();
    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.issuerTrusted).toBe(true);
  });

  it('returns issuerTrusted=false for untrusted issuer', async () => {
    const otherKeypair = await generateKeypair();
    trustIssuer(createDID(otherKeypair.publicKey));

    const credential = await makeCredential();
    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.issuerTrusted).toBe(false);
  });

  it('exportRegistry returns all trusted DIDs', async () => {
    const kp1 = await generateKeypair();
    const kp2 = await generateKeypair();
    const did1 = createDID(kp1.publicKey);
    const did2 = createDID(kp2.publicKey);

    trustIssuer(did1);
    trustIssuer(did2);

    const exported = exportRegistry();
    expect(exported).toContain(did1);
    expect(exported).toContain(did2);
    expect(exported).toHaveLength(2);
  });

  it('loadRegistry replaces existing entries', async () => {
    const kp = await generateKeypair();
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
    const keypair = await generateKeypair();
    const credential = await createCredential({
      keypair,
      payload: { task: 'test', outcome: 'pass' },
    });

    const otherDID = createDID((await generateKeypair()).publicKey);
    const result = await verifyCredential(credential, { trustedIssuers: [otherDID] });
    expect(result.valid).toBe(true);
    expect(result.issuerTrusted).toBe(false);
  });

  it('uses injected Set instead of global registry', async () => {
    const keypair = await generateKeypair();
    const credential = await createCredential({
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
    const credential = await makeCredential();
    const result = await verifyCredential(credential, { trustedIssuers: [] });
    expect(result.issuerTrusted).toBe(true);
  });

  it('injected trust does not affect global registry', async () => {
    const keypair = await generateKeypair();
    const did = createDID(keypair.publicKey);

    await verifyCredential(await makeCredential(), { trustedIssuers: [did] });
    expect(exportRegistry()).toHaveLength(0);
  });
});

describe('expiry (validUntil)', () => {
  beforeEach(() => {
    loadRegistry([]);
  });

  it('credential without validUntil is not expired', async () => {
    const credential = await makeCredential();
    const result = await verifyCredential(credential);
    expect(result.expired).toBe(false);
  });

  it('credential with future validUntil is not expired', async () => {
    const credential = await makeCredential({
      validUntil: new Date(Date.now() + 86400_000).toISOString(),
    });
    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.expired).toBe(false);
  });

  it('credential with past validUntil is expired', async () => {
    const credential = await makeCredential({
      validUntil: new Date(Date.now() - 1000).toISOString(),
    });
    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.expired).toBe(true);
  });

  it('expiry check can be disabled via checkExpiry: false', async () => {
    const credential = await makeCredential({
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
    const credential = await makeCredential();
    const result = await verifyCredential(credential);
    expect(result.revoked).toBe(false);
  });

  it('credential is not revoked when store says no', async () => {
    const store = new MemoryStore();
    const credential = await makeCredential();
    await store.save(credential);

    const result = await verifyCredential(credential, { store });
    expect(result.revoked).toBe(false);
  });

  it('credential is revoked after store.revoke()', async () => {
    const store = new MemoryStore();
    const credential = await makeCredential();
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
    const credential = await makeCredential();
    const result = await verifyCredential(credential);
    expect(result.holderVerified).toBe(true);
  });

  it('third-party attestation without binding: holderVerified=false', async () => {
    const issuerKp = await generateKeypair();
    const subjectKp = await generateKeypair();
    const credential = await createCredential({
      keypair: issuerKp,
      subject: createDID(subjectKp.publicKey),
      payload: { task: 'audit', outcome: 'clean' },
    });

    const result = await verifyCredential(credential);
    expect(result.valid).toBe(true);
    expect(result.holderVerified).toBe(false);
  });

  it('third-party attestation with valid binding: holderVerified=true', async () => {
    const issuerKp = await generateKeypair();
    const subjectKp = await generateKeypair();
    const binding = await createHolderBinding(subjectKp, 'consent-challenge-123');

    const credential = await createCredential({
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
    const issuerKp = await generateKeypair();
    const subjectKp = await generateKeypair();
    const wrongKp = await generateKeypair();
    const binding = await createHolderBinding(wrongKp, 'consent-challenge');

    const credential = await createCredential({
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
    const issuerKp = await generateKeypair();
    const subjectKp = await generateKeypair();
    const binding = await createHolderBinding(subjectKp, 'original-challenge');

    const credential = await createCredential({
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

describe('audience binding', () => {
  beforeEach(() => {
    loadRegistry([]);
  });

  it('accepts matching expectedAudience', async () => {
    const credential = await makeCredential({ audience: 'https://agent.example' });
    const result = await verifyCredential(credential, {
      expectedAudience: 'https://agent.example',
    });

    expect(result.valid).toBe(true);
  });

  it('throws when expectedAudience does not match aud', async () => {
    const credential = await makeCredential({ audience: 'https://agent.example' });

    await expect(
      verifyCredential(credential, { expectedAudience: 'https://other.example' }),
    ).rejects.toThrow('Credential audience mismatch');
  });

  it('throws when expectedAudience is set but aud is missing', async () => {
    const credential = await makeCredential();

    await expect(
      verifyCredential(credential, { expectedAudience: 'https://agent.example' }),
    ).rejects.toThrow('Credential audience mismatch');
  });
});

describe('verifyBatch', () => {
  beforeEach(() => {
    loadRegistry([]);
  });

  it('verifies multiple credentials in one call', async () => {
    const credentials = [await makeCredential(), await makeCredential(), await makeCredential()];
    const results = await verifyBatch(credentials);

    expect(results).toHaveLength(3);
    expect(results.every((result) => result.valid)).toBe(true);
  });

  it('deduplicates revocation lookups with a single batch fetch', async () => {
    const credentials = [await makeCredential(), await makeCredential(), await makeCredential()];
    const fetcher = vi.fn(async (statusIds: string[]) => {
      return Object.fromEntries(statusIds.map((statusId) => [statusId, false]));
    });

    const results = await verifyBatch(credentials, { revocationBatchFetcher: fetcher });

    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledWith(
      expect.arrayContaining(credentials.map((credential) => credential.credentialStatus.id)),
    );
    expect(results.every((result) => result.revoked === false)).toBe(true);
  });

  it('reuses revocation cache and skips batch fetch when values are cached', async () => {
    const credential = await makeCredential();
    const cache = new Map<string, boolean>([[credential.credentialStatus.id, true]]);
    const fetcher = vi.fn(async (_statusIds: string[]) => ({}));

    const [result] = await verifyBatch([credential], {
      revocationCache: cache,
      revocationBatchFetcher: fetcher,
    });

    expect(fetcher).not.toHaveBeenCalled();
    expect(result.revoked).toBe(true);
  });
});
