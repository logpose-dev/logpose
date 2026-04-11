import { describe, it, expect } from 'vitest';
import {
  bytesToHex,
  createAttestor,
  createHolderBinding,
  generateKeypair,
  isValidDID,
  verifyCredential,
} from '../src/index.js';
import type { Credential, CredentialFilter, ICredentialStore } from '../src/index.js';

describe('createAttestor', () => {
  it('creates an attestor with a valid did:key DID', async () => {
    const attestor = await createAttestor();
    expect(attestor.did).toMatch(/^did:key:z/);
    expect(isValidDID(attestor.did)).toBe(true);
  });

  it('records a credential with correct VC structure', async () => {
    const attestor = await createAttestor();
    const credential = await attestor.record({
      task: 'code-review',
      outcome: 'approved',
      evidence: { pr: 42 },
    });

    expect(credential['@context']).toEqual([
      'https://www.w3.org/ns/credentials/v2',
      'https://w3id.org/security/data-integrity/v2',
    ]);
    expect(credential.type).toEqual(['VerifiableCredential', 'LogposeAttestation']);
    expect(credential.issuer).toBe(attestor.did);
    expect(credential.credentialSubject.task).toBe('code-review');
    expect(credential.credentialSubject.outcome).toBe('approved');
    expect(credential.credentialSubject.evidence).toEqual({ pr: 42 });
    expect(credential.proof.type).toBe('Ed25519Signature2024');
    expect(credential.proof.proofPurpose).toBe('assertionMethod');
    expect(credential.credentialStatus).toEqual({
      type: 'LogposeRevocation',
      id: credential.id,
    });
  });

  it('retrieves a credential by ID after recording', async () => {
    const attestor = await createAttestor();
    const credential = await attestor.record({
      task: 'deploy',
      outcome: 'success',
    });

    const retrieved = await attestor.get(credential.id);
    expect(retrieved).toEqual(credential);

    const viaStoreAlias = await attestor.store.get(credential.id);
    expect(viaStoreAlias).toEqual(credential);
  });

  it('lists and filters credentials by task', async () => {
    const attestor = await createAttestor();
    await attestor.record({ task: 'build', outcome: 'pass' });
    await attestor.record({ task: 'test', outcome: 'pass' });
    await attestor.record({ task: 'build', outcome: 'fail' });

    const builds = await attestor.list({ task: 'build' });
    expect(builds).toHaveLength(2);
    expect(builds.every((c) => c.credentialSubject.task === 'build')).toBe(true);

    const total = await attestor.count();
    expect(total).toBe(3);
  });

  it('preserves identity across attestors using getPrivateKeyHex()', async () => {
    const first = await createAttestor();
    const second = await createAttestor({ privateKey: first.getPrivateKeyHex() });
    expect(second.did).toBe(first.did);
    expect(second.getPrivateKeyHex()).toBe(first.getPrivateKeyHex());
  });

  it('getPrivateKeyHex() is not enumerable via JSON.stringify', async () => {
    const attestor = await createAttestor();
    const json = JSON.stringify(attestor);
    expect(json).not.toContain(attestor.getPrivateKeyHex());
  });

  it('records credential with subject via options bag', async () => {
    const issuer = await createAttestor();
    const subject = await createAttestor();
    const credential = await issuer.record(
      { task: 'audit', outcome: 'clean' },
      { subject: subject.did },
    );
    expect(credential.credentialSubject.id).toBe(subject.did);
    expect(credential.issuer).toBe(issuer.did);
  });

  it('records credential with validUntil via options bag', async () => {
    const attestor = await createAttestor();
    const expiry = new Date(Date.now() + 86400_000).toISOString();
    const credential = await attestor.record(
      { task: 'deploy', outcome: 'success' },
      { validUntil: expiry },
    );
    expect(credential.validUntil).toBe(expiry);
  });

  it('records credential with holder binding via options bag', async () => {
    const issuer = await createAttestor();
    const subjectKp = await generateKeypair();
    const subject = await createAttestor({ privateKey: bytesToHex(subjectKp.privateKey) });
    const binding = await createHolderBinding(subjectKp, 'consent-challenge');

    const credential = await issuer.record(
      { task: 'audit', outcome: 'clean' },
      { subject: subject.did, holderBinding: binding },
    );
    expect(credential.credentialSubject.holderBinding).toEqual(binding);
  });

  it('records credential with audience via options bag', async () => {
    const issuer = await createAttestor();
    const credential = await issuer.record(
      { task: 'audit', outcome: 'clean' },
      { audience: 'https://verifier.example' },
    );

    expect(credential.aud).toBe('https://verifier.example');
  });

  it('uses an injected pluggable ICredentialStore', async () => {
    const credentials = new Map<string, Credential>();
    const revoked = new Set<string>();

    const store: ICredentialStore = {
      async save(credential: Credential): Promise<void> {
        credentials.set(credential.id, credential);
      },
      async load(id: string): Promise<Credential | undefined> {
        return credentials.get(id);
      },
      async delete(id: string): Promise<void> {
        credentials.delete(id);
        revoked.delete(id);
      },
      async list(filter?: CredentialFilter): Promise<Credential[]> {
        const all = [...credentials.values()];
        if (!filter?.task) {
          return all;
        }
        return all.filter((credential) => credential.credentialSubject.task === filter.task);
      },
      async count(filter?: CredentialFilter): Promise<number> {
        const all = await this.list(filter);
        return all.length;
      },
      async revoke(id: string): Promise<void> {
        revoked.add(id);
      },
      async isRevoked(id: string): Promise<boolean> {
        return revoked.has(id);
      },
    };

    const attestor = await createAttestor({ store });
    const credential = await attestor.record({ task: 'test', outcome: 'pass' });

    expect(await attestor.get(credential.id)).toEqual(credential);
    expect(await attestor.count()).toBe(1);
  });

  it('revokes a credential', async () => {
    const attestor = await createAttestor();
    const credential = await attestor.record({ task: 'test', outcome: 'pass' });

    await attestor.revoke(credential.id);

    const result = await verifyCredential(credential, { store: attestor.store });
    expect(result.valid).toBe(true);
    expect(result.revoked).toBe(true);
  });
});
