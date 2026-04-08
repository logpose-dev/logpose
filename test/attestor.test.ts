import { describe, it, expect } from 'vitest';
import { createAttestor, isValidDID } from '../src/index.js';

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

    expect(credential['@context']).toEqual(['https://www.w3.org/ns/credentials/v2']);
    expect(credential.type).toEqual(['VerifiableCredential', 'LogposeAttestation']);
    expect(credential.issuer).toBe(attestor.did);
    expect(credential.credentialSubject.task).toBe('code-review');
    expect(credential.credentialSubject.outcome).toBe('approved');
    expect(credential.credentialSubject.evidence).toEqual({ pr: 42 });
    expect(credential.proof.type).toBe('Ed25519Signature2024');
    expect(credential.proof.proofPurpose).toBe('assertionMethod');
  });

  it('retrieves a credential by ID after recording', async () => {
    const attestor = await createAttestor();
    const credential = await attestor.record({
      task: 'deploy',
      outcome: 'success',
    });

    const retrieved = await attestor.get(credential.id);
    expect(retrieved).toEqual(credential);
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

  it('preserves identity across attestors using privateKeyHex', async () => {
    const first = await createAttestor();
    const second = await createAttestor({ privateKey: first.privateKeyHex });
    expect(second.did).toBe(first.did);
    expect(second.privateKeyHex).toBe(first.privateKeyHex);
  });
});
