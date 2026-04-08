import { describe, it, expect } from 'vitest';
import { MemoryStore, createCredential, generateKeypair, createDID } from '../src/index.js';
import type { Credential } from '../src/index.js';

function makeCredential(overrides?: {
  task?: string;
  issuerKeypair?: ReturnType<typeof generateKeypair>;
  subject?: string;
  validFrom?: string;
}): Credential {
  const keypair = overrides?.issuerKeypair ?? generateKeypair();
  const cred = createCredential({
    keypair,
    subject: overrides?.subject,
    payload: {
      task: overrides?.task ?? 'default-task',
      outcome: 'pass',
    },
  });
  // Override validFrom for date range testing
  if (overrides?.validFrom) {
    const adjusted = { ...cred, validFrom: overrides.validFrom };
    // Re-sign would be needed for real verification, but for store tests
    // we just need the data shape
    return adjusted;
  }
  return cred;
}

describe('MemoryStore', () => {
  it('saves and retrieves a credential by ID', async () => {
    const store = new MemoryStore();
    const cred = makeCredential();
    await store.save(cred);
    const retrieved = await store.get(cred.id);
    expect(retrieved).toEqual(cred);
  });

  it('returns undefined for unknown ID', async () => {
    const store = new MemoryStore();
    expect(await store.get('urn:uuid:nonexistent')).toBeUndefined();
  });

  it('lists all credentials with no filter', async () => {
    const store = new MemoryStore();
    await store.save(makeCredential({ task: 'a' }));
    await store.save(makeCredential({ task: 'b' }));
    const all = await store.list();
    expect(all).toHaveLength(2);
  });

  it('filters by issuer', async () => {
    const store = new MemoryStore();
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    await store.save(makeCredential({ issuerKeypair: kp1 }));
    await store.save(makeCredential({ issuerKeypair: kp2 }));
    await store.save(makeCredential({ issuerKeypair: kp1 }));

    const did1 = createDID(kp1.publicKey);
    const results = await store.list({ issuer: did1 });
    expect(results).toHaveLength(2);
    expect(results.every((c) => c.issuer === did1)).toBe(true);
  });

  it('filters by subject', async () => {
    const store = new MemoryStore();
    const kp = generateKeypair();
    const subjectDID = createDID(generateKeypair().publicKey);
    await store.save(makeCredential({ issuerKeypair: kp, subject: subjectDID }));
    await store.save(makeCredential({ issuerKeypair: kp }));

    const results = await store.list({ subject: subjectDID });
    expect(results).toHaveLength(1);
    expect(results[0].credentialSubject.id).toBe(subjectDID);
  });

  it('filters by task', async () => {
    const store = new MemoryStore();
    await store.save(makeCredential({ task: 'build' }));
    await store.save(makeCredential({ task: 'test' }));
    await store.save(makeCredential({ task: 'build' }));

    const results = await store.list({ task: 'build' });
    expect(results).toHaveLength(2);
  });

  it('filters by date range (since/until)', async () => {
    const store = new MemoryStore();
    await store.save(makeCredential({ task: 'old', validFrom: '2026-01-01T00:00:00.000Z' }));
    await store.save(makeCredential({ task: 'mid', validFrom: '2026-06-15T00:00:00.000Z' }));
    await store.save(makeCredential({ task: 'new', validFrom: '2026-12-31T00:00:00.000Z' }));

    const sinceResults = await store.list({ since: '2026-06-01T00:00:00.000Z' });
    expect(sinceResults).toHaveLength(2);

    const untilResults = await store.list({ until: '2026-06-30T00:00:00.000Z' });
    expect(untilResults).toHaveLength(2);

    const rangeResults = await store.list({
      since: '2026-03-01T00:00:00.000Z',
      until: '2026-09-01T00:00:00.000Z',
    });
    expect(rangeResults).toHaveLength(1);
    expect(rangeResults[0].credentialSubject.task).toBe('mid');
  });

  it('count respects filters', async () => {
    const store = new MemoryStore();
    await store.save(makeCredential({ task: 'build' }));
    await store.save(makeCredential({ task: 'test' }));
    await store.save(makeCredential({ task: 'build' }));

    expect(await store.count()).toBe(3);
    expect(await store.count({ task: 'build' })).toBe(2);
    expect(await store.count({ task: 'deploy' })).toBe(0);
  });

  it('revoke marks a credential as revoked', async () => {
    const store = new MemoryStore();
    const cred = makeCredential();
    await store.save(cred);

    expect(await store.isRevoked(cred.id)).toBe(false);
    await store.revoke(cred.id);
    expect(await store.isRevoked(cred.id)).toBe(true);
  });

  it('isRevoked returns false for unknown ID', async () => {
    const store = new MemoryStore();
    expect(await store.isRevoked('urn:uuid:nonexistent')).toBe(false);
  });

  it('revoking same ID twice is idempotent', async () => {
    const store = new MemoryStore();
    const cred = makeCredential();
    await store.save(cred);

    await store.revoke(cred.id);
    await store.revoke(cred.id);
    expect(await store.isRevoked(cred.id)).toBe(true);
  });
});
