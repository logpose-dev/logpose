import type { Credential, CredentialFilter, CredentialStore, ICredentialStore } from '../types.js';

export class MemoryStore implements ICredentialStore, CredentialStore {
  private credentials = new Map<string, Credential>();
  private revokedIds = new Set<string>();

  async save(credential: Credential): Promise<void> {
    this.credentials.set(credential.id, credential);
  }

  async load(id: string): Promise<Credential | undefined> {
    return this.credentials.get(id);
  }

  async get(id: string): Promise<Credential | undefined> {
    return this.load(id);
  }

  async delete(id: string): Promise<void> {
    this.credentials.delete(id);
    this.revokedIds.delete(id);
  }

  async list(filter?: CredentialFilter): Promise<Credential[]> {
    let results = [...this.credentials.values()];
    if (!filter) return results;

    if (filter.issuer) {
      results = results.filter((c) => c.issuer === filter.issuer);
    }
    if (filter.subject) {
      results = results.filter((c) => c.credentialSubject.id === filter.subject);
    }
    if (filter.task) {
      results = results.filter((c) => c.credentialSubject.task === filter.task);
    }
    if (filter.since) {
      results = results.filter((c) => c.validFrom >= filter.since!);
    }
    if (filter.until) {
      results = results.filter((c) => c.validFrom <= filter.until!);
    }

    return results;
  }

  async count(filter?: CredentialFilter): Promise<number> {
    const results = await this.list(filter);
    return results.length;
  }

  async revoke(id: string): Promise<void> {
    this.revokedIds.add(id);
  }

  async isRevoked(id: string): Promise<boolean> {
    return this.revokedIds.has(id);
  }
}
