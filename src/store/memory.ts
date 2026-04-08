import type { Credential, CredentialFilter, CredentialStore } from '../types.js';

export class MemoryStore implements CredentialStore {
  private credentials = new Map<string, Credential>();

  async save(credential: Credential): Promise<void> {
    this.credentials.set(credential.id, credential);
  }

  async get(id: string): Promise<Credential | undefined> {
    return this.credentials.get(id);
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
}
