import { generateKeypair, keypairFromPrivateKey, bytesToHex } from './identity/keypair.js';
import { createDID } from './identity/did.js';
import { createCredential } from './credential.js';
import { MemoryStore } from './store/memory.js';
import type {
  AttestationPayload,
  AttestorConfig,
  Credential,
  CredentialFilter,
  CredentialStore,
  Keypair,
  RecordOptions,
} from './types.js';

export interface Attestor {
  readonly did: string;
  readonly store: CredentialStore;
  getPrivateKeyHex(): string;
  record(payload: AttestationPayload, options?: RecordOptions): Promise<Credential>;
  get(id: string): Promise<Credential | undefined>;
  list(filter?: CredentialFilter): Promise<Credential[]>;
  count(filter?: CredentialFilter): Promise<number>;
  revoke(id: string): Promise<void>;
}

export async function createAttestor(config?: AttestorConfig): Promise<Attestor> {
  const keypair: Keypair = config?.privateKey
    ? keypairFromPrivateKey(config.privateKey)
    : generateKeypair();

  const store: CredentialStore = config?.store ?? new MemoryStore();
  const did = createDID(keypair.publicKey);
  const hex = bytesToHex(keypair.privateKey);

  return {
    did,
    store,

    getPrivateKeyHex(): string {
      return hex;
    },

    async record(payload: AttestationPayload, options?: RecordOptions): Promise<Credential> {
      const credential = createCredential({
        keypair,
        subject: options?.subject,
        payload,
        validUntil: options?.validUntil,
        holderBinding: options?.holderBinding,
      });
      await store.save(credential);
      return credential;
    },

    async get(id: string): Promise<Credential | undefined> {
      return store.get(id);
    },

    async list(filter?: CredentialFilter): Promise<Credential[]> {
      return store.list(filter);
    },

    async count(filter?: CredentialFilter): Promise<number> {
      return store.count(filter);
    },

    async revoke(id: string): Promise<void> {
      await store.revoke(id);
    },
  };
}
