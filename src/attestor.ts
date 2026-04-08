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
} from './types.js';

export interface Attestor {
  readonly did: string;
  readonly privateKeyHex: string;
  record(payload: AttestationPayload, subject?: string): Promise<Credential>;
  get(id: string): Promise<Credential | undefined>;
  list(filter?: CredentialFilter): Promise<Credential[]>;
  count(filter?: CredentialFilter): Promise<number>;
}

export async function createAttestor(config?: AttestorConfig): Promise<Attestor> {
  const keypair: Keypair = config?.privateKey
    ? keypairFromPrivateKey(config.privateKey)
    : generateKeypair();

  const store: CredentialStore = config?.store ?? new MemoryStore();
  const did = createDID(keypair.publicKey);
  const privateKeyHex = bytesToHex(keypair.privateKey);

  return {
    did,
    privateKeyHex,

    async record(payload: AttestationPayload, subject?: string): Promise<Credential> {
      const credential = createCredential({ keypair, subject, payload });
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
  };
}
