import { generateKeypair, keypairFromPrivateKey, bytesToHex } from './identity/keypair.js';
import { createDID } from './identity/did.js';
import { createCredential } from './credential.js';
import { MemoryStore } from './store/memory.js';
import type {
  AttestationPayload,
  AttestorConfig,
  CredentialStore,
  Credential,
  CredentialFilter,
  ICredentialStore,
  Keypair,
  RecordOptions,
} from './types.js';

export interface Attestor {
  readonly did: string;
  readonly store: ICredentialStore & { get(id: string): Promise<Credential | undefined> };
  getPrivateKeyHex(): string;
  record(payload: AttestationPayload, options?: RecordOptions): Promise<Credential>;
  get(id: string): Promise<Credential | undefined>;
  list(filter?: CredentialFilter): Promise<Credential[]>;
  count(filter?: CredentialFilter): Promise<number>;
  revoke(id: string): Promise<void>;
}

export async function createAttestor(config?: AttestorConfig): Promise<Attestor> {
  const keypair: Keypair = config?.privateKey
    ? await keypairFromPrivateKey(config.privateKey)
    : await generateKeypair();

  const store = normalizeStore(config?.store ?? new MemoryStore());
  const did = createDID(keypair.publicKey);
  const hex = bytesToHex(keypair.privateKey);

  return {
    did,
    store,

    getPrivateKeyHex(): string {
      return hex;
    },

    async record(payload: AttestationPayload, options?: RecordOptions): Promise<Credential> {
      const credential = await createCredential({
        keypair,
        subject: options?.subject,
        payload,
        validUntil: options?.validUntil,
        holderBinding: options?.holderBinding,
        aud: options?.aud,
        audience: options?.audience,
      });
      await store.save(credential);
      return credential;
    },

    async get(id: string): Promise<Credential | undefined> {
      return store.load(id);
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

function normalizeStore(
  store: ICredentialStore | CredentialStore,
): ICredentialStore & { get(id: string): Promise<Credential | undefined> } {
  const load = hasLoad(store)
    ? (id: string) => store.load(id)
    : (id: string) => store.get(id);

  const get = hasGet(store)
    ? (id: string) => store.get(id)
    : load;

  const remove = hasDelete(store)
    ? (id: string) => store.delete(id)
    : async () => {
      throw new Error('delete() is not implemented by this credential store');
    };

  return {
    save: (credential) => store.save(credential),
    load,
    get,
    delete: remove,
    list: (filter) => store.list(filter),
    count: (filter) => store.count(filter),
    revoke: (id) => store.revoke(id),
    isRevoked: (id) => store.isRevoked(id),
  };
}

function hasLoad(store: ICredentialStore | CredentialStore): store is ICredentialStore {
  return typeof (store as ICredentialStore).load === 'function';
}

function hasGet(store: ICredentialStore | CredentialStore): store is CredentialStore {
  return typeof (store as CredentialStore).get === 'function';
}

function hasDelete(store: ICredentialStore | CredentialStore): store is ICredentialStore {
  return typeof (store as ICredentialStore).delete === 'function';
}
