export interface AttestationPayload {
  task: string;
  outcome: string;
  evidence?: Record<string, unknown>;
}

export interface HolderBinding {
  type: 'Ed25519HolderBinding';
  challenge: string;
  signature: string;
}

export interface CredentialSubject extends AttestationPayload {
  id: string;
  holderBinding?: HolderBinding;
}

export interface Proof {
  type: 'Ed25519Signature2024';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  proofValue: string;
}

export interface CredentialStatus {
  type: 'LogposeRevocation';
  id: string;
}

export interface Credential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  aud?: string;
  validFrom: string;
  validUntil?: string;
  credentialStatus: CredentialStatus;
  credentialSubject: CredentialSubject;
  proof: Proof;
}

export interface CredentialFilter {
  issuer?: string;
  subject?: string;
  task?: string;
  since?: string;
  until?: string;
}

export interface ICredentialStore {
  save(credential: Credential): Promise<void>;
  load(id: string): Promise<Credential | undefined>;
  get?(id: string): Promise<Credential | undefined>;
  delete(id: string): Promise<void>;
  list(filter?: CredentialFilter): Promise<Credential[]>;
  count(filter?: CredentialFilter): Promise<number>;
  revoke(id: string): Promise<void>;
  isRevoked(id: string): Promise<boolean>;
}

export interface CredentialStore {
  save(credential: Credential): Promise<void>;
  get(id: string): Promise<Credential | undefined>;
  list(filter?: CredentialFilter): Promise<Credential[]>;
  count(filter?: CredentialFilter): Promise<number>;
  revoke(id: string): Promise<void>;
  isRevoked(id: string): Promise<boolean>;
}

export interface AttestorConfig {
  store?: ICredentialStore | CredentialStore;
  privateKey?: string;
}

export interface RevocationCache {
  get(statusId: string): boolean | undefined | Promise<boolean | undefined>;
  set(statusId: string, revoked: boolean): void | Promise<void>;
}

export type RevocationBatchResult = Record<string, boolean> | ReadonlyMap<string, boolean>;
export type RevocationBatchFetcher = (statusIds: string[]) => Promise<RevocationBatchResult>;

export interface VerifyOptions {
  trustedIssuers?: string[] | Set<string>;
  store?: ICredentialStore | CredentialStore;
  checkExpiry?: boolean;
  expectedAudience?: string;
  revocationCache?: RevocationCache | Map<string, boolean>;
  revocationBatchFetcher?: RevocationBatchFetcher;
}

export interface VerifyResult {
  valid: boolean;
  issuerTrusted: boolean;
  expired: boolean;
  revoked: boolean;
  holderVerified: boolean;
  credential: Credential;
}

export interface Keypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export interface RecordOptions {
  subject?: string;
  validUntil?: string;
  holderBinding?: HolderBinding;
  audience?: string;
  aud?: string;
}
