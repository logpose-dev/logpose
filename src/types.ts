export interface AttestationPayload {
  task: string;
  outcome: string;
  evidence?: Record<string, unknown>;
}

export interface CredentialSubject {
  id: string;
  task: string;
  outcome: string;
  evidence?: Record<string, unknown>;
}

export interface Proof {
  type: 'Ed25519Signature2024';
  created: string;
  verificationMethod: string;
  proofPurpose: 'assertionMethod';
  proofValue: string;
}

export interface Credential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
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

export interface CredentialStore {
  save(credential: Credential): Promise<void>;
  get(id: string): Promise<Credential | undefined>;
  list(filter?: CredentialFilter): Promise<Credential[]>;
  count(filter?: CredentialFilter): Promise<number>;
}

export interface AttestorConfig {
  store?: CredentialStore;
  privateKey?: string;
}

export interface VerifyResult {
  valid: boolean;
  issuerTrusted: boolean;
  credential: Credential;
}

export interface Keypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}
