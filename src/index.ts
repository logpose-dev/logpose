export { createAttestor } from './attestor.js';
export type { Attestor } from './attestor.js';

export { createCredential } from './credential.js';
export type { CreateCredentialOptions } from './credential.js';

export { createHolderBinding } from './holder.js';

export { generateKeypair, keypairFromPrivateKey, bytesToHex, hexToBytes } from './identity/keypair.js';
export { createDID, parseDID, isValidDID } from './identity/did.js';

export { verifyCredential, verifyBatch } from './verify/verifier.js';
export { trustIssuer, untrustIssuer, isTrustedIssuer, loadRegistry, exportRegistry } from './verify/registry.js';

export { MemoryStore } from './store/memory.js';

export type {
  AttestationPayload,
  AttestorConfig,
  Credential,
  CredentialFilter,
  CredentialStatus,
  CredentialStore,
  ICredentialStore,
  CredentialSubject,
  HolderBinding,
  Keypair,
  Proof,
  RevocationBatchFetcher,
  RevocationBatchResult,
  RevocationCache,
  RecordOptions,
  VerifyOptions,
  VerifyResult,
} from './types.js';
