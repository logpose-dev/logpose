export { createAttestor } from './attestor.js';
export type { Attestor } from './attestor.js';

export { createCredential } from './credential.js';
export type { CreateCredentialOptions } from './credential.js';

export { generateKeypair, keypairFromPrivateKey, bytesToHex, hexToBytes } from './identity/keypair.js';
export { createDID, parseDID, isValidDID } from './identity/did.js';

export { verifyCredential } from './verify/verifier.js';
export { trustIssuer, untrustIssuer, loadRegistry, exportRegistry } from './verify/registry.js';

export { MemoryStore } from './store/memory.js';

export type {
  AttestationPayload,
  AttestorConfig,
  Credential,
  CredentialFilter,
  CredentialStore,
  CredentialSubject,
  Keypair,
  Proof,
  VerifyResult,
} from './types.js';
