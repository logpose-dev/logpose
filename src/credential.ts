import { jcs } from './jcs.js';
import { sign, bytesToHex } from './identity/keypair.js';
import { createDID } from './identity/did.js';
import type { AttestationPayload, Credential, HolderBinding, Keypair } from './types.js';

export interface CreateCredentialOptions {
  keypair: Keypair;
  subject?: string;
  payload: AttestationPayload;
  validUntil?: string;
  holderBinding?: HolderBinding;
  audience?: string;
  aud?: string;
}

export async function createCredential(options: CreateCredentialOptions): Promise<Credential> {
  const { keypair, payload } = options;
  const issuer = createDID(keypair.publicKey);
  const subject = options.subject ?? issuer;
  const audience = options.aud ?? options.audience;
  const now = new Date().toISOString();
  const id = `urn:uuid:${randomUUID()}`;

  const unsigned: Omit<Credential, 'proof'> = {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/security/data-integrity/v2'],
    id,
    type: ['VerifiableCredential', 'LogposeAttestation'],
    issuer,
    ...(audience !== undefined ? { aud: audience } : {}),
    validFrom: now,
    ...(options.validUntil !== undefined ? { validUntil: options.validUntil } : {}),
    credentialStatus: { type: 'LogposeRevocation', id },
    credentialSubject: {
      id: subject,
      task: payload.task,
      outcome: payload.outcome,
      ...(payload.evidence !== undefined ? { evidence: payload.evidence } : {}),
      ...(options.holderBinding !== undefined ? { holderBinding: options.holderBinding } : {}),
    },
  };

  const message = new TextEncoder().encode(jcs(unsigned)!);
  const signature = await sign(message, keypair.privateKey);

  return {
    ...unsigned,
    proof: {
      type: 'Ed25519Signature2024',
      created: now,
      verificationMethod: `${issuer}#key-1`,
      proofPurpose: 'assertionMethod',
      proofValue: bytesToHex(signature),
    },
  };
}

function randomUUID(): string {
  if (typeof globalThis.crypto?.randomUUID === 'function') {
    return globalThis.crypto.randomUUID();
  }

  if (!globalThis.crypto?.getRandomValues) {
    throw new Error('Web Crypto API is unavailable in this runtime');
  }

  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);

  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = bytesToHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
