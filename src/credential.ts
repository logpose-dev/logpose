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
}

export function createCredential(options: CreateCredentialOptions): Credential {
  const { keypair, payload } = options;
  const issuer = createDID(keypair.publicKey);
  const subject = options.subject ?? issuer;
  const now = new Date().toISOString();
  const id = `urn:uuid:${crypto.randomUUID()}`;

  const unsigned: Omit<Credential, 'proof'> = {
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://w3id.org/security/data-integrity/v2'],
    id,
    type: ['VerifiableCredential', 'LogposeAttestation'],
    issuer,
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
  const signature = sign(message, keypair.privateKey);

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
