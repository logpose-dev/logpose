import canonicalize from 'canonicalize';
import { sign, bytesToHex } from './identity/keypair.js';
import { createDID } from './identity/did.js';
import type { AttestationPayload, Credential, Keypair } from './types.js';

const jcs = canonicalize as unknown as (input: unknown) => string | undefined;

export interface CreateCredentialOptions {
  keypair: Keypair;
  subject?: string;
  payload: AttestationPayload;
}

export function createCredential(options: CreateCredentialOptions): Credential {
  const { keypair, payload } = options;
  const issuer = createDID(keypair.publicKey);
  const subject = options.subject ?? issuer;

  const unsigned = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${crypto.randomUUID()}`,
    type: ['VerifiableCredential', 'LogposeAttestation'],
    issuer,
    validFrom: new Date().toISOString(),
    credentialSubject: {
      id: subject,
      task: payload.task,
      outcome: payload.outcome,
      ...(payload.evidence !== undefined ? { evidence: payload.evidence } : {}),
    },
  };

  const message = new TextEncoder().encode(jcs(unsigned)!);
  const signature = sign(message, keypair.privateKey);

  return {
    ...unsigned,
    proof: {
      type: 'Ed25519Signature2024',
      created: unsigned.validFrom,
      verificationMethod: `${issuer}#key-1`,
      proofPurpose: 'assertionMethod',
      proofValue: bytesToHex(signature),
    },
  };
}
