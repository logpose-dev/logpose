import { jcs } from '../jcs.js';
import { verify, hexToBytes } from '../identity/keypair.js';
import { parseDID } from '../identity/did.js';
import { isTrustedIssuer } from './registry.js';
import type { Credential, VerifyOptions, VerifyResult } from '../types.js';

interface ResultFields {
  valid: boolean;
  issuerTrusted: boolean;
  expired: boolean;
  revoked: boolean;
  holderVerified: boolean;
}

export async function verifyCredential(
  credential: Credential,
  options?: VerifyOptions,
): Promise<VerifyResult> {
  const fail = (): VerifyResult => ({
    valid: false, issuerTrusted: false, expired: false,
    revoked: false, holderVerified: false, credential,
  });

  try {
    // Signature verification
    const publicKey = parseDID(credential.issuer);
    const { proof: _, ...unsigned } = credential;
    const message = new TextEncoder().encode(jcs(unsigned)!);
    const signature = hexToBytes(credential.proof.proofValue);
    const valid = verify(signature, message, publicKey);

    // Expiry
    const checkExpiry = options?.checkExpiry !== false;
    const expired = checkExpiry
      && credential.validUntil !== undefined
      && new Date(credential.validUntil).getTime() < Date.now();

    // Trust
    let issuerTrusted: boolean;
    if (options?.trustedIssuers !== undefined) {
      const trusted = options.trustedIssuers instanceof Set
        ? options.trustedIssuers
        : new Set(options.trustedIssuers);
      issuerTrusted = trusted.size === 0 ? true : trusted.has(credential.issuer);
    } else {
      issuerTrusted = isTrustedIssuer(credential.issuer);
    }

    // Revocation
    let revoked = false;
    if (options?.store) {
      revoked = await options.store.isRevoked(credential.id);
    }

    // Holder binding
    let holderVerified: boolean;
    const binding = credential.credentialSubject.holderBinding;
    if (binding) {
      try {
        const subjectPubKey = parseDID(credential.credentialSubject.id);
        const challengeBytes = new TextEncoder().encode(binding.challenge);
        const bindingSig = hexToBytes(binding.signature);
        holderVerified = verify(bindingSig, challengeBytes, subjectPubKey);
      } catch {
        holderVerified = false;
      }
    } else {
      holderVerified = credential.issuer === credential.credentialSubject.id;
    }

    return { valid, issuerTrusted, expired, revoked, holderVerified, credential };
  } catch {
    return fail();
  }
}
