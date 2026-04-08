import canonicalize from 'canonicalize';
import { verify, hexToBytes } from '../identity/keypair.js';
import { parseDID } from '../identity/did.js';
import { isTrustedIssuer } from './registry.js';
import type { Credential, VerifyResult } from '../types.js';

const jcs = canonicalize as unknown as (input: unknown) => string | undefined;

export function verifyCredential(credential: Credential): VerifyResult {
  try {
    const publicKey = parseDID(credential.issuer);

    const { proof: _, ...unsigned } = credential;
    const message = new TextEncoder().encode(jcs(unsigned)!);
    const signature = hexToBytes(credential.proof.proofValue);

    const valid = verify(signature, message, publicKey);
    const issuerTrusted = isTrustedIssuer(credential.issuer);

    return { valid, issuerTrusted, credential };
  } catch {
    return { valid: false, issuerTrusted: false, credential };
  }
}
