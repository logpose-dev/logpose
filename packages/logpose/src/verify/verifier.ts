import { jcs } from '../jcs.js';
import { verify, hexToBytes } from '../identity/keypair.js';
import { parseDID } from '../identity/did.js';
import { isTrustedIssuer } from './registry.js';
import type {
  Credential,
  RevocationBatchResult,
  RevocationCache,
  VerifyOptions,
  VerifyResult,
} from '../types.js';

export async function verifyCredential(
  credential: Credential,
  options?: VerifyOptions,
): Promise<VerifyResult> {
  assertAudienceMatch(credential, options?.expectedAudience);

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
    const valid = await verify(signature, message, publicKey);

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
    const revoked = await resolveRevocation(credential, options);

    // Holder binding
    let holderVerified: boolean;
    const binding = credential.credentialSubject.holderBinding;
    if (binding) {
      try {
        const subjectPubKey = parseDID(credential.credentialSubject.id);
        const challengeBytes = new TextEncoder().encode(binding.challenge);
        const bindingSig = hexToBytes(binding.signature);
        holderVerified = await verify(bindingSig, challengeBytes, subjectPubKey);
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

export async function verifyBatch(
  credentials: Credential[],
  options?: VerifyOptions,
): Promise<VerifyResult[]> {
  if (credentials.length === 0) {
    return [];
  }

  const cache = normalizeRevocationCache(options?.revocationCache);
  const statusIds = [...new Set(credentials.map((credential) => credential.credentialStatus.id))];
  const missingStatusIds: string[] = [];

  for (const statusId of statusIds) {
    const cached = await cache.get(statusId);
    if (cached === undefined) {
      missingStatusIds.push(statusId);
    }
  }

  if (missingStatusIds.length > 0) {
    if (options?.store) {
      await Promise.all(missingStatusIds.map(async (statusId) => {
        const revoked = await options.store!.isRevoked(statusId);
        await cache.set(statusId, revoked);
      }));
    } else if (options?.revocationBatchFetcher) {
      const batchResult = await options.revocationBatchFetcher(missingStatusIds);
      for (const statusId of missingStatusIds) {
        await cache.set(statusId, readBatchResult(batchResult, statusId));
      }
    } else {
      for (const statusId of missingStatusIds) {
        await cache.set(statusId, false);
      }
    }
  }

  const verifyOptions: VerifyOptions = {
    ...options,
    revocationCache: cache,
  };

  return Promise.all(credentials.map((credential) => verifyCredential(credential, verifyOptions)));
}

function assertAudienceMatch(credential: Credential, expectedAudience?: string): void {
  if (expectedAudience === undefined) {
    return;
  }

  if (credential.aud !== expectedAudience) {
    throw new Error(
      `Credential audience mismatch: expected "${expectedAudience}", got "${credential.aud ?? ''}"`,
    );
  }
}

async function resolveRevocation(
  credential: Credential,
  options?: VerifyOptions,
): Promise<boolean> {
  const statusId = credential.credentialStatus.id;
  const cache = normalizeRevocationCache(options?.revocationCache);
  const cached = await cache.get(statusId);

  if (cached !== undefined) {
    return cached;
  }

  let revoked = false;

  if (options?.store) {
    revoked = await options.store.isRevoked(statusId);
  } else if (options?.revocationBatchFetcher) {
    const batchResult = await options.revocationBatchFetcher([statusId]);
    revoked = readBatchResult(batchResult, statusId);
  }

  await cache.set(statusId, revoked);
  return revoked;
}

function normalizeRevocationCache(cache?: VerifyOptions['revocationCache']): RevocationCache {
  if (!cache) {
    const local = new Map<string, boolean>();
    return {
      get: (statusId: string) => local.get(statusId),
      set: (statusId: string, revoked: boolean) => {
        local.set(statusId, revoked);
      },
    };
  }

  if (cache instanceof Map) {
    return {
      get: (statusId: string) => cache.get(statusId),
      set: (statusId: string, revoked: boolean) => {
        cache.set(statusId, revoked);
      },
    };
  }

  return cache;
}

function readBatchResult(batchResult: RevocationBatchResult, statusId: string): boolean {
  if (isMapBatchResult(batchResult)) {
    return batchResult.get(statusId) ?? false;
  }

  return batchResult[statusId] ?? false;
}

function isMapBatchResult(batchResult: RevocationBatchResult): batchResult is ReadonlyMap<string, boolean> {
  return typeof (batchResult as ReadonlyMap<string, boolean>).get === 'function';
}
