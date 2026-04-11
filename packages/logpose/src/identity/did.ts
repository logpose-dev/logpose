import { base58 } from '@scure/base';

const DID_KEY_PREFIX = 'did:key:z';
const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);
const ED25519_PUBLIC_KEY_LENGTH = 32;

export function createDID(publicKey: Uint8Array): string {
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new Error(`Expected 32-byte Ed25519 public key, got ${publicKey.length} bytes`);
  }
  const bytes = new Uint8Array(2 + publicKey.length);
  bytes.set(ED25519_MULTICODEC, 0);
  bytes.set(publicKey, 2);
  return DID_KEY_PREFIX + base58.encode(bytes);
}

export function parseDID(did: string): Uint8Array {
  if (!did.startsWith(DID_KEY_PREFIX)) {
    throw new Error(`Invalid did:key format: ${did}`);
  }
  const encoded = did.slice(DID_KEY_PREFIX.length);
  const bytes = base58.decode(encoded);
  if (bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new Error('DID does not contain an Ed25519 public key');
  }
  const publicKey = bytes.slice(2);
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new Error(`Invalid Ed25519 public key length: expected 32 bytes, got ${publicKey.length}`);
  }
  return publicKey;
}

export function isValidDID(did: string): boolean {
  try {
    parseDID(did);
    return true;
  } catch {
    return false;
  }
}
