import type { Keypair } from '../types.js';

const ED25519_PRIVATE_KEY_LENGTH = 32;
const ED25519_PUBLIC_KEY_LENGTH = 32;
const KEY_CACHE_MAX_ENTRIES = 2048;
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01,
  0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

const privateKeyCache = new Map<string, Promise<CryptoKey>>();
const publicKeyCache = new Map<string, Promise<CryptoKey>>();

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error('Invalid hex string');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

export async function generateKeypair(): Promise<Keypair> {
  const webCrypto = getWebCrypto();
  const generated = await webCrypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair;

  if (!generated.privateKey || !generated.publicKey) {
    throw new Error('Web Crypto failed to generate an Ed25519 keypair');
  }

  const jwk = await webCrypto.subtle.exportKey('jwk', generated.privateKey);
  if (typeof jwk.d !== 'string' || typeof jwk.x !== 'string') {
    throw new Error('Unable to export Ed25519 keypair as JWK');
  }

  const privateKey = base64UrlToBytes(jwk.d);
  if (privateKey.length !== ED25519_PRIVATE_KEY_LENGTH) {
    throw new Error(`Expected 32-byte Ed25519 private key, got ${privateKey.length} bytes`);
  }

  const publicKey = base64UrlToBytes(jwk.x);
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new Error(`Expected 32-byte Ed25519 public key, got ${publicKey.length} bytes`);
  }

  return { privateKey, publicKey };
}

export async function keypairFromPrivateKey(hex: string): Promise<Keypair> {
  const privateKey = hexToBytes(hex);
  if (privateKey.length !== ED25519_PRIVATE_KEY_LENGTH) {
    throw new Error(`Expected 32-byte Ed25519 private key, got ${privateKey.length} bytes`);
  }

  const webCrypto = getWebCrypto();
  const importedPrivateKey = await webCrypto.subtle.importKey(
    'pkcs8',
    toArrayBuffer(toPkcs8(privateKey)),
    { name: 'Ed25519' },
    true,
    ['sign'],
  );

  const jwk = await webCrypto.subtle.exportKey('jwk', importedPrivateKey);
  if (typeof jwk.x !== 'string') {
    throw new Error('Unable to derive Ed25519 public key from private key');
  }

  const publicKey = base64UrlToBytes(jwk.x);
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new Error(`Expected 32-byte Ed25519 public key, got ${publicKey.length} bytes`);
  }

  return { privateKey, publicKey };
}

export async function sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array> {
  const webCrypto = getWebCrypto();
  const key = await importPrivateCryptoKey(privateKey);
  const signature = await webCrypto.subtle.sign('Ed25519', key, toArrayBuffer(message));
  return new Uint8Array(signature);
}

export async function verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  const webCrypto = getWebCrypto();
  const key = await importPublicCryptoKey(publicKey);
  return webCrypto.subtle.verify(
    'Ed25519',
    key,
    toArrayBuffer(signature),
    toArrayBuffer(message),
  );
}

function getWebCrypto(): Crypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto API is unavailable in this runtime');
  }
  return globalThis.crypto;
}

function toPkcs8(privateKey: Uint8Array): Uint8Array {
  if (privateKey.length !== ED25519_PRIVATE_KEY_LENGTH) {
    throw new Error(`Expected 32-byte Ed25519 private key, got ${privateKey.length} bytes`);
  }

  const bytes = new Uint8Array(ED25519_PKCS8_PREFIX.length + privateKey.length);
  bytes.set(ED25519_PKCS8_PREFIX, 0);
  bytes.set(privateKey, ED25519_PKCS8_PREFIX.length);
  return bytes;
}

function base64UrlToBytes(input: string): Uint8Array {
  if (typeof globalThis.atob !== 'function') {
    throw new Error('Base64 decoder is unavailable in this runtime');
  }

  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
  const decoded = globalThis.atob(normalized + padding);

  const bytes = new Uint8Array(decoded.length);
  for (let i = 0; i < decoded.length; i += 1) {
    bytes[i] = decoded.charCodeAt(i);
  }
  return bytes;
}

async function importPrivateCryptoKey(privateKey: Uint8Array): Promise<CryptoKey> {
  const keyHex = bytesToHex(privateKey);
  const cached = privateKeyCache.get(keyHex);
  if (cached) {
    return cached;
  }

  const webCrypto = getWebCrypto();
  const importedKeyPromise = webCrypto.subtle.importKey(
    'pkcs8',
    toArrayBuffer(toPkcs8(privateKey)),
    { name: 'Ed25519' },
    false,
    ['sign'],
  );
  setCacheEntry(privateKeyCache, keyHex, importedKeyPromise);

  return importedKeyPromise;
}

async function importPublicCryptoKey(publicKey: Uint8Array): Promise<CryptoKey> {
  if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) {
    throw new Error(`Expected 32-byte Ed25519 public key, got ${publicKey.length} bytes`);
  }

  const keyHex = bytesToHex(publicKey);
  const cached = publicKeyCache.get(keyHex);
  if (cached) {
    return cached;
  }

  const webCrypto = getWebCrypto();
  const importedKeyPromise = webCrypto.subtle.importKey(
    'raw',
    toArrayBuffer(publicKey),
    { name: 'Ed25519' },
    false,
    ['verify'],
  );
  setCacheEntry(publicKeyCache, keyHex, importedKeyPromise);

  return importedKeyPromise;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function setCacheEntry<T>(cache: Map<string, T>, key: string, value: T): void {
  if (!cache.has(key) && cache.size >= KEY_CACHE_MAX_ENTRIES) {
    const oldestKey = cache.keys().next().value;
    if (oldestKey !== undefined) {
      cache.delete(oldestKey);
    }
  }
  cache.set(key, value);
}
