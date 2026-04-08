import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/curves/utils.js';
import type { Keypair } from '../types.js';

export { bytesToHex, hexToBytes };

export function generateKeypair(): Keypair {
  const privateKey = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function keypairFromPrivateKey(hex: string): Keypair {
  const privateKey = hexToBytes(hex);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey);
}

export function verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  return ed25519.verify(signature, message, publicKey);
}
