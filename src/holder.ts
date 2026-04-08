import { sign, bytesToHex } from './identity/keypair.js';
import type { HolderBinding, Keypair } from './types.js';

export function createHolderBinding(keypair: Keypair, challenge: string): HolderBinding {
  const message = new TextEncoder().encode(challenge);
  const signature = sign(message, keypair.privateKey);
  return {
    type: 'Ed25519HolderBinding',
    challenge,
    signature: bytesToHex(signature),
  };
}
