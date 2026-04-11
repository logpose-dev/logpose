import { sign, bytesToHex } from './identity/keypair.js';
import type { HolderBinding, Keypair } from './types.js';

export async function createHolderBinding(keypair: Keypair, challenge: string): Promise<HolderBinding> {
  const message = new TextEncoder().encode(challenge);
  const signature = await sign(message, keypair.privateKey);
  return {
    type: 'Ed25519HolderBinding',
    challenge,
    signature: bytesToHex(signature),
  };
}
