# logpose

Verifiable reputation and attestation SDK for agent-to-agent communication.

The SDK follows [W3C Verifiable Credentials 2.0](https://www.w3.org/TR/vc-data-model-2.0/), `did:key`, and Ed25519 signatures.

## Runtime support

`@logpose-dev/logpose` uses Web Crypto (`globalThis.crypto.subtle`) and is designed for Node.js, Cloudflare Workers, and Next.js Edge runtimes without Node crypto polyfills.

## Install

```sh
pnpm add @logpose-dev/logpose
```

## Quick start

```typescript
import { createAttestor, verifyCredential } from '@logpose-dev/logpose';

const agent = await createAttestor();

const credential = await agent.record({
  task: 'code-review',
  outcome: 'approved',
  evidence: { pr: 42, repo: 'acme/api' },
});

const result = await verifyCredential(credential);
console.log(result.valid);          // true
console.log(result.issuerTrusted);  // true when trust registry is empty
console.log(result.holderVerified); // true for self-attestation
```

## Features

### Pluggable storage

`createAttestor()` accepts `store` and defaults to in-memory `MemoryStore`.

```typescript
import {
  createAttestor,
  type Credential,
  type CredentialFilter,
  type ICredentialStore,
} from '@logpose-dev/logpose';

class DurableStore implements ICredentialStore {
  async save(_credential: Credential): Promise<void> {}
  async load(_id: string): Promise<Credential | undefined> { return undefined; }
  async delete(_id: string): Promise<void> {}
  async list(_filter?: CredentialFilter): Promise<Credential[]> { return []; }
  async count(_filter?: CredentialFilter): Promise<number> { return 0; }
  async revoke(_id: string): Promise<void> {}
  async isRevoked(_id: string): Promise<boolean> { return false; }
}

const attestor = await createAttestor({ store: new DurableStore() });
```

### Revocation and batch verification

Use `verifyBatch()` to dedupe revocation lookups and avoid N+1 fetches.

```typescript
import { verifyBatch } from '@logpose-dev/logpose';

const results = await verifyBatch(credentials, {
  revocationBatchFetcher: async (statusIds) => {
    const response = await fetch('https://registry.example/revocation/batch', {
      method: 'POST',
      body: JSON.stringify({ statusIds }),
    });
    return await response.json() as Record<string, boolean>;
  },
});
```

### Audience binding

Credentials can include `aud` and verifiers can require strict audience matching.

```typescript
const credential = await agent.record(
  { task: 'deploy', outcome: 'success' },
  { audience: 'https://agent-b.example' },
);

await verifyCredential(credential, {
  expectedAudience: 'https://agent-b.example',
});
```

If `expectedAudience` is provided and does not match `credential.aud`, verification throws.

### Holder binding

```typescript
import { createAttestor, createHolderBinding, verifyCredential } from '@logpose-dev/logpose';

const issuer = await createAttestor();
const subject = await createAttestor();

const binding = await createHolderBinding(
  { privateKey: /* subject private key bytes */, publicKey: /* subject public key bytes */ },
  'consent-challenge-123',
);

const credential = await issuer.record(
  { task: 'audit', outcome: 'clean' },
  { subject: subject.did, holderBinding: binding },
);

const result = await verifyCredential(credential);
console.log(result.holderVerified); // true
```

## Migration guide (v0.1.x -> v0.2.0)

This release includes breaking API changes and should be published as a new minor (`0.2.0`) under semver pre-1.0 rules.

### Breaking changes

- `generateKeypair()` is now async.
- `keypairFromPrivateKey()` is now async.
- `createCredential()` is now async.
- `createHolderBinding()` is now async.
- Crypto internals now use Web Crypto only (no `@noble/curves` runtime signing path).

### Storage API updates

- New `ICredentialStore` interface uses `load()` and `delete()`.
- Legacy `CredentialStore` (`get()`) remains accepted via adapter for compatibility.

### New verification capabilities

- `verifyBatch(credentials, options?)` for deduplicated revocation checks.
- `VerifyOptions.expectedAudience` for replay resistance.
- `VerifyOptions.revocationCache` and `VerifyOptions.revocationBatchFetcher` for high-throughput verifier services.

## License

MIT
