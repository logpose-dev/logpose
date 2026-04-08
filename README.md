# logpose

Verifiable reputation and attestation SDK for AI agents. Agents cryptographically sign credentials proving what they've done, and verifiers check those credentials.

Built on [W3C Verifiable Credentials 2.0](https://www.w3.org/TR/vc-data-model-2.0/), [did:key](https://w3c-ccg.github.io/did-method-key/), and Ed25519 signatures.

## Install

```sh
pnpm add logpose
```

## Usage

```typescript
import { createAttestor, verifyCredential } from 'logpose';

// Create an attestor (generates a new Ed25519 keypair)
const agent = await createAttestor();
console.log(agent.did); // did:key:z6Mk...

// Record a credential
const credential = await agent.record({
  task: 'code-review',
  outcome: 'approved',
  evidence: { pr: 42, repo: 'acme/api' },
});

// Verify it (async)
const result = await verifyCredential(credential);
console.log(result.valid);          // true
console.log(result.issuerTrusted);  // true (permissive mode — empty registry)
console.log(result.holderVerified); // true (self-attestation)

// Persist identity across sessions
const key = agent.getPrivateKeyHex();
const sameAgent = await createAttestor({ privateKey: key });
console.log(sameAgent.did === agent.did); // true
```

### Revocation

Every credential includes a `credentialStatus` field. Revoke via the attestor, check via the verifier:

```typescript
await agent.revoke(credential.id);

const result = await verifyCredential(credential, { store: agent.store });
console.log(result.revoked); // true
```

### Holder Binding

When an issuer attests about a different subject, the subject can prove consent by signing a challenge:

```typescript
import { createAttestor, createHolderBinding, verifyCredential } from 'logpose';

const issuer = await createAttestor();
const subject = await createAttestor();

// Subject signs a challenge to prove consent
const binding = createHolderBinding(
  { privateKey: /* subject's private key bytes */, publicKey: /* subject's public key bytes */ },
  'consent-challenge-123',
);

// Issuer includes the binding in the credential
const credential = await issuer.record(
  { task: 'audit', outcome: 'clean' },
  { subject: subject.did, holderBinding: binding },
);

const result = await verifyCredential(credential);
console.log(result.holderVerified); // true — subject proved consent
```

Without a holder binding, third-party attestations have `holderVerified: false`.

### Trust Registry

```typescript
import { trustIssuer, verifyCredential } from 'logpose';

// Option 1: Global registry
trustIssuer(trustedAgent.did);
const result = await verifyCredential(credential);

// Option 2: Injectable trust (no global state)
const result2 = await verifyCredential(credential, {
  trustedIssuers: [trustedAgent.did],
});
```

### Credential Expiry

```typescript
const credential = await agent.record(
  { task: 'deploy', outcome: 'success' },
  { validUntil: new Date(Date.now() + 86400_000).toISOString() },
);

const result = await verifyCredential(credential);
console.log(result.expired); // false (until validUntil passes)
```

### Credential Structure (W3C VC 2.0)

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/security/data-integrity/v2"
  ],
  "id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
  "type": ["VerifiableCredential", "LogposeAttestation"],
  "issuer": "did:key:z6Mk...",
  "validFrom": "2026-04-08T15:30:00.000Z",
  "credentialStatus": {
    "type": "LogposeRevocation",
    "id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000"
  },
  "credentialSubject": {
    "id": "did:key:z6Mk...",
    "task": "code-review",
    "outcome": "approved",
    "evidence": { "pr": 42 }
  },
  "proof": {
    "type": "Ed25519Signature2024",
    "created": "2026-04-08T15:30:00.000Z",
    "verificationMethod": "did:key:z6Mk...#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "a1b2c3..."
  }
}
```

### VerifyResult

```typescript
interface VerifyResult {
  valid: boolean;          // Ed25519 signature check
  issuerTrusted: boolean;  // Trust registry check
  expired: boolean;        // validUntil check
  revoked: boolean;        // Store revocation check
  holderVerified: boolean; // Holder binding / self-attestation check
  credential: Credential;
}
```

## License

MIT
