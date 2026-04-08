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

// Verify it
const result = verifyCredential(credential);
console.log(result.valid);          // true
console.log(result.issuerTrusted);  // true (permissive mode — empty registry)

// Persist identity across sessions
const key = agent.privateKeyHex;
const sameAgent = await createAttestor({ privateKey: key });
console.log(sameAgent.did === agent.did); // true
```

### Credential Structure (W3C VC 2.0)

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
  "type": ["VerifiableCredential", "LogposeAttestation"],
  "issuer": "did:key:z6Mk...",
  "validFrom": "2026-04-08T15:30:00.000Z",
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

### Trust Registry

By default, the trust registry is empty and operates in permissive mode (all issuers trusted). Add specific issuers to restrict trust:

```typescript
import { trustIssuer, verifyCredential } from 'logpose';

trustIssuer(trustedAgent.did);

const result = verifyCredential(credential);
// result.issuerTrusted is true only if credential.issuer is in the registry
```

## License

MIT
