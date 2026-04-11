# @logpose-dev/a2a

Transport and network adapter package for exchanging Logpose credentials between A2A agents.

## What it provides

- `advertise(attestor, options)` - builds an Agent Card `reputation` fragment.
- `serve(attestor)` - WinterCG handler for `/.well-known/logpose.json`.
- `serveExpress(attestor)` - Express/Connect middleware for the same endpoint.
- `evaluate(agentUrl)` - fetches and verifies remote credentials with batched verification.

This package intentionally contains no cryptographic implementation and delegates verification to `@logpose-dev/logpose`.

## Agent Card reputation fragment

```ts
const fragment = await advertise(attestor, { agentUrl: 'https://agent.example.com/a2a' });

// {
//   reputation: {
//     protocol: 'logpose-v1',
//     did: 'did:key:...',
//     credentials_endpoint: 'https://agent.example.com/.well-known/logpose.json',
//     summary: { total_credentials, oldest, skills_attested }
//   }
// }
```

## Well-known endpoint

The `serve` and `serveExpress` adapters expose credentials at `/.well-known/logpose.json` with `Access-Control-Allow-Origin: *`.

## Trust evaluation

`evaluate(agentUrl)`:

1. Fetches `/.well-known/logpose.json` from `agentUrl`.
2. Delegates verification to the core SDK `verifyBatch` with `{ expectedAudience: agentUrl }`.
3. Returns:

```ts
interface TrustSummary {
  isTrusted: boolean;
  valid: number;
  revoked: number;
  reasons: string[];
}
```

Trust is strict: `isTrusted === (valid > 0 && revoked === 0)`.
