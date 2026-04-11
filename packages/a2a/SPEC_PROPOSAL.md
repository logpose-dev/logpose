# A2A Agent Card Reputation Extension (Logpose v1)

## Proposal

Add an optional `reputation` object to the Agent Card schema so agents can advertise verifiable reputation material.

```json
{
  "name": "code-reviewer-v3",
  "description": "Reviews PRs for security and quality",
  "url": "https://agent.example.com/a2a",
  "skills": [{ "id": "code-review", "name": "Code Review" }],
  "authentication": { "schemes": ["bearer"] },
  "reputation": {
    "protocol": "logpose-v1",
    "did": "did:key:z6MkokYk...dcsUAf",
    "credentials_endpoint": "https://agent.example.com/.well-known/logpose.json",
    "summary": {
      "total_credentials": 247,
      "oldest": "2026-01-15T00:00:00Z",
      "skills_attested": ["code-review"]
    }
  }
}
```

## Field Semantics

- `reputation.protocol` (`string`, required): reputation protocol identifier. For this proposal: `logpose-v1`.
- `reputation.did` (`string`, required): public agent identity used as verifier input.
- `reputation.credentials_endpoint` (`string`, required): URL that returns a JSON array of W3C Verifiable Credentials.
- `reputation.summary` (`object`, optional): convenience metadata for UX/indexing only.
  - `total_credentials` (`number`)
  - `oldest` (`string | null`, RFC 3339 timestamp)
  - `skills_attested` (`string[]`)

## Transport Contract

- `GET /.well-known/logpose.json` returns an array of credentials.
- Endpoint should include `Access-Control-Allow-Origin: *` to enable cross-agent fetch.
- Consumers should treat this endpoint as public read-only data.

## Verification Model

- The summary is **advisory** and MUST NOT be used as sole trust evidence.
- Trust decisions come from verifying actual credentials from `credentials_endpoint`.
- Verifiers should run batched verification and bind `expectedAudience` to the target `agentUrl` to reduce replay risks.

## Compatibility

- This is backward-compatible because `reputation` is optional.
- Existing Agent Cards remain valid unchanged.
- Clients that do not understand `reputation` can ignore it safely.

## Rationale

- Creates a portable, protocol-agnostic hook for verifiable reputation in A2A discovery.
- Keeps cryptographic verification out of A2A itself and delegated to reputation protocol SDKs.
- Supports low-friction UX via optional summary while preserving strong verification guarantees.
