# Logpose

Verifiable reputation and attestation SDK for AI agents using W3C Verifiable Credentials.

## Architecture

```
src/
├── index.ts              Barrel export (public API)
├── types.ts              Core type definitions (W3C VC 2.0 aligned)
├── credential.ts         Credential creation + JCS canonicalization + signing
├── attestor.ts           Main factory: createAttestor()
├── identity/
│   ├── keypair.ts        Ed25519 key management (@noble/curves)
│   └── did.ts            did:key creation/parsing (@scure/base for base58btc)
├── store/
│   └── memory.ts         In-memory CredentialStore
└── verify/
    ├── verifier.ts       Signature verification
    └── registry.ts       Trust registry (permissive when empty)
```

## Conventions

- **ESM only** — `"type": "module"`, `.js` extensions in all imports
- **Module resolution** — `nodenext` (strict ESM enforcement)
- **Crypto** — `@noble/curves` for Ed25519, `@scure/base` for base58btc encoding
- **Canonicalization** — `canonicalize` package (RFC 8785 JCS)
- **DID method** — `did:key` with Ed25519 multicodec prefix (`0xed01`)
- **Tests** — vitest, files in `test/`
- **Node** — 24+ (arm64), managed via fnm

## Build & Test

```sh
pnpm build    # tsc → dist/
pnpm test     # vitest run
pnpm test:watch  # vitest (watch mode)
```
