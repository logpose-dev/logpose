# Changelog

All notable changes to this project are documented in this file.

## [0.2.0] - 2026-04-11

### Breaking

- Switched SDK cryptography to strict Web Crypto (`globalThis.crypto.subtle`) for runtime portability.
- Made low-level crypto APIs async:
  - `generateKeypair()`
  - `keypairFromPrivateKey()`
  - `createCredential()`
  - `createHolderBinding()`

### Added

- Introduced `ICredentialStore` with `save/load/delete/list/count/revoke/isRevoked`.
- Added `MemoryStore` support for both new (`load`) and legacy (`get`) retrieval methods.
- Added `verifyBatch(credentials, options?)` to deduplicate revocation checks and reduce N+1 calls.
- Added `VerifyOptions.revocationCache` and `VerifyOptions.revocationBatchFetcher`.
- Added audience binding support:
  - Optional `aud` claim on credentials
  - `VerifyOptions.expectedAudience` strict match enforcement

### Changed

- `createAttestor({ store })` now accepts both `ICredentialStore` and legacy `CredentialStore` via compatibility adapter.
- Removed `@noble/curves` runtime dependency from the package.

### Migration notes

- Await all low-level crypto API calls listed above.
- Existing custom stores with `get()` continue to work; new implementations should adopt `ICredentialStore`.
- If you rely on single-credential revocation network checks, prefer `verifyBatch()` for high-throughput verification pipelines.
