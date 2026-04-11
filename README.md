# logpose

This repository contains the Logpose npm packages managed together in a pnpm workspace.

## Packages

- `@logpose-dev/logpose` - core verifiable credential SDK for agent reputation and attestation -- [NPM Package](https://www.npmjs.com/package/@logpose-dev/logpose)
- `@logpose-dev/a2a` - transport and network adapters for agent-to-agent credential exchange -- [NPM Package](https://www.npmjs.com/package/@logpose-dev/a2a)

## Workspace layout

```text
packages/
  logpose/
  a2a/
```

## Development

Install dependencies from the repository root:

```sh
pnpm install
```

Run package builds:

```sh
pnpm -r build
```

Run core SDK tests:

```sh
pnpm --filter @logpose-dev/logpose test
```

Run adapter type checks:

```sh
pnpm --filter @logpose-dev/a2a typecheck
```

## Publishing

Each workspace package publishes independently to npm under its own package name.
