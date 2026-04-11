# Delegation Demo (Agent A <-> Agent B)

This demo starts two local Express servers that simulate A2A delegation with Logpose trust checks:

- **Agent A (Provider)** on `http://localhost:3001`
  - creates two mock `code-review` credentials with positive outcomes
  - binds each credential audience (`aud`) to `http://localhost:3001`
  - publishes credentials at `/.well-known/logpose.json` via `serveExpress(...)`
  - accepts delegated work at `POST /task`
- **Agent B (Delegator)** on `http://localhost:3002`
  - evaluates Agent A using `evaluate(targetAgentUrl)`
  - only delegates if `TrustSummary.isTrusted === true`

## Prerequisites

- Node.js 24+
- pnpm 10+

## Run the demo

From the monorepo root:

```sh
pnpm install
pnpm -r build
pnpm --filter @logpose-dev/delegation-demo demo
```

The `demo` script sets `FORCE_COLOR=1` so screenshots and recordings keep ANSI colors.

## Expected terminal flow

The output is intentionally staged so a new reader can follow the trust flow:

1. `Agent A booted`
2. `Agent B discovered Agent A`
3. `Agent B verified the credentials`
4. `Agent B delegated the task`

Color highlights:

- `[Agent A]` is blue.
- `[Agent B]` is magenta.
- Step markers (`[1/4]` .. `[4/4]`) are yellow.
- `isTrusted=true` and successful outcomes are green.

## Troubleshooting

- If ports are busy, stop existing processes using `3001` and `3002`.
- If trust fails, verify Agent A is reachable at `http://localhost:3001/.well-known/logpose.json`.
- If runtime imports fail, run `pnpm -r build` again to refresh workspace `dist/` artifacts.
