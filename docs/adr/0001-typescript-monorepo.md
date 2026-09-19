# ADR-0001: TypeScript monorepo with npm workspaces

- Status: Accepted
- Date: 2026-09-19

## Context
AdminSecOps needs a web dashboard, a local API, a CLI and a shared assessment engine,
with a clear path to Azure hosting. The engine must be shared verbatim between the CLI,
the API and (later) a hosted service so results are identical everywhere.

## Decision
A single repository using npm workspaces: libraries in `packages/*`, deployables in
`apps/*`. Strict TypeScript (`strict`, `noUncheckedIndexedAccess`), ES modules,
project references (`tsc -b`) for Node packages, Vite for the web app, Vitest for all
tests, typed ESLint. PowerShell collectors live in `collectors/` because they run on
administrator workstations, not in Node.

## Consequences
- One lockfile and one `npm run verify` gate for all TypeScript.
- npm workspaces avoid an additional package manager (pnpm/yarn) as a prerequisite.
- Tests resolve workspace packages to TypeScript sources (see `vitest.config.ts`), so a
  build is not needed to test.
