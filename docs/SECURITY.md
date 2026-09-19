# Security

AdminSecOps is security software; its own security is a product requirement.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainer (see the repository
owner contact) rather than opening a public issue. Include steps to reproduce and the
affected version. Do not include real assessment evidence in reports.

## Security properties

| Property | Where enforced |
|---|---|
| Collectors are read-only | `collectors/powershell/core` wrappers + static AST test |
| No secrets in evidence | Collector pre-write scan; `packages/core/src/sensitive.ts`; ingestion rejection |
| Evidence integrity | Manifest SHA-256/size verification (`packages/evidence/src/bundle.ts`) |
| Safe archive handling | In-memory ZIP reader with limits (`packages/evidence/src/package-reader.ts`) |
| Safe JSON parsing | `packages/core/src/safe-json.ts` |
| Schema validation, unknown property stripping | `packages/schemas` |
| Missing evidence never PASS | `packages/engine/src/evaluate.ts` + `library.test.ts` |
| Output encoding | React rendering (no raw HTML), escaped report templating (`packages/reporting/src/html-builder.ts`) |
| Web security headers / CSP | `apps/api/src/security.ts` |
| DNS rebinding / CSRF protection | `apps/api/src/security.ts` |
| Loopback-only binding | `apps/api/src/config.ts` |
| Upload size limits | `@fastify/multipart` limits + package limits |
| Structured logging without evidence | `packages/core/src/logger.ts` (redaction), API logs method/route/status only |
| Error handling without secrets | `AdminSecOpsError` public messages |
| Secret scanning of the repository | `npm run scan:secrets` (`scripts/scan-secrets.ts`) |
| Dependency hygiene | Lockfile, minimal dependencies, `npm run audit:deps` |

See [THREAT-MODEL.md](THREAT-MODEL.md) for threats, mitigations and residual risks.

## Development rules

- Never commit credentials, tokens, evidence, customer data or private keys. `.gitignore`
  excludes ZIPs, collector output folders, `.env` and key files; `npm run scan:secrets`
  must pass before merging.
- Sample data must be fictional (`*.example` domains, documentation IP ranges).
- New datasets require a schema, a privacy classification and a permissions entry.
- New controls must never read the wall clock (use `ctx.assessedAt`) and must never PASS
  on missing or unknown data.
- Do not introduce `dangerouslySetInnerHTML`, `innerHTML`, `eval` or dynamic code execution
  (enforced by ESLint).

## Release checklist

`npm run verify` (lint, typecheck, tests, build, secret scan), `npm run test:ps`,
`npm run lint:ps`, `npm run audit:deps`, review `git status` for untracked evidence.
