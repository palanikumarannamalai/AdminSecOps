# Development

## Prerequisites

- Node.js 22.22 or later (npm 10+)
- PowerShell 7.2+ for collectors and collector tests
- Pester 5+ and PSScriptAnalyzer for PowerShell tests/lint:
  `Install-Module Pester, PSScriptAnalyzer -Scope CurrentUser`

## Setup

```powershell
npm install
npm run build
npm test
```

## Running locally

```powershell
npm run build
npm start                 # API + dashboard on http://localhost:4310
```

Development with hot reload (two terminals):

```powershell
$env:ADMINSECOPS_DEV = '1'; npm run dev:api     # API on 127.0.0.1:4310
npm run dev:web                                  # Vite on http://localhost:5173 (proxies /api)
```

Environment variables (API):

| Variable | Default | Meaning |
|---|---|---|
| `ADMINSECOPS_PORT` | `4310` | Listen port |
| `ADMINSECOPS_HOST` | `127.0.0.1` | Must be a loopback address |
| `ADMINSECOPS_DATA_DIR` | `%LOCALAPPDATA%\AdminSecOps\data` | Processed results (sensitive) |
| `ADMINSECOPS_WEB_DIST` | `apps/web/dist` | Built dashboard |
| `ADMINSECOPS_SAMPLES_DIR` | `fixtures/assessments` | Sanitized samples |
| `ADMINSECOPS_DEV` | unset | `1` allows the Vite dev server Host header |

## CLI

```powershell
node apps/cli/dist/main.js assess <package.zip|dir> --out .\reports
node apps/cli/dist/main.js validate <package.zip|dir>
node apps/cli/dist/main.js compare old.json new.json
node apps/cli/dist/main.js controls
```

## Demo

`npm run demo` assesses the three sanitized fixtures end to end and writes reports to
`out/demo` (git-ignored).

## Branching

`main` is stable and must always pass `npm run verify`. Work happens on `feature/*`
branches merged with `--no-ff` after verification.

## Conventions

- ES modules, `.js` extensions in relative imports, strict TypeScript.
- Packages never import from apps; the web app imports only types and pure constants.
- Every new dataset: schema + collector + permissions + privacy class + `npm run docs:generate`.
- Every new control: see ADDING-A-CONTROL.md.
