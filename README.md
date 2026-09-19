# AdminSecOps

**You're the admin. Are you secure?**
Security assessment and remediation guidance for Microsoft administrators.

AdminSecOps answers: *Is my Microsoft environment secure, what have I missed, and what
should I fix first?* It collects configuration evidence with read-only PowerShell
collectors, verifies it, evaluates it with deterministic and tested controls, prioritizes
the findings, and tells you how to fix, roll back and verify each one - all on your own
machine.

> Status: **0.1.0 development milestone** (free, local-only). See
> [KNOWN-LIMITATIONS](docs/KNOWN-LIMITATIONS.md) before relying on results.

## How it works

```
Administrator -> PowerShell collector (read-only) -> adminsecops-assessment.zip
      -> AdminSecOps local app (evidence verification -> normalized inventory
         -> deterministic controls -> findings -> prioritization)
      -> dashboard + HTML/JSON reports
```

- **Collectors collect facts. Controls evaluate facts. The UI displays results.**
- Evidence is hashed (SHA-256) in `evidence-manifest.json` and verified before use.
- Missing, failed or unauthorized evidence is reported as **Not assessed** - never Pass.
- No AI decides results. No composite "security score" - counts, coverage and a
  documented "What should I fix first?" order instead.
- Nothing is sent to any cloud service. The local API only listens on 127.0.0.1.

## What it covers today

| Module | Implemented controls | Collector |
|---|---|---|
| Entra ID (incl. hybrid identity) | 27 | Microsoft Graph (read scopes) |
| Microsoft 365 (Exchange Online, mail DNS, SharePoint, Defender for Office 365) | 14 | Exchange Online PowerShell, Graph, DNS |
| Intune | 4 | Microsoft Graph |
| Azure | 12 | Azure Resource Manager (Reader) |
| Active Directory | 23 | ActiveDirectory module (domain user) |
| AD CS / PKI | 4 | Active Directory configuration partition |
| Group Policy | 4 | GroupPolicy module, SYSVOL |
| Windows host | 11 | Local registry/CIM (local admin) |
| **Total** | **99** | |

The full list with severities and framework mappings is in
[docs/CONTROL-CATALOG.md](docs/CONTROL-CATALOG.md); exactly what is collected and the
permissions needed are in [docs/DATA-COLLECTION.md](docs/DATA-COLLECTION.md).

## Quick start

Prerequisites: Node.js 22.22+, PowerShell 7.2+ (for collection).

```powershell
npm install
npm run build
npm start          # open http://localhost:4310
```

In the dashboard choose **Load sample** to explore sanitized, fictional environments
(Contoso, Contoso follow-up, Fabrikam), or upload a collector package.

Collect evidence from your environment (read-only; see
[collectors/powershell/README.md](collectors/powershell/README.md)):

```powershell
Import-Module .\collectors\powershell\AdminSecOps.Collector.psd1
Get-AdminSecOpsPermission -Module All        # what access is needed and why
Test-AdminSecOpsPrerequisite -Module Entra
Invoke-AdminSecOpsCollection -Module Entra, M365, Exchange -OutputPath C:\AdminSecOps-Evidence
```

Assess offline from the command line:

```powershell
node apps/cli/dist/main.js assess C:\AdminSecOps-Evidence\adminsecops-assessment-<timestamp>.zip --out .\reports
```

Run the end-to-end demonstration on sanitized data: `npm run demo`.

## Repository

| Path | Contents |
|---|---|
| `apps/web` | React dashboard |
| `apps/api` | Local REST API (serves the dashboard) |
| `apps/cli` | Command-line interface |
| `packages/core` | Vocabulary, safe JSON, hashing, secret detection, logging |
| `packages/schemas` | Evidence contract and result schemas (Zod) |
| `packages/evidence` | Safe package reading and integrity verification |
| `packages/inventory` | Normalized inventory and derived views |
| `packages/controls` | Control API and library |
| `packages/engine` | Evaluation, findings, prioritization, comparison |
| `packages/reporting` | HTML and JSON reports |
| `collectors/powershell` | Read-only collectors |
| `fixtures/` | Sanitized fictional evidence packages |
| `docs/` | Engineering documentation and ADRs |

## Development

```powershell
npm run verify     # lint, typecheck, tests, production build, secret scan
npm run test:ps    # Pester tests for collectors
npm run lint:ps    # PSScriptAnalyzer
```

See [DEVELOPMENT](docs/DEVELOPMENT.md), [TESTING](docs/TESTING.md),
[ARCHITECTURE](docs/ARCHITECTURE.md), [CONTROL-MODEL](docs/CONTROL-MODEL.md),
[EVIDENCE-MODEL](docs/EVIDENCE-MODEL.md), [THREAT-MODEL](docs/THREAT-MODEL.md),
[PRIVACY](docs/PRIVACY.md), [SECURITY](docs/SECURITY.md),
[ADDING-A-CONTROL](docs/ADDING-A-CONTROL.md), [ADDING-A-COLLECTOR](docs/ADDING-A-COLLECTOR.md),
[COLLECTOR-ARCHITECTURE](docs/COLLECTOR-ARCHITECTURE.md), [ROADMAP](docs/ROADMAP.md),
[PRODUCT-VISION](docs/PRODUCT-VISION.md), [KNOWN-LIMITATIONS](docs/KNOWN-LIMITATIONS.md).

## Handling assessment data

Evidence packages and reports describe your security weaknesses and contain account
identifiers. Keep them in an access-controlled location and delete them when finished.
Never commit them to source control.
