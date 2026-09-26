# AdminSecOps

**You're the admin. Are you secure?**
Security assessment and remediation guidance for Microsoft administrators.

AdminSecOps is a free, independent community project by Palanikumar Annamalai. It is not
affiliated with or endorsed by Microsoft or any current or former employer.

AdminSecOps collects configuration evidence through fixed read operations, evaluates it
with deterministic controls and explains findings, remediation, rollback and verification.
It does not automatically remediate your environment.

**Status: online test release.** No live tenant has been validated in this release —
connect an authorised test tenant, not production. Implemented connectors are not a
guarantee of complete coverage. Validate results in an authorised test environment before
relying on them.

- [Launch the online app](https://app.adminsecops.com)
- [About the project and author](https://www.palanikumar.net/tools/adminsecops)
- [Contribute](CONTRIBUTING.md) · [Roadmap](docs/ROADMAP.md) · [Changes](CHANGELOG.md)

## Choose how to use it

| Mode | Where assessment data is processed | Getting started |
|---|---|---|
| Online app | Hosted service; results retained 30 days and audit events 90 days | Sign in with Microsoft at app.adminsecops.com; grant the required tenant consent |
| Static browser edition | Your browser tab; no assessment API | [Explore fictional samples](https://www.palanikumar.net/tools/adminsecops/app/) — this is the older browser edition |
| Local application / CLI | Your machine; you manage evidence and results | Build from source below; use the PowerShell collector for local evidence |

## Online coverage

Microsoft Graph supplies Entra ID, SharePoint/OneDrive tenant settings, Teams app and
per-team settings, and Intune evidence. Azure has a separate connection and consent flow.
Public DNS supplies mail authentication records.

Exchange Online assessment is not enabled in the hosted service. The only Exchange connection
Microsoft offers for this data requires a management-scoped permission, so it stays off until
there is a read-only path or an explicit opt-in. See
[docs/ONLINE-CONNECTORS.md](docs/ONLINE-CONNECTORS.md#exchange-online-fixed-server-side-runner).

Exchange Online and on-premises collection are available only in the local edition.

Coverage depends on permissions, roles, licensing and successful collection. Teams tenant
policies are not available online, and on-premises means AD, AD CS, Group Policy and
Windows. The current connector release still needs end-to-end validation in authorised
customer tenants; an implemented connector is not a claim that all live scenarios pass.

Missing, failed or unauthorised evidence is **Not assessed**, never Pass. Coverage counts
are not a security score, and an assessment is not certification or a guarantee of security.

See the [control catalogue](docs/CONTROL-CATALOG.md),
[online connectors and permissions](docs/ONLINE-CONNECTORS.md),
[online workloads](docs/ONLINE-WORKLOADS.md) and [limitations](docs/KNOWN-LIMITATIONS.md).

## Quick start

Prerequisites: Node.js 22.22+, PowerShell 7.2+ (for collection).

```powershell
npm ci
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
| `apps/web` | React dashboard: online, local and static browser modes |
| `apps/control-plane` | Hosted sign-in, tenant-bound API, collection worker and PostgreSQL persistence |
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
[PRODUCT-VISION](docs/PRODUCT-VISION.md), [KNOWN-LIMITATIONS](docs/KNOWN-LIMITATIONS.md),
[HOSTED-BROWSER-MODE](docs/HOSTED-BROWSER-MODE.md).

## Handling assessment data

Evidence packages and reports describe your security weaknesses and contain account
identifiers. Keep them in an access-controlled location and delete them when finished.
Never commit them to source control.

Do not include tenant names, identifiers, credentials, access tokens, logs, screenshots or
raw assessment output in a public GitHub issue. See [SECURITY](SECURITY.md) for reporting
security concerns and [PRIVACY](docs/PRIVACY.md) for the mode-specific data-handling model.
