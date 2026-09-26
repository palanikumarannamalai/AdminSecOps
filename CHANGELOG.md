# Changelog

## Unreleased

- Launch review corrections:
  - The hosted service no longer offers the Exchange Online connector: its only supported
    connection needs the management-scoped `Exchange.Manage` permission. The README, landing
    page, sign-in page and `docs/ONLINE-CONNECTORS.md` say so, and the connector guide lists
    the exact scopes each enabled connector requests.
  - The sign-in page, landing page, README and connector guide warn that no live tenant has
    been validated in this release.
  - The README disclaimer no longer names an employer.
  - The landing page and README no longer list Exchange Online as online coverage;
    Exchange Online and on-premises collection are available only in the local edition.
  - Real identifiers removed from the tree (history is unchanged). The tenant and subscription
    IDs and tenant name in the infra docs and one web test are now fictional
    (`aaaaaaaa-0000-4000-8000-00000000000N`, Contoso). The administrator account and
    application (client) ID are placeholders (`<admin-upn>`, `<client-id>`). The App Service
    deployment IDs in `docs/validation/` are now `<deployment-id>`.
  - `npm run scan:secrets` (part of `npm run verify`) now fails on any GUID that is not
    obviously fictional, produced by the seeded fixture generator, or listed with its source
    in `scripts/known-guids.ts`. The allowlist holds 60 Microsoft-published identifiers
    checked against Microsoft Learn, plus the project's own and hand-written test values.
  - `docs/ONLINE-CONNECTORS.md` and `docs/PRIVACY.md` ask administrators to confirm the app
    name and publisher on Microsoft's consent screen before granting.

- Online connectors (hosted collector 0.3.0; engine and control library unchanged at 0.3.0):
  - **Entra.** Collects the remaining six datasets: PIM assignment instances and
    eligibilities, applications, service principals, API permission grants and directory
    synchronization. One new delegated scope, `OnPremDirectorySynchronization.Read.All`.
  - **Intune.** `intune.settings` falls back to one exact Graph beta property path
    (`/beta/deviceManagement/settings`) when v1.0 omits the settings.
  - **Azure.** A separately consented Azure Resource Manager connector with its own
    AAD-bound encrypted token. It uses tenant-bound subscription discovery, allow-listed
    read operations and a strict nextLink policy. Disabled until `ONLINE_CONNECTORS`
    enables it.
  - **Exchange Online.** A connector that runs one fixed, read-only PowerShell script on the
    server. Disabled until the owner approves `Exchange.Manage` and a runtime is installed.
  - **DNS.** Public SPF/DMARC checks with explicit provenance limits.
  - **Coverage page.** Distinguishes not connected, consent required, unsupported and
    collection failure. The home page lets users connect, reconnect or disconnect each
    source.
  - See `docs/ONLINE-CONNECTORS.md`.

- Online workloads (engine 0.3.0, control library 0.3.0, hosted collector 0.2.0, PowerShell
  collector 0.2.0):
  - A unified read-only Graph v1.0 collector for Entra ID, SharePoint/OneDrive, Microsoft Teams
    settings and Intune, with shared budgets, bounded per-resource requests and tenant
    verification first.
  - Exchange Online is reported as not available online.
  - New datasets `m365.teamsAppSettings` and `m365.teamsTeamSettings`; optional SharePoint
    domain-list and idle sign-out fields.
  - New controls M365-SPO-003, M365-SPO-004, M365-TMS-001 and M365-TMS-002 (review-based where
    the setting depends on context).
  - Coverage page per workload.
  - Consent-aware `/api/me` with a re-consent sign-in path.
  - See `docs/ONLINE-WORKLOADS.md`.

- Hosted browser mode: a static build of the dashboard that runs the engine entirely in
  the browser, published at https://www.palanikumar.net/tools/adminsecops/app. No
  server-side API; strict Content-Security-Policy with `connect-src 'none'`; fictional
  samples; optional, explicit on-device persistence with "Delete local data".
- Browser-safe evidence reader (`@adminsecops/evidence/browser`) with the same ZIP limits,
  integrity and secret checks as the Node reader; SHA-256 via `@noble/hashes`.
- Dashboard: light and dark themes, focusable scrollable tables, mobile layout fixes.
- Playwright browser tests (Chromium, Firefox, WebKit) with automated WCAG checks.

## 0.1.0-beta - 2026-09-19

- First public beta for authorised testing in non-production environments.
- Local dashboard, API and CLI for processing assessment evidence.
- Read-only collectors for Entra ID, Microsoft 365, Exchange Online, Intune, Azure,
  Active Directory, AD CS, Group Policy and Windows.
- 99 deterministic controls with evidence status, prioritisation, remediation, rollback
  and validation guidance.
- Fictional sample environments and offline replay tests.

Known limitations are maintained in `docs/KNOWN-LIMITATIONS.md`.
