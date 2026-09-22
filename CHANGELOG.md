# Changelog

## Unreleased

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
