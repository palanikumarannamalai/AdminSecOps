# Changelog

## Unreleased

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
