# ADR-0007: Hosted browser mode without a server API

- Status: Accepted
- Date: 2026-09-19

## Context
Visitors to www.palanikumar.net should be able to try AdminSecOps without installing
Node.js. ADR-0005 keeps evidence on the administrator's machine, and the local API has no
authentication, so it must never be exposed to the internet. A hosted service that accepts
tenant evidence would need authentication, tenant isolation and encryption at rest first.

## Decision
Publish a static build of `apps/web` that runs the evidence reader, engine and reporting
in the visitor's browser. The site serves only static files; there is no API that accepts
evidence. The page's Content-Security-Policy sets `connect-src 'none'`, so the page cannot
send data anywhere. Node-only code paths get browser-safe equivalents (ZIP reader, SHA-256)
with parity tests instead of being moved to a server. Results stay in memory unless the
visitor explicitly opts in to on-device storage.

## Consequences
- Evidence processing on the hosted page is as private as the visitor's browser.
- The browser build is limited by main-thread processing and browser memory; local mode
  remains the recommendation for large tenants and for regular use.
- The website repository vendors the AdminSecOps source and commits the built app; updates
  follow docs/HOSTED-BROWSER-MODE.md.
