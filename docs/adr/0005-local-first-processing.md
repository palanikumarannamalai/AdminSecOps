# ADR-0005: Local-first processing

- Status: Accepted
- Date: 2026-09-19

## Context
Assessment evidence describes an organisation's security weaknesses and contains
identifiers of privileged accounts. Many target customers cannot upload it to a
third-party service.

## Decision
The first release runs entirely on the administrator's machine: collectors write a
ZIP, and the local API/CLI process it in memory. The API binds only to loopback and
refuses other addresses. No telemetry, no external calls from the application.

## Consequences
- No authentication is implemented for the local API; it is protected by loopback
  binding, a Host allowlist, Origin checks and a required client header (see THREAT-MODEL.md).
- A hosted Azure service will require authentication, tenant isolation, encryption at
  rest and evidence signing before it can be offered (ROADMAP.md).
