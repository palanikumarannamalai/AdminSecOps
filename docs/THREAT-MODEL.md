# Threat model

Scope: the collectors, the evidence package, the local application (API, dashboard, CLI)
and the planned hosted service. Method: STRIDE per component, with the assets and trust
boundaries below. Status column: **Mitigated** (implemented and tested), **Partial**,
**Planned**, **Accepted** (documented residual risk).

## Assets

| Asset | Sensitivity |
|---|---|
| Evidence package | High: configuration weaknesses, privileged account names, tenant/forest identifiers. Must never contain credentials. |
| Processed assessment results / reports | High: the same, plus prioritized weaknesses (an attacker's to-do list). |
| Collector session (Graph / Exchange / Azure / AD access) | Critical: read access to directory and configuration. |
| Control library and engine | Integrity-critical: wrong rules produce false assurance. |

## Trust boundaries

1. Microsoft services / AD  <->  collector (runs as the administrator).
2. Collector output  <->  engine ingestion (package may be modified in transit or crafted).
3. Browser  <->  local API (other websites in the same browser are untrusted).
4. Local machine  <->  network (nothing should be exposed).
5. (Future) customer  <->  hosted service.

## Collectors

| Threat | Mitigation | Status |
|---|---|---|
| Collector changes configuration (bug or tampering) | All data access goes through GET-only / Get-* allowlisted wrappers; static AST test fails on write verbs or non-GET HTTP methods. | Mitigated (see collector README) |
| Collector captures secrets (tokens, passwords, secret hints, LAPS passwords, cpassword values) | Datasets request metadata only; explicit dropping of `hint`/key values; pre-write secret scan blocks a dataset; engine re-scans and rejects. | Mitigated |
| Over-privileged collection account | Least-privilege roles documented per dataset (DATA-COLLECTION.md); read-only Graph scopes; optional elevated collection is opt-in. | Mitigated |
| Collecting from the wrong tenant via a reused or cached session (e.g. an Az context cached on disk) | Tenant guard: sessions are displayed; with `-TenantId` any session in another tenant aborts the run; without it, multi-tenant sessions abort. | Mitigated, tested |
| Token persistence | Interactive auth via Microsoft modules; the collector never writes tokens; `-KeepConnections` not default. | Mitigated |
| Collector script tampering on disk | Module is plain PowerShell; code signing of releases is planned. | Planned |

## Evidence package and ingestion

| Threat | Mitigation | Status |
|---|---|---|
| Tampering / corruption after collection (T) | SHA-256 and size per file in the manifest; mismatching files are not used; integrity shown prominently. | Mitigated |
| Forged package (manifest rewritten) (S/T) | Hashes are not signatures. Documented; signing planned before the hosted service. | Accepted (local) / Planned |
| Zip bomb, huge files (D) | Archive, entry count, per-file, total and compression-ratio limits; actual (not declared) sizes enforced while streaming. | Mitigated, tested |
| Path traversal / absolute paths / symlinks (T/E) | Nothing is extracted to disk; entry names are validated; symlinks, encrypted and duplicate entries rejected; directory reads refuse links and out-of-root paths. | Mitigated, tested |
| Malicious JSON (prototype pollution, deep nesting, invalid UTF-8) (T/D) | `safeJsonParse`: size and depth limits, forbidden keys, strict UTF-8. | Mitigated, tested |
| Evidence smuggling extra data into reports (I) | Schemas strip undeclared properties; secret scan rejects files. | Mitigated, tested |
| Validation errors leaking evidence values (I) | Messages contain JSON paths and issue codes only. | Mitigated, tested |

## Local application (API + dashboard)

| Threat | Mitigation | Status |
|---|---|---|
| Network exposure (S/I) | API refuses non-loopback bind addresses. | Mitigated, tested |
| DNS rebinding from a malicious website (S) | Host header allowlist (`127.0.0.1`, `localhost`, `[::1]` with the configured port). | Mitigated, tested |
| CSRF from a malicious website (T) | State-changing requests require `X-AdminSecOps-Client` header (forces a CORS preflight that is never granted); cross-origin `Origin` rejected; OPTIONS refused. | Mitigated, tested |
| XSS via evidence values (object names, policy names, collector messages) (T/E) | React text rendering only; `dangerouslySetInnerHTML`/`innerHTML` banned by lint; strict CSP (`script-src 'self'`); links restricted to https. | Mitigated, tested |
| XSS in HTML report opened from disk (T) | Report contains no scripts; all values escaped by a contextual template; meta CSP with hashed style; https-only links. | Mitigated, tested |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY`. | Mitigated |
| Error messages exposing secrets or paths (I) | `AdminSecOpsError` public messages only; generic 500 messages; logs redact sensitive keys and never include payloads. | Mitigated, tested |
| Resource exhaustion by large uploads (D) | 100 MB multipart limit; one package processed at a time. | Mitigated, tested |
| Stored results readable by other local users (I) | Stored in the user profile (`%LOCALAPPDATA%\AdminSecOps\data`), owner-only file mode where supported, atomic writes. On Windows, NTFS ACLs of the profile apply. | Partial |
| Path traversal via assessment IDs (T) | IDs validated as GUIDs before any file access. | Mitigated, tested |
| Malicious local process calling the API (S/E) | Any local process running as the user can already read the user's files. | Accepted |
| Supply chain (dependencies) | Minimal dependency set, lockfile, `npm audit`, no install scripts added. | Partial (SBOM/signing planned) |

## CLI

Reads only the paths given; writes reports with owner-only mode and refuses to
overwrite without `--force`; shares the ingestion protections above.

## Future hosted service (Azure) - required before launch

- Strong authentication (Entra ID, MFA), per-customer tenant isolation, RBAC.
- Evidence signing by the collector and verification on upload.
- Encryption at rest with customer-scoped keys; short retention by default; deletion.
- Malware scanning of uploads; WAF; rate limiting; audit logging of access to results.
- Separation of processing workers from the web tier; no evidence in logs/telemetry.
- Threat model review and penetration test of the hosted service.
