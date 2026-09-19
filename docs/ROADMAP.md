# Roadmap

Status as of the 0.1.0 development milestone. Items are ordered by value to administrators.

## Next (recommended next development phase)

1. **Live collector validation.** Run the collectors against a dedicated test tenant, test
   Azure subscription and lab AD forest; record sanitized responses as new replay scenarios;
   fix any shape differences. Required before a public release.
2. **Evidence package signing.** Collector signs the manifest (per-run key, certificate or
   Sigstore-style); engine verifies. Prerequisite for any hosted processing.
3. **Schema extensions recommended by control authors** (each unlocks more precise results):
   - `exchange.outboundSpamPolicies`: rule state and sender scope (decide custom "On" policies).
   - `exchange.acceptedDomains`: `MatchSubDomains`.
   - Inbox-rule forwarding dataset (closes the gap noted by M365-EXO-005).
   - `windows.hosts`: OS edition/product type, Defender running mode, LSA PPL runtime state.
   - `azure.networkSecurityGroups`: subnet/NIC associations; `azure.storageAccounts`: creation time.
   - `gpo.groupPolicyObjects`: link order and security filtering (effective winner).
   - `ad.domainControllerSettings`: domain; `ad.users`: `supportedEncryptionTypes`;
     `ad.trusts`: raw `trustAttributes`; `ad.computers`: Entra-backed LAPS marker.
   - `adcs.certificateTemplates`: owner, `msPKI-RA-Application-Policies`, DN;
     `adcs.certificateAuthorities`: EDITF flags (ESC6), CA ACL (ESC7), enrollment-agent restrictions.
4. **Control library expansion** (evidence-backed only): Teams external access and
   meeting policies, Defender for Office 365 preset policies and anti-phishing, Intune
   configuration profiles / security baselines / ASR rules / BitLocker reporting, Azure
   Policy assignments and Key Vault/SQL/VM configuration, Entra workload identities and
   federation settings, AD CS ESC6/ESC7/ESC8 (web enrollment), GPO baseline comparison
   against Microsoft security baselines (Windows, Edge, Microsoft 365 Apps).
5. **Browser end-to-end tests** (Playwright) for the dashboard.
6. **Code signing** of the PowerShell module and release artifacts; SBOM generation.

## Later

- PDF, executive and technical report variants; remediation tracker export; evidence
  package export with verification instructions.
- Configuration-level drift (value-by-value diff of datasets), not just finding drift.
- Exceptions / risk acceptance records (documented, expiring) that change a finding's
  presentation without changing its deterministic status.
- Optional AI assistance that explains findings and drafts change plans from results
  (never determines results; see ADR-0002).

## Commercial (not in the free release; architecture prepared)

Continuous monitoring and scheduled assessments, assessment history, multi-customer/MSP
workspaces, white-label reporting, custom controls, APIs, hosted evidence processing on
Azure (see THREAT-MODEL.md "Future hosted service"), team RBAC, commercial reporting.
