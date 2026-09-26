# Known limitations

This is an honest list of what the 0.1.0 development milestone does **not** do, or does
only partially. Placeholder or planned capabilities are not presented as implemented.

## Validation status

- **Collectors are not validated against live services in this repository.** They were
  written against documented Microsoft Graph, Exchange Online, Azure Resource Manager,
  ActiveDirectory and GroupPolicy shapes and are tested with recorded, sanitized
  responses (replay mode) and a cross-language contract test. Real tenants, subscriptions
  and forests may return shapes, paging behaviour, throttling or errors not yet covered.
  Run a first collection in a test environment and review `logs/collection-log.json`.
- Collector specifics:
  - live error handling (real Graph/ARM error objects, throttling) is exercised only through
    replay and mocks; licence errors whose text is not recognised are reported as
    Unauthorized or Failed rather than NotApplicable;
  - `exchange.smtpAuthMailboxes` records the primary SMTP address (Get-EXOCASMailbox returns no UPN);
  - `ad.users` counts users with one query per domain, which is memory-heavy in very large domains;
  - Azure principal name resolution is capped at 500 principals;
  - GPO parsing does not flatten Preferences, scripts, restricted groups or services;
  - `Resolve-DnsName` exists only on Windows; elsewhere mail DNS lookups report Error
    (dependent controls become Not assessed).
- The dashboard is covered by component tests and by API-level end-to-end tests; there
  are no automated browser (Playwright) tests yet.

## Evidence

- SHA-256 hashes detect corruption and after-the-fact modification of individual files
  but the package is **not signed**; someone able to rewrite the manifest can forge a package.
- The Windows module assesses only the host it runs on. There is no remote/multi-host
  collection yet (the dataset already supports multiple hosts).
- `ad.domainControllerSettings` (LDAP signing, channel binding, SMB signing on DCs) is
  optional and requires local administrator rights on each DC; without it the related
  controls are Not assessed.
- `entra.onPremisesSynchronization` requires Global Administrator or Hybrid Identity
  Administrator; with Global Reader it is reported Unauthorized.
- Sign-in activity for guests needs Entra ID P1/P2; the registration report needs P1/P2.

## Controls

- 99 controls are implemented across Entra ID, hybrid identity, Microsoft 365, Intune,
  Azure, Active Directory, AD CS, Group Policy and Windows hosts. Coverage within each area
  is intentionally selective (high-value checks with reliable evidence).
- **Not yet implemented modules/areas:** Microsoft Teams, Defender for Office 365 policy
  depth (anti-phishing, preset policies), Microsoft Defender for Endpoint configuration,
  Intune configuration profiles, security baselines, endpoint security and ASR rules,
  Azure Policy, VMs, SQL, logging beyond the activity log, Entra workload identity and
  federation settings, Exchange Hybrid, AD CS CA-level issues (ESC6/ESC7/ESC8, web
  enrollment), GPO comparison against Microsoft security baselines (Windows, Edge,
  Microsoft 365 Apps). The architecture supports them; see ROADMAP.md.
- Some controls return **REVIEW** where evidence cannot settle the question (for example
  applications with high-impact permissions, custom authentication strengths, custom
  outbound spam policies set to On, non-privileged accounts with SPNs). The reason is
  always stated.
- Conditional Access analysis does not resolve group membership of included/excluded
  groups; exclusions are reported as notes for review.
- Threshold choices (for example 4 Global Administrators, 180-day KRBTGT rotation,
  90-day inactivity, 365-day secret lifetime) are explicit, documented parameters; they
  are not yet configurable per organisation in the UI.
- Framework mappings reference identifiers only and do not imply compliance. CISA SCuBA
  identifiers are versioned and should be re-checked when ScubaGear releases change.
- Windows 10 end of support is modelled as 14 October 2025; Extended Security Updates
  coverage is not detected, so ESU-covered systems are still reported.

## Application

- Single local user; no authentication (protected by loopback binding, Host allowlist,
  Origin and client-header checks). Not designed to be exposed on a network.
- Processed results are stored as JSON in the user profile; they are not encrypted by
  the application (rely on disk encryption / profile ACLs).
- One evidence package is processed at a time; very large tenants may approach the
  100 MB upload / 256 MB uncompressed limits.
- Comparison works at finding level (new / resolved / changed findings and control
  status changes); value-level configuration drift is planned.
- Reports: HTML and JSON only. PDF, executive and remediation-tracker formats are planned.
- No exceptions / risk-acceptance workflow yet.

## Online (hosted control plane) collection

See [ONLINE-WORKLOADS.md](ONLINE-WORKLOADS.md#not-available-online-and-why).

- Exchange Online and Defender for Office 365 settings, Teams tenant-wide policies and
  beta-only properties are not available to delegated Microsoft Graph v1.0. The affected
  controls are always NOT_ASSESSED online.
- Teams per-team settings are owner-chosen, not tenant policy. At most 200 teams are read
  per assessment, and teams the signed-in administrator cannot read make the evidence
  Partial.
- The live behaviour of the new SharePoint, Teams and Intune endpoints has only been
  validated against synthetic Microsoft Graph responses, not against a live tenant.

## Hosted browser mode

See [HOSTED-BROWSER-MODE.md](HOSTED-BROWSER-MODE.md#hosted-mode-limitations).

- Processing runs on the page's main thread; large packages can make the tab unresponsive
  for a few seconds.
- The archive, inflated files and results are held in browser memory together; packages
  near the 256 MB uncompressed limit may fail on mobile devices. Use local mode for those.
- The browser cannot collect evidence (no PowerShell, AD, AD CS, Group Policy, Windows host
  or cloud API access). Collection remains a separate, read-only administrative step.
- Opt-in on-device persistence (IndexedDB) is not encrypted by the application.
- Automated keyboard-navigation tests do not run on WebKit, because Safari's Tab key
  behaviour depends on a user preference; Chromium and Firefox are tested.
