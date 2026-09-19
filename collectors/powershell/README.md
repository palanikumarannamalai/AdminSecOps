# AdminSecOps.Collector (PowerShell 7)

Read-only evidence collectors for AdminSecOps. The module reads security configuration from Microsoft Entra ID,
Microsoft 365 (SharePoint), Exchange Online, Intune, Azure, Active Directory, AD CS, Group Policy and the local
Windows host, and writes a verifiable evidence package that the AdminSecOps engine assesses offline.

> **Validation status - read this first.** Everything in this module is verified by automated tests against
> recorded, sanitized responses (offline replay) and mocked service cmdlets. **No live Microsoft 365, Entra,
> Azure or Active Directory environment has been used to test it.** The Windows host collector (`windows.hosts`)
> is the only dataset that has also been executed live (on a non-elevated Windows 11 development machine). See
> [Validation status and limitations](#validation-status-and-limitations) before relying on a live run.

## Contents

- [Quick start](#quick-start)
- [Commands](#commands)
- [Output package](#output-package)
- [Permissions (least privilege)](#permissions-least-privilege)
- [What is collected and what is never collected](#what-is-collected-and-what-is-never-collected)
- [Collection statuses](#collection-statuses)
- [Read-only and secret-handling guarantees](#read-only-and-secret-handling-guarantees)
- [Offline replay](#offline-replay)
- [Tests](#tests)
- [Validation status and limitations](#validation-status-and-limitations)
- [Layout](#layout)

## Quick start

Requirements: PowerShell 7.2 or later and the Microsoft modules for the services you assess.

| Module(s)             | Required PowerShell module(s)                                  |
| --------------------- | -------------------------------------------------------------- |
| Entra, M365, Intune   | `Microsoft.Graph.Authentication`                               |
| Exchange              | `ExchangeOnlineManagement` (Graph optional, for licence detection) |
| Azure                 | `Az.Accounts` (Graph optional, for principal names)            |
| AD, ADCS              | RSAT `ActiveDirectory`, domain-joined Windows computer        |
| GPO                   | RSAT `GroupPolicy` and `ActiveDirectory`, domain-joined Windows computer |
| Windows               | none (Windows only; run elevated for complete results)         |

```powershell
Import-Module ./collectors/powershell/AdminSecOps.Collector.psd1

# What will be needed and what is collected
Get-AdminSecOpsPermission -Summary
Test-AdminSecOpsPrerequisite -Module Entra, Exchange

# Cloud assessment (interactive, read-only sign-in; nothing is stored)
Invoke-AdminSecOpsCollection -Module Entra, M365, Exchange, Intune, Azure -OutputPath C:\Assessments -Label 'Contoso'

# On-premises assessment, run on a domain-joined admin workstation as a domain user
Invoke-AdminSecOpsCollection -Module AD, ADCS, GPO -OutputPath C:\Assessments

# Everything, reusing sessions you opened yourself (Connect-MgGraph / Connect-ExchangeOnline / Connect-AzAccount)
Invoke-AdminSecOpsCollection -Module All -SkipConnect
```

Upload or open the resulting `adminsecops-assessment-<timestamp>.zip` in AdminSecOps.

## Commands

### `Invoke-AdminSecOpsCollection`

```
Invoke-AdminSecOpsCollection -Module <Entra|M365|Exchange|Intune|Azure|AD|ADCS|GPO|Windows|All>[]
    [-OutputPath <dir>] [-Label <string>] [-TenantId <guid>] [-IncludeDomainControllerSettings]
    [-ReplayPath <dir>] [-NoZip] [-SkipConnect]
```

- Signs in interactively (`Connect-MgGraph -Scopes <read scopes> -NoWelcome`, `Connect-ExchangeOnline -ShowBanner:$false`,
  `Connect-AzAccount`) only when no session exists and neither `-SkipConnect` nor `-ReplayPath` is used.
- Runs the selected modules in a fixed order; one dataset failing never stops the module, and one module failing
  never stops the run.
- Returns a summary object: `AssessmentId`, `Mode`, `PackagePath`, `ManifestPath`, `ZipPath`, `Modules`,
  `DatasetCount`, `DatasetsByStatus`.
- `-IncludeDomainControllerSettings` additionally reads LDAP signing, LDAP channel binding and SMB signing
  registry values from every domain controller through the Remote Registry service (read-only; requires local
  administrator on the DCs). Without it, `ad.domainControllerSettings` is written with status `NotCollected`.

### `Get-AdminSecOpsPermission [-Module ...] [-Summary]`

Explains, per dataset (or per module with `-Summary`), the read operations performed, the least-privilege
permissions, licence prerequisites and what is never collected.

### `Test-AdminSecOpsPrerequisite [-Module ...]`

Checks PowerShell version, required modules, existing service connections (without connecting), elevation
(Windows) and domain membership (AD, ADCS, GPO). `Required = $false` checks only reduce completeness.

## Output package

```
<OutputPath>/
  AdminSecOps-Assessment-<yyyyMMdd-HHmmss>/
    evidence-manifest.json
    evidence/<module>/<dataset>.json        (one envelope per dataset, e.g. evidence/entra/conditionalAccessPolicies.json)
    logs/collection-log.json
  adminsecops-assessment-<yyyyMMdd-HHmmss>.zip   (unless -NoZip)
```

- One GUID `assessmentId` per run, repeated in every envelope.
- Every envelope: `schemaVersion`, `datasetId`, `assessmentId`, `collector {name, version, module, moduleVersion}`,
  `collectedAt`, `source {system, operations[], apiVersion}`, `status`, `errors[]`, `warnings[]`, `data`
  (`null` unless `Success` or `Partial`). `data` follows the zod schema of the dataset in
  `packages/schemas/src/datasets/*.ts`.
- The manifest lists each file with its lower-case SHA-256 (computed after writing) and size, so the engine can
  detect any modification. Files are UTF-8 without BOM; timestamps are ISO-8601 UTC (`2026-09-01T10:00:00.0000000Z`).
- The ZIP is built with `System.IO.Compression.ZipArchive` and forward-slash entry names.
- Generated packages are ignored by git (`.gitignore`). Treat them as confidential: they contain identifiers
  (UPNs, account and group names) and security configuration.

## Permissions (least privilege)

| Module   | Role / rights                                                                 | Sign-in |
| -------- | ------------------------------------------------------------------------------ | ------- |
| Entra    | Microsoft Entra **Global Reader** (Security Reader suffices for most datasets). `entra.onPremisesSynchronization` additionally requires Hybrid Identity Administrator or Global Administrator; without it the dataset is `Unauthorized`. | Microsoft Graph, delegated |
| M365     | Global Reader (or SharePoint Administrator)                                    | Microsoft Graph, delegated |
| Exchange | Exchange Online **View-Only Organization Management** (or Global Reader)       | `Connect-ExchangeOnline` |
| Intune   | Global Reader (or an Intune read-only role)                                    | Microsoft Graph, delegated |
| Azure    | Azure RBAC **Reader** on each subscription or a parent management group        | `Connect-AzAccount` |
| AD       | Any authenticated **domain user**; local administrator on DCs only for `-IncludeDomainControllerSettings` | Current Windows identity |
| ADCS     | Any authenticated domain user (Configuration partition read)                   | Current Windows identity |
| GPO      | Any authenticated domain user (GPO and SYSVOL read)                            | Current Windows identity |
| Windows  | **Local administrator** on the assessed host for complete results              | Local only |

Microsoft Graph delegated scopes requested (all read-only; admin consent is required for some):
`Organization.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory`, `RoleAssignmentSchedule.Read.Directory`,
`RoleEligibilitySchedule.Read.Directory`, `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All`,
`Application.Read.All`, `Directory.Read.All`, `User.Read.All`, `OnPremDirectorySynchronization.Read.All`,
`SharePointTenantSettings.Read.All`, `DeviceManagementConfiguration.Read.All`, `DeviceManagementManagedDevices.Read.All`.

Run `Get-AdminSecOpsPermission` for the per-dataset operations and permissions.

## What is collected and what is never collected

| Dataset area | Live data source (read operations) |
| --- | --- |
| `entra.*` (17 datasets) | Graph v1.0 GET: `organization`, `subscribedSkus`, `policies/identitySecurityDefaultsEnforcementPolicy`, `policies/authorizationPolicy`, `identity/conditionalAccess/policies`, `roleManagement/directory/roleDefinitions`, `roleAssignments?$expand=principal`, `roleAssignmentScheduleInstances`, `roleEligibilitySchedules`, `reports/authenticationMethods/userRegistrationDetails`, `policies/authenticationMethodsPolicy` (+ per-method configuration when targets are not inline), `applications`, `servicePrincipals` (`$select` with credential metadata), `servicePrincipals(appId=...)` + `appRoleAssignedTo` for Microsoft Graph and Office 365 Exchange Online, `groupSettings`, `users?$filter=userType eq 'Guest'` (+ `signInActivity`), `directory/onPremisesSynchronization` |
| `m365.sharePointSettings` | Graph v1.0 GET `admin/sharepoint/settings` |
| `exchange.*` (11 datasets) | `Get-OrganizationConfig`, `Get-TransportConfig`, `Get-AdminAuditLogConfig`, `Get-AcceptedDomain`, `Get-DkimSigningConfig`, `Get-HostedOutboundSpamFilterPolicy`, `Get-RemoteDomain`, `Get-EXOMailbox -Filter` (forwarding only), `Get-EXOCASMailbox -Properties SmtpClientAuthenticationDisabled`, `Get-AtpPolicyForO365`, `Resolve-DnsName -Type TXT` (SPF, `_dmarc`) for every authoritative accepted domain |
| `intune.*` (3 datasets) | Graph v1.0 GET `deviceManagement?$select=settings`, `deviceManagement/managedDeviceOverview`, `deviceManagement/deviceCompliancePolicies?$expand=assignments` |
| `azure.*` (8 datasets) | ARM GET per subscription: `subscriptions` (2022-12-01), `Microsoft.Authorization/roleAssignments` + `roleDefinitions` (2022-04-01) with optional Graph `directoryObjects/{id}` name lookup, `Microsoft.Security/pricings` (2024-01-01), `securityContacts` (2023-12-01-preview), `Microsoft.Storage/storageAccounts` (2023-05-01), `Microsoft.KeyVault/vaults` (2023-07-01), `Microsoft.Network/networkSecurityGroups` (2023-09-01, custom rules only), `Microsoft.Insights/diagnosticSettings` (2021-05-01-preview) |
| `ad.*` (10 datasets) | `Get-ADForest`, `Get-ADOptionalFeature`, `Get-ADDomain`, `Get-ADObject` (machine account quota, LAPS schema attributes), `Get-ADDefaultDomainPasswordPolicy`, `Get-ADFineGrainedPasswordPolicy`, `Get-ADGroup`/`Get-ADGroupMember -Recursive` (well-known privileged group SIDs), `Get-ADUser` (counts; security-relevant LDAP filter; krbtgt), `Get-ADComputer`, `Get-ADTrust`, `Get-ADDomainController`, optional remote registry reads on DCs |
| `adcs.*` (2 datasets) | `Get-ADRootDSE`, `Get-ADObject` under `CN=Enrollment Services` and `CN=Certificate Templates` (flags, EKUs, `nTSecurityDescriptor` access rules) |
| `gpo.*` (2 datasets) | `Get-GPO -All`, `Get-GPOReport -ReportType Xml` per GPO; SYSVOL scan of `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `DataSources.xml`, `Drives.xml`, `Printers.xml` |
| `windows.hosts` | Local host only: `Get-CimInstance` (`Win32_OperatingSystem`, `Win32_ComputerSystem`, `Win32_DeviceGuard`), `Get-NetFirewallProfile -PolicyStore ActiveStore`, `Get-SmbServerConfiguration`, read-only HKLM registry, `Get-MpComputerStatus` |

**Never collected** (not requested, and blocked by the local secret scan if it ever appeared):
client secret values and `passwordCredentials.hint` / `secretText`, certificate key material, access or refresh
tokens (the Graph context is only read for tenant ID and granted scope names), user passwords and hashes,
LAPS passwords (`ms-Mcs-AdmPwd`, `msLAPS-Password`, encrypted LAPS attributes are refused by the AD wrapper),
BitLocker recovery data, custom banned password lists (only allow-listed directory setting names are kept),
security contact e-mail addresses and phone numbers (only a count), storage account keys and connection strings,
Key Vault secrets/keys/certificates, mail, message bodies, inbox rules, files, event logs, GPP `cpassword` values
(files are scanned in memory; only domain, GPO GUID, relative path and file name are recorded), and GPO registry
values whose name suggests a credential (recorded with `value: null` and a warning).

## Collection statuses

| Status | When |
| --- | --- |
| `Success` | Dataset collected completely. |
| `Partial` | Some pages, subscriptions, domains, hosts or objects failed; `errors[]` says which. `data` is valid for what was read. |
| `Unauthorized` | HTTP 401/403, `Authorization_RequestDenied`, `AuthorizationFailed`, AD/registry access denied. |
| `NotApplicable` | Licence or feature absent. Detected from `entra.subscribedSkus` service plans (`AAD_PREMIUM`, `AAD_PREMIUM_P2`, `INTUNE_A`, `ATP_ENTERPRISE`, `THREAT_INTELLIGENCE`) when Graph is available, and from licence-specific service errors (e.g. `Authentication_RequestFromNonPremiumTenantOrB2CTenant`, "Request not applicable to target tenant"). A warning explains why. |
| `NotCollected` | Option not selected (`ad.domainControllerSettings` without `-IncludeDomainControllerSettings`) or a module prerequisite is missing (module not installed, not connected, not domain-joined). |
| `Failed` | Any other exception, including `SENSITIVE_CONTENT_BLOCKED` when the local secret scan rejects the data. |

Module status in the manifest: `Completed`, `CompletedWithErrors` (some `Partial`/`Failed`/`Unauthorized`),
`Failed` (all datasets failed) or `Skipped` (prerequisites not met).

## Read-only and secret-handling guarantees

- All data access goes through wrappers in `core/DataAccess.ps1`: `Invoke-AsoGraphGet` (only
  `Invoke-MgGraphRequest -Method GET`, `@odata.nextLink` paging, 429/503 `Retry-After` handling),
  `Invoke-AsoArmGet` (only `Invoke-AzRestMethod -Method GET`), `Invoke-AsoExoCommand` / `Invoke-AsoAdCommand` /
  `Invoke-AsoGpoCommand` / `Invoke-AsoWindowsCommand` (explicit allow-lists of `Get-*` cmdlets), read-only
  registry keys (`OpenSubKey(..., $false)`), `Resolve-DnsName` and SYSVOL file reads.
- `tests/ReadOnly.Tests.ps1` parses every module file with the PowerShell AST and fails on state-changing verbs
  (`Set-`, `New-`, `Remove-`, `Add-`, `Enable-`, `Disable-`, `Grant-`, `Revoke-`, `Update-`, ...), any non-GET
  `-Method` or `Method = ...` value, `Invoke-RestMethod`/`Invoke-WebRequest`/`Invoke-Expression`, write APIs
  (`WriteAllText`, `SetValue`, `CreateSubKey`, `Delete`, ...), writable registry opens and unknown dynamic
  invocations. File-system writes are allowed only in `core/Output.ps1` (package writing).
- Before each envelope is written, `core/SecretScan.ps1` (a mirror of `packages/core/src/sensitive.ts`, kept in
  sync by `tests/SecretScan.Tests.ps1`) scans it; on any finding the dataset is written as `Failed` with
  `SENSITIVE_CONTENT_BLOCKED` and `data: null`. The manifest and log are scanned as well.
- Logs (`logs/collection-log.json`) contain timestamps, module, dataset, level and messages only - never response
  bodies, tokens or evidence values; messages are passed through a token/secret redactor.
- Credentials are never requested, stored or written; sign-in uses the Microsoft modules' interactive flows.

## Offline replay

`-ReplayPath <dir>` makes the wrappers read recorded, sanitized responses instead of calling services. The
transformation code is identical in both modes; only the wrappers differ.

```powershell
Invoke-AdminSecOpsCollection -Module All -ReplayPath ./collectors/powershell/tests/replay/contoso -OutputPath $env:TEMP -SkipConnect
```

Replay folder layout:

| Folder | Content | File name |
| --- | --- | --- |
| `graph/` | Raw Graph JSON (`value` / `@odata.nextLink`) | replay key of the request URL, e.g. `v1.0_policies_authorizationPolicy.json` |
| `arm/` | Raw ARM JSON (`value` / `nextLink`) | replay key of the path without `api-version`, e.g. `subscriptions.json` |
| `exo/` | Cmdlet output as JSON objects with the real property names | `<Cmdlet>.json` |
| `ad/` | AD cmdlet output; `remote-registry.json` for DC settings | explicit replay key, e.g. `Get-ADUser_<domain>_securityRelevant.json` |
| `gpo/` | `Get-GPO_<domain>.json`, `Get-GPOReport_<domain>_<guid>.xml`, `sysvol/<domain>/Policies/...` | |
| `windows/` | CIM/cmdlet output and `registry.json` (`"HKLM\\<key>\\<value>": data`) | |
| `dns/` | `{"records": [...]}` or `{"status": "NotFound"}` | replay key of the DNS name |

Replay keys: the scheme/host is removed, `api-version` is dropped, other unsafe characters become `_`, and keys
longer than 120 characters are shortened with a SHA-256 suffix (see `Get-AsoReplayKey` in `core/DataAccess.ps1`).
A file containing `{"__replayError": {"statusCode": 403, "errorCode": "...", "message": "..."}}` raises the same
error the live wrapper raises, so permission and licence cases can be replayed.

The Contoso scenario (`tests/replay/contoso`) is entirely fictional (tenant `contoso.example`, forest
`corp.contoso.example`, GUIDs of the form `aaaa0001-...`, documentation IP ranges `192.0.2.0/24` and
`198.51.100.0/24`, a generated public-only CA certificate). Well-known Microsoft constants (built-in role template
IDs, Microsoft Graph / Exchange Online app IDs, default GPO GUIDs) are used where controls depend on them. It
covers every dataset and deliberately includes: multi-page Graph responses (Conditional Access, service
principals), a 403 (`entra.onPremisesSynchronization` -> `Unauthorized`), licence-missing cases
(PIM datasets and `exchange.atpPolicy` -> `NotApplicable`), a per-subscription 403 (`azure.keyVaults` ->
`Partial`), `NotCollected` (`ad.domainControllerSettings`), and raw secrets that must be dropped
(`passwordCredentials.hint`, `BannedPasswordList`, security contact e-mails, a GPO `DefaultPassword` registry value
and a fake GPP `cpassword`). These fictional values exist only in the raw replay input, never in evidence.

## Tests

```powershell
pwsh -NoProfile -File scripts/Invoke-PesterTests.ps1        # all Pester tests (exit code != 0 on failure)
pwsh -NoProfile -File scripts/Invoke-PSScriptAnalyzer.ps1   # Error + Warning rules, PSScriptAnalyzerSettings.psd1
npx vitest run tests/collector-contract.test.ts             # cross-language contract (skipped without pwsh)
```

| Test file | Covers |
| --- | --- |
| `tests/Core.Tests.ps1` | FILETIME and timestamp conversion, array serialisation, envelope/manifest writer, SHA-256, UTF-8 without BOM, ZIP entry names, status mapping, replay keys, value normalisation |
| `tests/SecretScan.Tests.ps1` | Parity with `sensitive.ts`; blocks `hint`, `secretText`, `cpassword`, JWT, LAPS attributes, keys; refuses secret AD attributes and non-allow-listed cmdlets |
| `tests/ReadOnly.Tests.ps1` | AST static analysis of every module file, plus negative tests proving the analyzer detects violations |
| `tests/Catalog.Tests.ps1` | Catalogue equals the TypeScript dataset registry (IDs and modules); permission and prerequisite commands |
| `tests/Replay.Tests.ps1` | End-to-end replay of the Contoso scenario: package, hashes, statuses, every module's transformations, failure isolation, paging failure -> `Partial`, licence fallbacks, options |
| `tests/LiveWrappers.Tests.ps1` | Live wrapper code paths with mocked `Invoke-MgGraphRequest` / `Invoke-AzRestMethod` / EXO cmdlet: GET-only, paging, 429 retry, 403 mapping; live local `windows.hosts` run on Windows |
| `tests/collector-contract.test.ts` (repo root) | Runs the replay, loads the ZIP with `readZipPackage` + `loadEvidenceBundle`, checks integrity, no sensitive content, every dataset present and schema-valid, then `runAssessment` with `CONTROL_LIBRARY` without `ERROR` |

## Validation status and limitations

Verified **only by replay and mocks** (not against a live service): every Entra, M365, Exchange, Intune, Azure,
AD, ADCS and GPO dataset, sign-in (`Connect-AsoService`), Graph/ARM error parsing of real exception objects,
throttling behaviour, and `-IncludeDomainControllerSettings` remote registry reads. The replay responses were
written from Microsoft's documented API/cmdlet shapes; real tenants can differ. Known points to validate on first
live use:

- Graph error objects: status codes are read from `Exception.Response.StatusCode` or the exception message, and
  error codes from `ErrorDetails` JSON. Licence detection by error text is heuristic; unmatched licence errors are
  reported as `Unauthorized`/`Failed` rather than `NotApplicable`.
- PIM licence detection uses the service plans `AAD_PREMIUM_P2` / Entra ID Governance plan names; tenants
  licensed through other SKUs may need the error-text fallback.
- `exchange.smtpAuthMailboxes`: `Get-EXOCASMailbox` does not return a UPN, so `userPrincipalName` holds the
  primary SMTP address (a warning says so). Enumerating all CAS mailboxes can be slow in large tenants.
- `azure.roleAssignments` uses ARM REST plus Graph `directoryObjects/{id}` (at most 500 principals are resolved)
  instead of `Get-AzRoleAssignment`, to keep one code path for live and replay. Inherited management-group and root
  assignments returned by the subscription listing are included.
- `ad.users` counts users with one `Get-ADUser -Filter *` per domain (memory-heavy in very large domains).
- GPO XML parsing covers Security settings (Account, SecurityOptions, UserRightsAssignment, Audit), Advanced Audit,
  Administrative Templates (`Policy`) and `RegistrySetting`; other extensions (Preferences, scripts, restricted
  groups, services) are not flattened. `wmiFilter` is the filter name as exposed by `Get-GPO`.
- `windows.hosts` covers only the computer running the collector (no remoting). Not elevated, some values may be
  `null` (with warnings). Executed live on a non-elevated Windows 11 machine during development.
- DNS lookups use the resolver of the collecting computer; `Resolve-DnsName` exists only on Windows (other
  platforms report `lookupStatus: Error`).
- Licence detection needs Microsoft Graph. When only Exchange or Azure is collected without a Graph session,
  licence-dependent datasets rely on service errors.

## Layout

```
AdminSecOps.Collector.psd1 / .psm1   module manifest (0.1.0, PowerShell 7.2) and loader
PSScriptAnalyzerSettings.psd1        analyzer policy (justifications inside)
core/Catalog.ps1                     dataset catalogue (id, module, operations, permissions, collector function)
core/Collection.ps1                  Invoke-AdminSecOpsCollection, module/dataset orchestration, Get-AdminSecOpsPermission
core/Connect.ps1                     interactive read-only sign-in, connection state
core/Context.ps1                     run context, conversions (timestamps, FILETIME), status mapping, licence detection
core/DataAccess.ps1                  read-only wrappers, replay, value normalisation
core/Json.ps1, Log.ps1, SecretScan.ps1, Prerequisites.ps1, Output.ps1 (the only writer: envelopes, manifest, log, ZIP)
entra/ m365/ exchange/ intune/ azure/ ad/ adcs/ gpo/ windows/   one file per module, one function per dataset
tests/                               Pester tests, static analyzer, replay/contoso scenario
```
