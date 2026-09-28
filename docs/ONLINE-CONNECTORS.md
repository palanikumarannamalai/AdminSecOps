# Online connectors

The hosted control plane (`apps/control-plane`, hosted collector **0.3.0**) reads evidence
server-side, read-only, with the signed-in administrator's **delegated** authority. It never
uses application (app-only) permissions, never changes tenant, Azure or Exchange settings,
and never assigns roles. Customers use only the browser: there is nothing to download or run.

Every source that cannot be read produces datasets with an explicit status and code. The
Coverage page turns those into **Not connected**, **Consent or permission required**,
**Unsupported online**, **Collection failed** or **Not licensed**. None of these ever counts
as passing, and the overview reports coverage, not a security score.

| Connector | State in this release | Default | What it covers |
|---|---|---|---|
| Microsoft Graph (existing sign-in) | Implemented | On | Entra ID (all 17 datasets), SharePoint/OneDrive, Teams settings, Intune |
| Public DNS | Implemented | On | SPF and DMARC records (`exchange.mailDnsRecords`) |
| Azure Resource Manager | Implemented, separate consent and token | **Off** until `ONLINE_CONNECTORS` contains `azure` | 8 Azure datasets, 12 Azure controls |
| Exchange Online | Implemented (fixed server-side PowerShell runner); available for explicit connection | Requires separate sign-in and management-scoped consent; live validation pending | 10 Exchange / Defender for Office 365 datasets |
| On-premises (AD, AD CS, GPO, Windows) | **Design only**, not implemented | Not available | 42 controls stay not assessed online |

The test deployment was activated on 2026-09-24 after explicit approval of the three delegated permissions. Hosted health, sign-in configuration, protected routes and the Exchange runtime probe passed; live tenant collection still requires interactive connection and validation. See `docs/validation/2026-09-24-connector-deployment.md`. On 2026-09-26 the Exchange connector was switched off in the hosted service (`ONLINE_CONNECTORS=azure`); the Exchange section below explains why.

No live tenant has been tested with this release. Connector behaviour is covered by synthetic tests
(see `docs/validation/2026-09-22-missing-connectors.md`).

> **Test release.** No live tenant has been validated in this release — connect an authorised
> test tenant, not production.

## Scopes requested by the enabled connectors

These are the only delegated scopes the hosted service requests today. No connector uses
application (app-only) permissions.

| Connector | Scopes requested | Read-only? |
|---|---|---|
| Microsoft Graph (sign-in) | `openid profile offline_access` plus `GRAPH_SCOPES`. The hosted service requests `AuditLog.Read.All Directory.Read.All Organization.Read.All Policy.Read.All RoleManagement.Read.Directory User.Read.All UserAuthenticationMethod.Read.All SharePointTenantSettings.Read.All TeamworkAppSettings.Read.All Team.ReadBasic.All DeviceManagementConfiguration.Read.All DeviceManagementManagedDevices.Read.All OnPremDirectorySynchronization.Read.All` | Yes. `loadConfig` refuses to start if `GRAPH_SCOPES` contains anything outside `READ_ONLY_GRAPH_SCOPES` (`apps/control-plane/src/config.ts`) |
| Azure Resource Manager | `https://management.azure.com/user_impersonation openid profile offline_access` | The scope itself is not read-only: it lets the app call ARM with the signed-in user's Azure RBAC. Read-only access comes from the role you assign — use **Reader**. ConfigReview sends only the fixed GET operations listed below, enforced by `validateArmUrl` |
| Public DNS | None (no Microsoft token) | Yes; public DNS queries only |
| Exchange Online | Separate optional Exchange.Manage consent | Reader access recommended |

The connector switch is server configuration, not a user setting: `ONLINE_CONNECTORS` is read
once at startup (`config.ts`), and `/auth/connect/{connector}` (`server.ts`), the connector view
and job preparation (`connectors.ts`) all refuse a connector that is not listed. A signed-in
user cannot enable one.

## Permission and runtime matrix

### Microsoft Graph (delegated, existing sign-in)

One scope is new: `OnPremDirectorySynchronization.Read.All`. The other new Entra datasets use
scopes that are already granted, because Microsoft lists them as sufficient (higher-privileged,
read-only) for those requests. The collector records the substitute in
`HOSTED_PERMISSION_OVERRIDES` (`apps/control-plane/src/collector/runtime.ts`), so consent
messages name the scope actually used.

| Dataset | Request (GET) | Delegated permission used | Role / licence |
|---|---|---|---|
| entra.roleAssignmentScheduleInstances | `/v1.0/roleManagement/directory/roleAssignmentScheduleInstances` | RoleManagement.Read.Directory (already granted) | Global Reader, Security Reader, Security Administrator or Privileged Role Administrator. Needs Entra ID P2 or ID Governance; without it the dataset is NotApplicable and no request is sent |
| entra.roleEligibilitySchedules | `/v1.0/roleManagement/directory/roleEligibilitySchedules` | RoleManagement.Read.Directory (already granted) | As above |
| entra.applications | `/v1.0/applications?$select=…,passwordCredentials,keyCredentials&$top=999` | Directory.Read.All (already granted) | Global Reader and other directory readers. Only credential metadata is kept; `hint`, `secretText` and `key` are never copied |
| entra.servicePrincipals | `/v1.0/servicePrincipals?$select=…` (default page size 100) | Directory.Read.All (already granted) | As above |
| entra.apiPermissionGrants | `/v1.0/servicePrincipals(appId='…')?$select=…`, `/v1.0/servicePrincipals/{id}/appRoleAssignedTo` | Directory.Read.All (already granted) | Microsoft Graph and Exchange Online resource principals. A resource principal that does not exist is noted, not failed |
| entra.onPremisesSynchronization | `/v1.0/directory/onPremisesSynchronization` | **OnPremDirectorySynchronization.Read.All (new)** | Microsoft documents **Global Administrator** as the only supported role. Other sign-in roles get 403, which is reported Unauthorized. `passThroughAuthenticationEnabled` is not a property of this resource and stays null |
| intune.settings | `/v1.0/deviceManagement?$select=settings`, then `/v1.0/deviceManagement`, then **one beta exception** `/beta/deviceManagement/settings` | DeviceManagementConfiguration.Read.All (already granted) | Intune licence. See "Intune settings" below |

The full `GRAPH_SCOPES` value is:

```text
User.Read Organization.Read.All Policy.Read.All RoleManagement.Read.Directory Directory.Read.All User.Read.All AuditLog.Read.All UserAuthenticationMethod.Read.All OnPremDirectorySynchronization.Read.All SharePointTenantSettings.Read.All TeamworkAppSettings.Read.All Team.ReadBasic.All DeviceManagementConfiguration.Read.All DeviceManagementManagedDevices.Read.All
```

#### Intune settings (`intune.settings`)

`deviceManagementSettings` (`secureByDefault`, `deviceComplianceCheckinThresholdDays`,
`isScheduledActionEnabled`) is a documented property of the `deviceManagement` singleton in
v1.0 and beta. The v1.0 "Get deviceManagement" pages have been withdrawn from Microsoft's
documentation, and a live v1.0 response omitted `settings` with and without `$select`. So the
collector:

1. tries v1.0 with `$select=settings`, then v1.0 without `$select`;
2. only if both omit it, reads the beta **property path** `/beta/deviceManagement/settings`
   once. It records warning `GRAPH_BETA_SOURCE`, because beta APIs can change.

Beta access is one exact path in `GRAPH_BETA_EXCEPTIONS` (`graph-client.ts`). It allows no query
string and is never used as a nextLink; every other beta URL is still rejected. A missing
`secureByDefault` is never defaulted: the dataset fails validation and INTUNE-CMP-001 is
NOT_ASSESSED. The Intune portal default for "Mark devices with no compliance policy assigned
as" is *Compliant*, which is the insecure setting, so a default would be wrong. A 403 is
Unauthorized. An empty beta response is reported as a service response gap, not as missing
consent. Existing evidence is unchanged: the dataset schema and its fields are the same.

### Azure Resource Manager (separate delegated token)

| Item | Value |
|---|---|
| App registration permission | Azure Service Management → Delegated → `user_impersonation`. This lets the app call ARM as the user; it grants no Azure access by itself |
| Scope requested at "Connect Azure" | `https://management.azure.com/user_impersonation openid profile offline_access` (one resource per token) |
| Accepted token audiences | `https://management.azure.com[/]`, `https://management.core.windows.net[/]` |
| Azure role | **Reader** (or any role with `*/read`) on each subscription to assess. Reader covers every operation below |

| Dataset | ARM operation (GET) | api-version |
|---|---|---|
| azure.subscriptions | `/subscriptions` | 2022-12-01 |
| azure.roleAssignments | `/subscriptions/{id}/providers/Microsoft.Authorization/roleAssignments`, `…/roleDefinitions`; principal names through Graph `/directoryObjects/{id}` with the **Graph** token | 2022-04-01 |
| azure.defenderPlans | `/subscriptions/{id}/providers/Microsoft.Security/pricings` | 2024-01-01 |
| azure.securityContacts | `/subscriptions/{id}/providers/Microsoft.Security/securityContacts` (addresses are counted, never stored) | 2023-12-01-preview (Microsoft publishes no GA version) |
| azure.storageAccounts | `/subscriptions/{id}/providers/Microsoft.Storage/storageAccounts` | 2023-05-01 |
| azure.keyVaults | `/subscriptions/{id}/providers/Microsoft.KeyVault/vaults` | 2023-07-01 |
| azure.networkSecurityGroups | `/subscriptions/{id}/providers/Microsoft.Network/networkSecurityGroups` | 2023-09-01 |
| azure.activityLogDiagnostics | `/subscriptions/{id}/providers/Microsoft.Insights/diagnosticSettings` | 2021-05-01-preview (the only documented version) |

The api-versions are the ones already used by the PowerShell collector and the dataset
definitions. Newer GA versions exist for storage, Key Vault and network. Moving to them is a
separate change that needs updated fixtures.

Safety properties (`arm-client.ts`, `azure.ts`):

- **Token separation.** The ARM token is stored and sealed separately from the Graph token.
  It is sent only to URLs `validateArmUrl` accepts: `https://management.azure.com`, exactly
  the operations above, the matching api-version, and only `api-version`/`$skiptoken` query
  parameters. The Graph token goes only to Graph.
  - A token that is identical to the Graph token is refused.
  - Before a token is stored and before each use, its claims must name ARM as audience, the
    session tenant (`tid`), the session user (`oid`) and the delegated `user_impersonation`
    scope.
- **Tenant binding.** Only subscriptions whose `tenantId` is the verified session tenant are
  read. Subscriptions of other tenants (for example Azure Lighthouse or guest access) are
  excluded and counted. Subscriptions without a tenant ID are excluded and make the list
  Partial.
- **nextLink.** A nextLink must keep the first page's exact path (same subscription and
  operation) and api-version. Anything else is not followed and the dataset is Partial.
- **Missing rights are never a pass.**
  - No visible subscription: `NO_ACCESSIBLE_SUBSCRIPTIONS`.
  - 403 in every subscription: `READER_REQUIRED`.
  - A refused subscription list: `SUBSCRIPTIONS_UNAUTHORIZED`.

  All three are Unauthorized, so the controls are NOT_ASSESSED. A 403 in some subscriptions
  makes the dataset Partial.
- **Visibility caveat.** Subscriptions the account cannot see are not assessed. Every Azure
  dataset carries warning `SUBSCRIPTION_VISIBILITY`.
- **Bounds.** Azure shares the collection's time, size, page and retry budget with Graph. At
  most `maxFanoutRequests` subscriptions are read (FANOUT_LIMIT → Partial). Cancellation
  stops the collection.

### Exchange Online (fixed server-side runner)

> **Optional hosted connection, enabled 28 September 2026.** The runtime probe passed with
> PowerShell 7.6.4 and ExchangeOnlineManagement 3.10.1. A user must explicitly connect
> Exchange and review its separate management-scoped permission (`Exchange.Manage`).
> The token can carry the signed-in account's write authority; ConfigReview only executes
> fixed read operations. A completed live Palani Lab assessment is still required.
> SPF and DMARC run independently from public DNS.

Delegated Microsoft Graph cannot read these settings: `/admin/exchange` exposes only
mailboxes and message trace. The alternatives were reviewed against current Microsoft
documentation:

| Option | Why it is not used |
|---|---|
| Exchange Online Admin API (REST, `Exchange.ManageV2`) | Preview. It covers only OrganizationConfig (reduced to MailTips properties) and AcceptedDomain; transport, DKIM, anti-spam, remote domains, CAS mailbox and ATP settings are missing |
| Graph Tenant Configuration Management | Exchange extraction is app-only through Microsoft's service principal. Delegated Exchange is not supported, and creating a snapshot needs `ConfigurationMonitoring.ReadWrite.All` (a write permission) |
| App-only `Exchange.ManageAsApp` + certificate | Persistent privileged access in every customer tenant, which is outside the delegated session model. Not used |

The implemented path is Microsoft's supported ExchangeOnlineManagement V3 module with a
delegated access token: `Connect-ExchangeOnline -AccessToken … -UserPrincipalName …`.

| Item | Value |
|---|---|
| App registration permission | Office 365 Exchange Online (`00000002-0000-0ff1-ce00-000000000000`) → Delegated → `Exchange.Manage` |
| Scope requested at "Connect Exchange Online" | `https://outlook.office.com/Exchange.Manage openid profile offline_access` |
| Exchange role | Global Reader or View-Only Organization Management (recommended). Security Reader alone does not cover every cmdlet |
| Server runtime | PowerShell **7.6** or later, ExchangeOnlineManagement **3.10.1** (pinned), absolute path in `EXCHANGE_PWSH_PATH` |
| Cmdlets (fixed) | Get-OrganizationConfig, Get-TransportConfig, Get-AdminAuditLogConfig, Get-AcceptedDomain, Get-DkimSigningConfig, Get-HostedOutboundSpamFilterPolicy, Get-RemoteDomain, Get-EXOMailbox (forwarding filter only), Get-EXOCASMailbox (SMTP AUTH overrides only), Get-AtpPolicyForO365 |

> **Boundary: owner decision required.** `Exchange.Manage` is **not a read-only permission**.
> Microsoft documents no read-only delegated Exchange permission. The token carries the
> signed-in user's whole Exchange RBAC; for an Exchange or Global Administrator that includes
> write. ConfigReview limits what it does, not what the token could do:
>
> - It runs one repository-owned script with a fixed table of `Get-*` cmdlets.
>   `Connect-ExchangeOnline -CommandName` loads only those cmdlets. That is a load filter, not
>   a security boundary.
> - There is no endpoint or parameter that accepts a command.
> - The token lives only in the encrypted session or job, and only for the session's
>   one-hour authorization.
>
> Delegated use of a third-party app token with `-AccessToken -UserPrincipalName` is
> documented only implicitly by Microsoft. It **must be verified live** before customers use
> it. The connector therefore stays **disabled** until the owner explicitly approves adding
> `Exchange.Manage` and the runtime is installed.

Runner safety properties (`exchange-runner.ts`,
`runtime/exchange/Invoke-AsoExchangeCollection.ps1`):

- **Fixed process.** `spawn` runs without a shell, with fixed arguments, and uses an absolute
  PowerShell path from configuration.
- **Token on stdin only.** The request (token, UPN, tenant, limits) goes to standard input and
  the script validates it again. The token is never on the command line.
- **Minimal environment.** The child gets only PATH, HOME, TMP and PSModulePath. The client
  secret, database URL and encryption key are not inherited.
- **Bounded run.** 5-minute timeout (killed), 32 MB output cap, and cancellation kills the
  process.
- **No error text.** Standard error is discarded; only fixed status codes are returned.
- **Strict result.** The result must match a strict shape: known operations, primitive values,
  at most 50 properties and 100,000 items.
- **Tenant check.** The connected tenant (`Get-ConnectionInformation`) must equal the verified
  tenant. Otherwise all Exchange data is discarded (`EXCHANGE_TENANT_NOT_VERIFIED`).
- **Bounded lists.** Lists are capped at 5,000 objects and 20,000 CAS mailboxes scanned.
  Hitting a cap makes the dataset Partial.

### Public DNS (`exchange.mailDnsRecords`)

- **Resolver.** Uses the host's recursive resolver (`node:dns`): 3-second timeout, 2 tries,
  at most 50 domains, and valid host names only.
- **Domain list.** The authoritative accepted domains from Exchange Online when that connector
  ran. Otherwise the tenant's **verified domains with the Email capability**, with warning
  `DOMAINS_FROM_VERIFIED_DOMAINS`. `*.onmicrosoft.com` is excluded.
- **Provenance.** Every dataset carries warning `DNS_PROVENANCE`: answers are not from
  authoritative servers and are not DNSSEC-validated. DNS never establishes accepted domains
  or DKIM signing state, so M365-MAIL-001 (DKIM) needs the Exchange connector. M365-MAIL-002
  (SPF) and M365-MAIL-003 (DMARC) run from DNS.
- **Failures.** A failed lookup is not a pass: the domain is NOT_ASSESSED. If every lookup
  fails, the dataset fails.

## Consent, sessions and tokens

- **Separate consent per connector.** The existing sign-in (`/auth/login`, Graph only) is
  unchanged. Each connector has its own sign-in at `/auth/connect/{azure|exchange}` and
  re-consent at `?consent=true`.
- **Bound to the session.** A connector sign-in:
  - always uses the **session tenant's** authority, never `organizations`/`common`;
  - uses PKCE, state and nonce;
  - requires a verified ID token for the **same user** as the session, with the same
    directory-role gate;
  - must return an access token whose claims match the connector.
  The callback attaches the token only to the session that started it.
- **Separate, bound encryption.** Connector tokens are sealed with AES-256-GCM, separately
  from the Graph token. The additional authenticated data binds each blob to
  connector + tenant + user, so it cannot be swapped between users, tenants or resources.
  They are stored in `encrypted_connectors` on the session and the job, and cleared when the
  job completes, fails or expires.
- **Refresh.** The server refreshes connector tokens at the session tenant's token endpoint.
  Refreshed tokens are checked again.
  - An expired or unrefreshable connector is recorded for the job as `expired`.
  - A missing consent (`AADSTS65001`) is recorded as `consent-required`.
  - Either way the assessment still runs, and those controls are NOT_ASSESSED.
- **One-hour authorization.** The one-hour administrator authorization of the Graph sign-in
  gates connector sign-in and every job. Signing in again as the same user in the same
  tenant keeps the connectors; anyone else starts without them. **Disconnect** removes a
  connector from the session.

## Deployment instructions (for the deployer)

Do these in order. Nothing here grants application permissions or changes customer tenants.

1. **Database (owner role, once).** The startup migration alters a table only when the column
   is missing, so the restricted runtime role does not need ALTER rights once this has been
   applied:

   ```sql
   ALTER TABLE aso_sessions ADD COLUMN IF NOT EXISTS encrypted_connectors text;
   ALTER TABLE aso_jobs ADD COLUMN IF NOT EXISTS encrypted_connectors text;
   ```

2. **Package.** Build as before (`infra/azure/ONLINE-TEST.md`). Also include
   `apps/control-plane/runtime/exchange/Invoke-AsoExchangeCollection.ps1` at the same relative
   path: the server resolves it as `../../runtime/exchange/` from `dist/collector/`.
3. **Graph scope.** Add Microsoft Graph delegated `OnPremDirectorySynchronization.Read.All`
   to the app registration and to `GRAPH_SCOPES`, using the value above.
4. **Azure connector** (needs the owner's approval to add the permission):
   - add Azure Service Management → Delegated → `user_impersonation` to the app
     registration;
   - set `ONLINE_CONNECTORS=azure`.

   The redirect URI is unchanged (`/auth/callback`).
5. **Exchange connector.** Only after an explicit owner decision about `Exchange.Manage` (see
   the boundary above):
   - Add Office 365 Exchange Online → Delegated → `Exchange.Manage`.
   - Install the runtime on the host. App Service Linux (Node) images do not include
     PowerShell.
     1. Download the official PowerShell 7.6.x `linux-x64` archive from
        `https://github.com/PowerShell/PowerShell/releases`.
     2. Verify its SHA-256 against the value published on the release page.
     3. Extract it to `/home/site/tools/powershell/7.6`, which persists across restarts.
     4. Run `/home/site/tools/powershell/7.6/pwsh -NoProfile -Command "Save-Module ExchangeOnlineManagement -RequiredVersion 3.10.1 -Repository PSGallery -Path /home/site/tools/psmodules"`.
   - Set these app settings:
     - `EXCHANGE_PWSH_PATH=/home/site/tools/powershell/7.6/pwsh`
     - `EXCHANGE_MODULE_PATH=/home/site/tools/psmodules`
     - `ONLINE_CONNECTORS=azure exchange`
   - Check that `/api/me` reports the Exchange connector as `not-connected`, not
     `runtime-unavailable`.

   Caveat: Microsoft lists Ubuntu LTS for this module, and the App Service Node image is
   Debian-based. If the runtime check or a live collection fails, use a custom container
   based on an Ubuntu 24.04 PowerShell image on the same plan. That is a packaging change
   for the owner to approve.
6. **Verify:**
   - `/api/health` returns 200 and unauthenticated `/api/me` returns 401.
   - `/auth/connect/azure` without a session returns 401.
   - With a session, `/auth/connect/azure` redirects to
     `login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` with only the ARM scope.
   - Coverage shows "not connected" until a customer connects.

## Customer activation

> **Confirm the publisher before you grant consent.** Microsoft's consent screen shows the
> app name and publisher. For the hosted service the app is **ConfigReview by Palanikumar Annamalai** and the
> publisher is shown as **unverified**: the registration has no Microsoft verified publisher
> yet. Before granting, check that you started sign-in from `configreview.apps.palanikumar.net`, that the
> app name matches, and that the permissions listed are the ones in this guide. If anything
> differs, stop and do not grant consent.

Customers do this in the browser only:

1. A tenant administrator re-consents: **Reconnect and review Microsoft consent** on the home
   page. This covers the new Graph scope.
2. **Connect Azure Resource Manager** on the home page.
   - If the tenant restricts user consent, an administrator consents to Azure Service
     Management `user_impersonation`.
   - Give the signing-in account **Reader** on the subscriptions to assess. ConfigReview does
     not assign it.
3. **Connect Exchange Online** is not offered by the hosted service. A self-hosted deployment
   that enables it needs an administrator to consent to `Exchange.Manage`; sign in with Global
   Reader or View-Only Organization Management.
4. Run an assessment and open **Coverage** to see what was assessed.

## On-premises connector (design only; not implemented)

The online service cannot reach Active Directory, AD CS, Group Policy or Windows hosts in
private networks, and it must not: no inbound customer ports, no browser access to internal
systems, no remote execution. The 42 on-premises controls therefore stay **Unsupported
online**. This is the proposed secure design. Nothing below exists yet.

- **Agent.** A signed ConfigReview on-premises agent: a Windows service built from this
  repository's PowerShell collectors, compiled and code-signed. The customer installs it on
  a domain-joined server. It runs as a dedicated **gMSA** that is a normal domain user with
  read access. It is not a Domain Admin; it gets only the read rights the AD, AD CS and GPO
  collectors document.
- **Outbound only.** The agent polls `https://<service>/agent/v1/...` over TLS 1.2+. It opens
  no listening port and needs no inbound firewall rule or VPN.
- **Explicit enrollment per tenant.** A tenant administrator creates a one-time enrollment
  code in the web UI (role-gated, 15-minute expiry, single use). The agent sends it with a
  locally generated key pair (TPM or DPAPI-protected). The service binds the agent's public
  key to that tenant and records who enrolled it. Administrators can revoke it at any time.
- **No arbitrary execution.** The service can only request a **collection run** by
  `datasetId` from the fixed catalogue compiled into the signed agent. It can never send
  code, commands, script blocks or parameters beyond dataset IDs and limits. The agent
  rejects anything else.
- **Signed, validated evidence.** The agent builds the standard evidence package (manifest
  with SHA-256 per file, as the PowerShell collector already does) and signs the manifest
  with its enrolled key. The service accepts a package only if:
  - the signature matches the agent enrolled for **that tenant**;
  - the assessment ID and nonce match an outstanding request;
  - it passes the existing schema, sensitive-content and size checks.
  Replays and packages from another tenant's agent are rejected.
- **Least data, bounded.** The same allow-listed fields as the PowerShell collector. There
  are size and time limits, and the evidence is processed in memory like online evidence.
- **Honest status.** An agent that is offline, unenrolled, outdated or failing produces
  datasets marked not connected or failed, never passing.

**Decision needed from the owner before implementation.** Shipping an installed agent is the
only safe way to cover on-premises controls. It conflicts with the "no manual scripts"
preference in one way: a customer administrator must install a signed service once on a
domain-joined server. The owner needs to decide:

1. whether this installation step is acceptable;
2. who owns code signing (certificate and build pipeline);
3. whether the hosted service may expose the outbound-only agent API.

Until then the web UI shows on-premises sources as **Not supported online**, with no install
link.

## Sources (official documentation, checked 2026-09-22)

- Graph: [roleAssignmentScheduleInstances](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignmentscheduleinstances?view=graph-rest-1.0), [roleEligibilitySchedules](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleeligibilityschedules?view=graph-rest-1.0), [list applications](https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0), [list servicePrincipals](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0), [appRoleAssignedTo](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignedto?view=graph-rest-1.0), [onPremisesDirectorySynchronization](https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-get?view=graph-rest-1.0), [deviceManagementSettings (v1.0)](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-devicemanagementsettings?view=graph-rest-1.0), [deviceManagementSettings (beta)](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-devicemanagementsettings?view=graph-rest-beta), [Intune compliance settings](https://learn.microsoft.com/en-us/intune/device-security/compliance/overview), [exchangeAdmin](https://learn.microsoft.com/en-us/graph/api/resources/exchangeadmin?view=graph-rest-1.0).
- Identity platform: [authorization code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow), [scopes](https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc).
- ARM: [Subscriptions - List](https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list?view=rest-resources-2022-12-01), [Role Assignments](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-subscription?view=rest-authorization-2022-04-01), [Pricings](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/pricings/list), [Security Contacts](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/security-contacts/list), [Storage Accounts](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/list?view=rest-storagerp-2023-05-01), [Vaults](https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/list-by-subscription), [NSGs](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-security-groups/list-all), [Subscription diagnostic settings](https://learn.microsoft.com/en-us/rest/api/monitor/subscription-diagnostic-settings/list?view=rest-monitor-2021-05-01-preview), [Reader role](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/general), [throttling](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/request-limits-and-throttling), [Lighthouse](https://learn.microsoft.com/en-us/azure/lighthouse/concepts/cross-tenant-management-experience).
- Exchange: [Exchange Online PowerShell module](https://learn.microsoft.com/powershell/exchange/exchange-online-powershell-v2), [Connect-ExchangeOnline](https://learn.microsoft.com/powershell/module/exchangepowershell/connect-exchangeonline), [app-only authentication](https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2), [Get-AdminAuditLogConfig](https://learn.microsoft.com/powershell/module/exchangepowershell/get-adminauditlogconfig), [Exchange Online permissions](https://learn.microsoft.com/exchange/permissions-exo/permissions-exo), [Admin API overview](https://learn.microsoft.com/exchange/reference/admin-api-overview), [Tenant Configuration Management](https://learn.microsoft.com/graph/api/resources/unified-tenant-configuration-management-api-overview?view=graph-rest-1.0), [TCM Exchange resources](https://learn.microsoft.com/graph/utcm-exchange-resources), [ExchangeOnlineManagement on PowerShell Gallery](https://www.powershellgallery.com/packages/ExchangeOnlineManagement).

## Hosted data retention

Assessment results are retained in the live database for 30 days and audit events for 90 days. Database backups may retain deleted records for up to seven additional days. Downloaded reports remain under your control. Raw collection evidence is processed in memory. The hosted backup retention setting was verified as seven days on 2026-09-27. This wording distinguishes live-database cleanup from expiry of backup copies; it does not change either setting.

