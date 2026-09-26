# Online workload assessments

The hosted control plane (`apps/control-plane`) collects evidence read-only through Microsoft
Graph **v1.0** with the signed-in administrator's delegated token. Hosted collector 0.2.0
covered Microsoft Entra ID, SharePoint and OneDrive, Microsoft Teams (the settings delegated
Graph exposes) and Microsoft Intune.

> **Hosted collector 0.3.0 adds more sources.** See [ONLINE-CONNECTORS.md](ONLINE-CONNECTORS.md)
> for the current permission and runtime matrix. It adds:
>
> - the remaining six Entra datasets;
> - an Intune settings fallback through one exact Graph beta path;
> - public SPF/DMARC DNS checks;
> - a separately consented Azure Resource Manager connector;
> - an Exchange Online connector that is disabled until the owner approves it.
>
> Where this page and ONLINE-CONNECTORS.md disagree, ONLINE-CONNECTORS.md is current.

The engine and control library are the same as for the PowerShell collector. A dataset that
is missing, denied, unlicensed, partial or invalid never produces a PASS (see
[CONTROL-MODEL.md](CONTROL-MODEL.md)). Each assessment has a **Coverage** page that shows,
for each workload:

- the datasets collected;
- how many catalogue controls were assessed or not assessed;
- the reason for each gap: missing permission or consent, no licence, failed collection,
  not collected, or not available to this collection method.

## Safety properties

- **GET only.** Every URL is checked against `https://graph.microsoft.com/v1.0/` before the
  request is sent. This includes each `@odata.nextLink`. Redirects are refused and beta
  URLs are never requested.
- **Tenant verified first.** `GET /organization` must return the tenant the session belongs
  to before any other customer data is requested. A mismatch or failure stops collection
  with no evidence.
- **One budget.** A single client enforces the time budget (10 minutes) and size budget
  (128 MB) for every workload. It also enforces per-response and page limits and a bounded
  429/503 retry.
- **Bounded per-resource requests.** At most 200 per dataset (`maxFanoutRequests`), for
  example one request per team or per policy. Hitting the cap, or any single request
  failing, makes the dataset **Partial**. An exhausted budget stops the remaining requests
  immediately. Cancellation stops collection and no bundle is produced.
- **Undeclared properties are dropped.** Missing values stay `null`, so the dataset schema
  rejects evidence rather than assuming a secure default. Secret-like content is discarded
  (Failed).
- **Directory settings are allow-listed.** Values outside the allow-list, such as custom
  blocked word lists, are dropped.

## Endpoint and permission matrix

All endpoints are Microsoft Graph v1.0, GET, delegated. Every permission listed is
read-only.

| Dataset | Endpoint(s) | Delegated permission | Role / licence notes |
|---|---|---|---|
| entra.organization | `/organization` | Organization.Read.All | Tenant verification |
| entra.subscribedSkus | `/subscribedSkus` | Organization.Read.All | Drives licence gating |
| entra.securityDefaults | `/policies/identitySecurityDefaultsEnforcementPolicy` | Policy.Read.All | |
| entra.authorizationPolicy | `/policies/authorizationPolicy` | Policy.Read.All | |
| entra.authenticationMethodsPolicy | `/policies/authenticationMethodsPolicy` (+ `/authenticationMethodConfigurations/{id}`) | Policy.Read.All | |
| entra.conditionalAccessPolicies | `/identity/conditionalAccess/policies` | Policy.Read.All | Entra ID P1 |
| entra.userRegistrationDetails | `/reports/authenticationMethods/userRegistrationDetails` | AuditLog.Read.All, UserAuthenticationMethod.Read.All | Entra ID P1/P2 |
| entra.roleDefinitions | `/roleManagement/directory/roleDefinitions` | RoleManagement.Read.Directory | |
| entra.roleAssignments | `/roleManagement/directory/roleAssignments?$expand=principal` | RoleManagement.Read.Directory, Directory.Read.All | |
| entra.guestUsers | `/users?$filter=userType eq 'Guest'` | User.Read.All, AuditLog.Read.All (signInActivity) | signInActivity needs P1/P2 |
| entra.groupSettings | `/groupSettings` | Directory.Read.All | Group.Unified guest settings for Microsoft 365 Groups / Teams |
| m365.sharePointSettings | `/admin/sharepoint/settings` | SharePointTenantSettings.Read.All | Global Reader or SharePoint Administrator |
| m365.teamsAppSettings | `/teamwork/teamsAppSettings` | TeamworkAppSettings.Read.All | Delegated only; Microsoft does not document the required role |
| m365.teamsTeamSettings | `/teams?$select=…`, `/teams/{id}?$select=…` | Team.ReadBasic.All | Per-team settings chosen by owners, not tenant policy. Teams that cannot be read make the dataset Partial |
| intune.settings | `/deviceManagement?$select=settings` (falls back to `/deviceManagement`) | DeviceManagementConfiguration.Read.All | Intune licence; Global Reader or an Intune read role |
| intune.deviceOverview | `/deviceManagement/managedDeviceOverview` | DeviceManagementManagedDevices.Read.All | Intune licence |
| intune.compliancePolicies | `/deviceManagement/deviceCompliancePolicies?$expand=assignments` (+ `/{id}/assignments` when not expanded) | DeviceManagementConfiguration.Read.All | Intune licence |

Sources:

- [sharepointSettings](https://learn.microsoft.com/en-us/graph/api/sharepointsettings-get?view=graph-rest-1.0)
- [teamsAppSettings](https://learn.microsoft.com/en-us/graph/api/teamsappsettings-get?view=graph-rest-1.0)
- [Get team](https://learn.microsoft.com/en-us/graph/api/team-get?view=graph-rest-1.0)
- [List teams](https://learn.microsoft.com/en-us/graph/api/teams-list?view=graph-rest-1.0)
- [deviceCompliancePolicy list](https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-list?view=graph-rest-1.0)
- [managedDeviceOverview](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddeviceoverview-get?view=graph-rest-1.0)
- [deviceManagementSettings](https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-devicemanagementsettings?view=graph-rest-1.0)
- [Intune role-based access control](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/role-based-access-control)
- [groupSettings](https://learn.microsoft.com/en-us/graph/api/group-list-settings?view=graph-rest-1.0)

The allow-list in `apps/control-plane/src/config.ts` (`READ_ONLY_GRAPH_SCOPES`) accepts only
these read-only scopes plus `User.Read`. A test checks that every scope the collector
derives from the dataset definitions is in that allow-list and contains no `Write`.

## Controls evaluated online

| Workload | Controls |
|---|---|
| SharePoint and OneDrive | M365-SPO-001 (Anyone links), M365-SPO-002 (legacy authentication), M365-SPO-003 (guest resharing, REVIEW when enabled), M365-SPO-004 (idle session sign-out, REVIEW when off) |
| Microsoft Teams | M365-TMS-001 (personal-scope resource-specific consent, REVIEW when enabled), M365-TMS-002 (guest channel management per team, REVIEW when allowed or unknown) |
| Intune | INTUNE-CMP-001, INTUNE-CMP-002, INTUNE-CMP-003, INTUNE-CA-001 (with Conditional Access) |
| Entra | Every Entra and hybrid control whose datasets are listed above |

Some collaboration settings are appropriate in one organization and not in another: guest
resharing, idle sign-out, resource-specific consent and guest channel management. They are
reported as **REVIEW** (an administrator decision) and never as a universal FAIL.

## Not available online, and why

- **Exchange Online and Defender for Office 365.** Delegated Graph still cannot read them:
  `/admin/exchange` exposes only mailboxes and message trace.
  - Hosted collector 0.3.0 reads them only through the separate Exchange Online connector.
    See [ONLINE-CONNECTORS.md](ONLINE-CONNECTORS.md); the connector is disabled until the
    owner approves it.
  - Without that connector, the Exchange datasets carry `CONNECTOR_NOT_CONNECTED` or
    `CONNECTOR_UNAVAILABLE` and their controls stay NOT_ASSESSED.
  - Licence, domain and tenant data is never used as a substitute.
- **Mail DNS records (SPF/DMARC).** Since 0.3.0 these are checked from public DNS. The domain
  list comes from the Exchange accepted domains, or else from verified domains with the Email
  capability. DNS never establishes DKIM or accepted domains.
- **Teams tenant-wide policies.** This covers meeting, messaging, external access
  (federation), client, guest meeting and app permission/setup policies. No v1.0 or beta
  delegated Graph resource returns them; Tenant Configuration Management is app-only.
  `/admin/teams/userConfigurations` returns policy *assignments*, not policy content, so
  it is not used.
- **Teams chat resource-specific consent and custom app settings.** These are beta-only
  (`isChatResourceSpecificConsentEnabled`, `customAppSettings`) and are not collected.
- **Intune Windows antivirus, firewall and TPM compliance requirements.** These are
  beta-only properties of `windows10CompliancePolicy` (`defenderEnabled`, `rtpEnabled`,
  `antivirusRequired`, `activeFirewallRequired`, `tpmRequired`). From v1.0 they are `null`.
- **Linux compliance** is configured in the settings catalog and is not evaluated.
- **Entra datasets.** Since 0.3.0 all of them are collected online. Directory
  synchronization settings need `OnPremDirectorySynchronization.Read.All`, and Microsoft
  supports this read only for the Global Administrator role; other roles are reported
  Unauthorized.
- **Azure** is collected through the separate Azure Resource Manager connector (0.3.0).
- **Active Directory, AD CS, Group Policy and Windows** remain outside the online collector.
  The outbound-only agent is designed, not implemented, in ONLINE-CONNECTORS.md.

## Consent and reconnecting

The deployment's `GRAPH_SCOPES` decides what the app requests at sign-in. The full online
set is:

```text
User.Read Organization.Read.All Policy.Read.All RoleManagement.Read.Directory Directory.Read.All User.Read.All AuditLog.Read.All UserAuthenticationMethod.Read.All OnPremDirectorySynchronization.Read.All SharePointTenantSettings.Read.All TeamworkAppSettings.Read.All Team.ReadBasic.All DeviceManagementConfiguration.Read.All DeviceManagementManagedDevices.Read.All
```

1. The app registration must list the same Microsoft Graph delegated permissions.
2. Most of these permissions require administrator consent. In each customer tenant, an
   administrator who can grant tenant-wide consent (for example Global Administrator or
   Privileged Role Administrator) must consent.
3. Existing sessions keep the scopes granted when they signed in. After new scopes are
   added:
   - the online home page lists the scopes Microsoft did not report as granted;
   - it offers **Reconnect and review Microsoft consent**, which is
     `/auth/login?consent=true`. That sign-in uses `prompt=consent` and applies the same
     directory-role gate.
4. If a scope is not granted, Microsoft Graph returns 403 for the datasets that need it. The
   dataset is reported **Unauthorized** with the missing consent named, and its controls are
   NOT_ASSESSED. The rest of the assessment continues.

The approved directory roles (Global Administrator, Privileged Role Administrator,
Security Administrator, Global Reader, Security Reader) are unchanged.

Some datasets need more than the scope:

- **SharePoint:** reading tenant settings needs Global Reader or SharePoint Administrator.
  A Security Reader session reports it as Unauthorized.
- **Teams app settings:** Microsoft does not document the required role.
