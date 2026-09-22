# Validation: online Microsoft 365, Intune, Teams and SharePoint assessments (2026-09-21)

Starting point: commit 2004c95 on branch `codex/online-test-app`. Implemented by Claude.

No deployment, cloud account access, tenant change, commit or push was performed. All
Microsoft Graph behaviour was validated against synthetic responses shaped after the
current Microsoft Graph v1.0 reference. **No live tenant calls were made.**

## Scope delivered

- **Unified online collector** (`apps/control-plane/src/collector/online.ts`, hosted
  collector 0.2.0):
  - Covers Entra ID (the ten existing datasets plus allow-listed `entra.groupSettings`),
    SharePoint/OneDrive tenant settings, Teams app settings, per-team settings and the three
    Intune datasets.
  - One bounded GET-only client and one time/size budget.
  - Tenant verification before any other read, and a strict v1.0 `nextLink` allowlist.
  - Bounded per-resource requests, with cancellation propagated.
  - `collectEntra` keeps its previous Entra-only behaviour.
- **Exchange Online / Defender for Office 365:** recorded as a *Skipped* module with the
  reason (`NOT_AVAILABLE_ONLINE`). Exchange controls remain NOT_ASSESSED.
- **Schemas:**
  - New `m365.teamsAppSettings` and `m365.teamsTeamSettings`.
  - Optional SharePoint `sharingAllowedDomainList`, `sharingBlockedDomainList`,
    `isRequireAcceptingUserToMatchInvitedUserEnabled` and `idleSessionSignOut`.
  - Role and licence notes on the Intune, SharePoint and Teams permissions, and a v1.0
    caveat for the beta-only Windows compliance properties.
- **Controls (library 0.3.0):**
  - M365-SPO-003 (guest resharing) and M365-SPO-004 (idle session sign-out).
  - M365-TMS-001 (personal-scope RSC) and M365-TMS-002 (guest channel management).
  - All four report REVIEW for context-dependent settings and never FAIL.
  - Existing M365-SPO-001/002 and INTUNE-CMP-001/002/003 and INTUNE-CA-001 now run online.
- **PowerShell collector 0.2.0:** the same two Teams datasets and the SharePoint fields, with
  replay fixtures, so the cross-language contract still covers every registry dataset.
- **Web:**
  - Coverage page per workload: datasets collected, catalogue/assessed/not-assessed/not
    applicable counts, and the gap reason for each missing dataset.
  - Online home page lists scopes that were not granted, with a re-consent link.
  - Sign-in and about text updated.
- **Auth and config:**
  - `GRAPH_SCOPES` allowlist extended with read-only scopes only.
  - Granted scopes recorded from the token response, inside the encrypted token blob.
  - `/api/me` reports required, granted and missing scopes.
  - `/auth/login?consent=true` re-prompts consent; any other `consent` value is rejected.
    The directory-role gate is unchanged.
- **Versions:** engine 0.3.0, control library 0.3.0, hosted collector 0.2.0, PowerShell
  collector 0.2.0.

## Checks run

| Check | Result |
|---|---|
| `npx vitest run --maxWorkers=2` (all projects, includes the PowerShell replay contract test, which ran) | 65 files, 1,329 tests passed |
| Control-plane subset | 82 tests passed (20 new online collector tests, plus server, auth and worker tests) |
| Web subset | 74 tests passed (Coverage page and consent notice tests are new) |
| `npm run test:ps` (Pester) | 194 passed, 0 failed |
| `npm run typecheck` and `tsc -b apps/control-plane` | passed |
| `npx eslint . --max-warnings=0` (excluding `docs/architecture/**`, `docs/investor/**`, `docs/product/**`) | passed |
| `npm run lint:ps` | 0 findings |
| `npm run build`, `npm run build:online -w @adminsecops/web` | passed |
| `npm run scan:secrets` | passed |
| `npm run fixtures`, `npm run docs:generate` | regenerated; the generated-docs and fixture tests pass |

The synthetic online test scenarios are in
`apps/control-plane/src/collector/online.test.ts`:

- **Normal collection:** all workloads, with online control verdicts.
- **Exchange:** controls NOT_ASSESSED with coverage not inflated.
- **GET-only / token:** only v1.0 GETs are sent, the token is never stored, and blocked
  directory setting values are dropped.
- **Cross-tenant guard:** a tenant mismatch stops collection after one request.
- **Access denied:** a 403 on SharePoint is reported Unauthorized and names the missing
  consent.
- **Missing fields:** a missing `secureByDefault` is Failed, not defaulted, and so is a
  missing platform count.
- **`$select` fallback:** `deviceManagement` retried without `$select`.
- **Partial pages:** a later compliance-policy page failing makes the dataset Partial.
- **Per-policy assignments:** assignments are read per policy, and one 403 makes the dataset
  Partial and turns PASS into REVIEW.
- **Invalid nextLink:** a beta `nextLink` on the team list is not followed.
- **Unreadable teams:** a team 403 or missing guest settings make the dataset Partial with
  unknown settings.
- **Fan-out limit:** the cap on per-resource requests is enforced.
- **Unsupported endpoint:** HTTP 400 is Failed and the control is NOT_ASSESSED.
- **No Intune licence:** Intune datasets are NotApplicable with no Intune calls, and a
  service licence error is also NotApplicable.
- **Cancellation:** cancelling mid fan-out stops collection.
- **Time budget:** exhaustion stops the fan-out, and later datasets fail.
- **Scopes:** the permission set equals the read-only allowlist.

## Azure / Entra configuration required (to be done by the deployer)

Add these **Microsoft Graph delegated** permissions to the app registration and to
`GRAPH_SCOPES`:

- `SharePointTenantSettings.Read.All`
- `TeamworkAppSettings.Read.All`
- `Team.ReadBasic.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementManagedDevices.Read.All`

The existing scopes are unchanged: `User.Read Organization.Read.All Policy.Read.All
RoleManagement.Read.Directory Directory.Read.All User.Read.All AuditLog.Read.All
UserAuthenticationMethod.Read.All`.

After deployment, a tenant administrator must grant consent again. Then either:

- **Re-consent path:** the administrator signs in through **Reconnect and review Microsoft
  consent** (`/auth/login?consent=true`), or
- **Admin grant:** the administrator grants admin consent to the app, then users sign in
  again.

Until then, the new datasets are Unauthorized and their controls are NOT_ASSESSED. Other
role and licence requirements:

- SharePoint needs Global Reader or SharePoint Administrator. A Security Reader sign-in
  cannot read it.
- Intune needs an Intune licence.

## Remaining blockers and unsupported items

Details are in `docs/ONLINE-WORKLOADS.md`.

- **Exchange Online and Defender for Office 365:** no delegated Graph access. Tenant
  Configuration Management is app-only, so use the PowerShell collector.
- **Teams tenant-wide policies:** meeting, messaging, federation and app permission/setup
  policies. There is no delegated Graph access.
- **Beta-only properties:** Teams chat RSC and custom app settings, and the Windows
  antivirus, firewall and TPM compliance fields. None of these are collected.
- **Entra datasets not collected online:** app registrations, service principals,
  permission grants, PIM schedules and sync settings. These need scopes or roles not
  requested.
- **Live verification pending:** the role needed for `teamsAppSettings` is not documented
  by Microsoft, and the live behaviour of the new endpoints has not been verified against a
  real tenant.

## Deployment review (22 September 2026)

Codex independently reran the full suite: 1,329 tests passed. Two additional regression
cases passed in the 22-test online collector suite: the documented wrapped Teams app
settings response and truncated expanded Intune assignments. Production package, server
and online frontend builds passed. The new five delegated scopes were validated against
the live Microsoft Graph service principal and added to the existing app registration.
Each customer must grant consent and rerun an assessment; synthetic tests do not establish
successful collection in a customer tenant. No tenant security settings were changed.

Deployment completed on 22 September 2026: Azure deployment
`d241c032-4dfa-46ac-b964-8c1947602688`, engine 0.3.0. A clean restart resolved
an interrupted platform warm-up. Live checks passed: health 200, unauthenticated API 401,
Microsoft consent redirect 302 with all five new scopes, and the updated frontend bundle.
Customer workload collection still requires fresh consent and a new tenant assessment.
