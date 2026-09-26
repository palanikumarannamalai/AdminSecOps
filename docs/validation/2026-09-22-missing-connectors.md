# Validation: missing online connectors (2026-09-22)

- **Starting point:** commit 7f41a87 on branch `codex/online-test-app` (engine and control
  library 0.3.0, hosted collector 0.2.0).
- **Implemented by:** Claude. Codex reviews and deploys.
- **Not done:** no deployment, commit, push, cloud account access, tenant access or
  permission change. The real assessment report, customer evidence, credentials and
  `~/.AdminSecOps-test` were not read.
- **No live tenant has been tested.** All behaviour below is validated only against
  synthetic responses shaped after current Microsoft documentation.

The current permission and runtime matrix, deployment steps and on-premises design are in
[docs/ONLINE-CONNECTORS.md](../ONLINE-CONNECTORS.md).

## Result per connector

| # | Connector | Status | Controls it can move from NOT_ASSESSED | Remaining blocker |
|---|---|---|---|---|
| 1 | Intune settings | **Complete (code)** | INTUNE-CMP-001 | Live check that `/beta/deviceManagement/settings` returns the settings where v1.0 omits them |
| 2 | Entra: six datasets | **Complete (code)** | ENTRA-PRIV-004, ENTRA-APP-00x (apps, grants), HYB-SYNC-001/002. PIM eligibility also feeds PRIV-001/002/005 | Consent for `OnPremDirectorySynchronization.Read.All`. The sync read works only for Global Administrator sign-ins (Microsoft limit) |
| 3 | Azure Resource Manager | **Complete (code), disabled by default** | All 12 Azure controls | Owner approval to add Azure Service Management `user_impersonation`; `ONLINE_CONNECTORS=azure`; customer Reader role |
| 4a | Public mail DNS | **Complete (code), always on** | M365-MAIL-002, M365-MAIL-003 | None. DNS is recursive and not DNSSEC-validated (documented in evidence) |
| 4b | Exchange Online | **Implemented, not activated** | 10 remaining Exchange/Defender controls (incl. M365-MAIL-001) | Owner decision on `Exchange.Manage` (not read-only), PowerShell 7.6 + ExchangeOnlineManagement 3.10.1 on the host, live verification of delegated `-AccessToken` |
| 5 | On-premises (42 controls) | **Design only** | None | Owner decision on an installed, signed, outbound-only agent (ONLINE-CONNECTORS.md) |
| 6 | Coverage UI and connect flow | **Complete (code)** | n/a | None |

Expected effect on the sanitized report (103 controls, 73 NOT_ASSESSED), after deployment
and customer consent/connection. These are **estimates, not measured**:

- Intune: 1 control.
- Entra and hybrid: 6 controls, subject to licence, role and consent. The sync read needs a
  Global Administrator sign-in.
- Azure: 12 controls, when connected and Reader is assigned.
- Exchange: 2 controls from DNS now; up to 12 total if the connector is activated.
- On-premises: all 42 remain not assessed.

## What was built

- **Shared client.** `graph-client.ts` is generalised with per-service `ServicePolicy` (URL
  allowlist, nextLink rule, headers) and one `CollectionBudget` shared by every service. The
  Graph behaviour is unchanged. Dot-segment URLs, including percent-encoded ones, are now
  rejected before parsing.
- **Intune.** `intune.ts` tries v1.0 `$select`, then v1.0 full, then the single beta
  exception `GRAPH_BETA_EXCEPTIONS = {'/beta/deviceManagement/settings'}`:
  - exact path, no query, never a nextLink;
  - warning `GRAPH_BETA_SOURCE`;
  - a missing `secureByDefault` still fails, never defaulted;
  - an empty response is a service gap, not missing consent.
- **Entra.** `entra.ts` adds PIM instances and eligibilities (licence-gated P2/ID
  Governance), applications, service principals and API permission grants (credential
  metadata only), and directory synchronization.
  - `HOSTED_PERMISSION_OVERRIDES` records that `RoleManagement.Read.Directory` and
    `Directory.Read.All` (already granted) are documented as sufficient.
  - The only new Graph scope is `OnPremDirectorySynchronization.Read.All`.
- **Azure.**
  - `arm-client.ts` holds the ARM operation and api-version allowlist and the same-path
    nextLink rule.
  - `azure.ts` has the eight collectors: tenant-bound subscription discovery, per-subscription
    fan-out, and principal names through Graph with the Graph token.
  - Missing rights are reported `NO_ACCESSIBLE_SUBSCRIPTIONS`, `READER_REQUIRED` or
    `SUBSCRIPTIONS_UNAUTHORIZED`, all Unauthorized.
- **Exchange.**
  - `exchange-runner.ts` defines the runner abstraction and a `PowerShellExchangeRunner`
    (fixed spawn, minimal env, stdin-only token, timeout/size/cancel, strict result parser,
    cached single-flight runtime probe).
  - `runtime/exchange/Invoke-AsoExchangeCollection.ps1` is the fixed Get-* table, validates
    input and uses `-CommandName`.
  - `exchange.ts` has the ten dataset mappings (no coercion) and the tenant check.
- **DNS.** `dns.ts` and the mail DNS collector use a bounded resolver. The domains come from
  Exchange accepted domains or verified Email domains, and every dataset carries the
  provenance warnings.
- **Connector plumbing.**
  - `package.ts` / `runtime.ts`: connector states map to explicit statuses and codes
    (`CONNECTOR_NOT_CONNECTED`, `_CONSENT_REQUIRED`, `_EXPIRED`, `_UNAVAILABLE`). The
    envelope `source.system` now reflects the real source, and the manifest records the
    connectors used.
  - A module whose datasets were all NotCollected is Skipped; one with some NotCollected is
    CompletedWithErrors.
- **Auth.** `auth.ts` adds per-connector consent and sign-in (`beginConnect`,
  `completeConnect`, `refreshConnector`):
  - bound to the session tenant, the session user and the starting session;
  - verified ID token and role gate;
  - access token claim checks for audience, tenant, user and delegated scope;
  - AES-GCM sealing with AAD bound to connector + tenant + user;
  - consent-required detection that keeps no provider text.
- **Connectors, server, worker, store, config.**
  - `connectors.ts`: state for UI and jobs.
  - `server.ts`: `/auth/connect/{azure|exchange}` (session required, refused when started
    cross-site), a connector branch in `/auth/callback`, `/api/connectors/{id}/disconnect`
    (CSRF-protected), connectors in `/api/me`, and jobs carry separately sealed connector
    tokens.
  - `worker.ts`: resolves and refreshes connectors per job.
  - `store.ts`: `encrypted_connectors` column, cleared with the job; ALTER only when missing.
  - `config.ts`: `ONLINE_CONNECTORS`, `EXCHANGE_PWSH_PATH` (absolute path only), and the new
    Graph scope in the read-only allowlist.
- **Web.**
  - The Coverage page distinguishes not connected, consent/permission required, unsupported
    online (including on-premises for online assessments), collection failed and not
    licensed.
  - The online home page has an "Additional data sources" panel with Connect, Reconnect and
    Disconnect. There is no button for connectors the deployment or server cannot use, and
    connect links are schema-restricted to `/auth/connect/…`.
- **Docs.** New `docs/ONLINE-CONNECTORS.md`, updated `docs/ONLINE-WORKLOADS.md`, and
  `CHANGELOG.md`.
- **Versions.** Hosted collector 0.3.0. Engine, control library and dataset schemas are
  unchanged, so old evidence stays compatible and fixtures/generated docs did not need
  regeneration.

## Checks run

| Check | Result |
|---|---|
| `npx vitest run --maxWorkers=2` (all projects) | 67 files; 1,390 passed, 1 skipped (see below) |
| Control-plane + web subset | 18 files; 217 passed, 1 skipped |
| `npm run typecheck` | passed |
| `npx eslint apps packages scripts tests --max-warnings=0` (untracked `docs/architecture`, `docs/investor`, `docs/product` not linted or edited) | passed |
| `npm run build:packages`, `npm run build -w @adminsecops/control-plane`, `npm run build:online -w @adminsecops/web` | passed |
| `npm run scan:secrets` | passed (scans tracked files only; the new files are untracked until committed. Their synthetic JWTs are generated at test time, not stored) |
| Local-PowerShell run of the Exchange script (probe + invalid-request rejection, no network) | **Not run here**: the local pwsh is outside the standard paths and setting `ADMINSECOPS_TEST_PWSH` needed interactive approval. Codex can run `ADMINSECOPS_TEST_PWSH=<abs path to pwsh> npx vitest run apps/control-plane/src/collector/exchange-runner.test.ts` |
| PSScriptAnalyzer on `runtime/exchange/*.ps1` | **Not run here** (interactive approval required; `npm run lint:ps` does not scan `apps/`). Codex should run `Invoke-ScriptAnalyzer -Path apps/control-plane/runtime/exchange -Settings collectors/powershell/PSScriptAnalyzerSettings.psd1` |
| Pester (`npm run test:ps`) | Not run: no PowerShell collector, catalogue or replay fixture changed |

Synthetic scenarios, in `apps/control-plane/src/collector/connectors.test.ts` unless noted:

- **Azure:**
  - normal collection of all 12 controls;
  - foreign-tenant subscription excluded and never requested;
  - Graph/ARM token separation on every request, and neither token stored;
  - Graph token reused as ARM token refused;
  - not connected, consent required, expired and unavailable states;
  - empty subscriptions reported as NO_ACCESSIBLE_SUBSCRIPTIONS;
  - 403 in all subscriptions (Unauthorized) and in one (Partial), without leaking the error
    body;
  - 404 and missing field (Failed);
  - later page fails (Partial);
  - five malicious nextLinks (other host, other subscription, other api-version, extra
    query, http), none followed;
  - fan-out limit;
  - subscription without tenant ID;
  - 401 on the subscription list;
  - cancellation;
  - URL allowlist unit cases.
- **Exchange:**
  - normal run with one runner call, controls evaluated, DNS using accepted domains, token
    not stored;
  - runtime unavailable, with no run started;
  - connection refused and one cmdlet denied (Unauthorized);
  - tenant mismatch or unreported tenant (all discarded);
  - truncated list (Partial) and missing values (Failed);
  - ATP cmdlet absent (NotApplicable);
  - timeout (Failed) and cancellation.
- **Exchange runner** (`exchange-runner.test.ts`):
  - fixed arguments, no shell, minimal environment (no client secret, key or DB URL), token
    only on stdin;
  - malformed output rejected;
  - timeout, size limit and cancellation kill the process;
  - missing runtime and module version mismatch;
  - single-flight probe;
  - the script's cmdlet table equals the TypeScript table, all `Get-*`, and there are no
    state-changing cmdlets, dynamic code or process execution.
- **DNS:**
  - only Email-capable verified domains, with provenance warnings, and MAIL-001 stays
    NOT_ASSESSED;
  - all lookups failing (Failed) and DMARC-only failures (MAIL-003 NOT_ASSESSED);
  - host name validation.
- **Entra:**
  - six datasets collected, with credential secrets, hints and key material never stored;
  - Exchange resource principal absent (noted);
  - PRIV-004 and HYB-SYNC evaluated;
  - no P2 licence: NotApplicable with no requests;
  - sync 403 names the new scope in the Unauthorized message, and controls stay
    NOT_ASSESSED;
  - no false consent hint for overridden scopes;
  - missing credential lists (Partial);
  - grant resource 403 (Unauthorized);
  - later PIM page fails (Partial).
- **Intune:**
  - beta used only after both v1.0 attempts, with one exact URL;
  - beta never called when v1.0 has the settings;
  - beta 403 (Unauthorized); empty beta response is a service gap; missing `secureByDefault`
    is Failed;
  - beta allowlist unit cases.
- **Auth** (`auth.test.ts`):
  - AAD-bound sealing across connector, tenant and user, with no cross-use between Graph and
    connector blobs;
  - claim checks: wrong audience (Graph, Exchange), tenant, user, app-only token, expired,
    opaque;
  - tenant-specific authorize URL with only the resource scope, including with open
    onboarding;
  - connect completion rejects other session, other user, wrong audience, a login
    transaction, and Exchange without a UPN;
  - a connector transaction cannot complete a login;
  - refresh at the session tenant with a re-check; a foreign-tenant refreshed token and
    consent-required (65001) are refused;
  - config validation.
- **Server** (`server.test.ts`):
  - connect requires session, an enabled connector and a valid consent value, and redirects
    to the tenant authority with the ARM scope;
  - cross-site starts refused;
  - expired one-hour authorization refused;
  - callback without the starting session refused;
  - declined consent without leaking provider text;
  - `/api/me` connector states without tokens;
  - a connector sealed for another user is ignored;
  - disconnect needs CSRF;
  - job gets sealed connectors, and an expired connector is recorded as a gap.
- **Worker** (`worker.test.ts`): connected, other user's blob, consent-required gap,
  missing, and disabled-deployment cases.
- **Store** (`store.test.ts`): ALTER only when the column is missing; connector tokens
  cleared on failure.
- **Web** (`CoveragePage.test.tsx`, `OnlineHomePage.test.tsx`):
  - connector gap reasons and workload blockers, including on-premises as unsupported
    online;
  - home page: Connect/Reconnect/Disconnect, no button for unavailable sources, non-connect
    URLs rejected.

## Deployer actions (Codex)

Full steps are in ONLINE-CONNECTORS.md → "Deployment instructions".

1. **Owner role:** add `encrypted_connectors` to `aso_sessions` and `aso_jobs`.
2. **Package:** include `apps/control-plane/runtime/exchange/`.
3. **Graph:**
   - add delegated `OnPremDirectorySynchronization.Read.All` to the app registration;
   - add it to `GRAPH_SCOPES` (full value in ONLINE-CONNECTORS.md).
4. **Azure** (after the owner approves the permission):
   - add Azure Service Management delegated `user_impersonation`;
   - set `ONLINE_CONNECTORS=azure`.
5. **Exchange:** only after the owner explicitly accepts the `Exchange.Manage` boundary.
   - Install pinned PowerShell 7.6.x (SHA-256 verified) and ExchangeOnlineManagement 3.10.1
     under `/home/site/tools`.
   - Set `EXCHANGE_PWSH_PATH` and `PSModulePath`, and add `exchange` to `ONLINE_CONNECTORS`.
   - Verify live before telling customers.
   - Until then, do nothing: the UI shows Exchange as not available on this deployment.
6. **Before deploying:** run the two "not run here" checks above.
7. **After deploying:** check health, the unauthenticated 401s, the connect redirect and
   Coverage.

## Customer actions

1. An administrator re-consents for the new Graph scope ("Reconnect and review Microsoft
   consent").
2. Connect Azure. The account needs Reader on the subscriptions to assess.
3. Optionally connect Exchange Online, when offered.
4. Run a new assessment.

## Known limitations

- **Delegated Exchange token.** A third-party app's delegated token with
  `Connect-ExchangeOnline -AccessToken -UserPrincipalName` is only implicitly documented by
  Microsoft. `Get-ConnectionInformation` must report `TenantID`, otherwise Exchange data is
  discarded (fails closed). Both need live verification.
- **Runtime platform.** The Exchange module lists Ubuntu LTS. The App Service Node image is
  Debian-based.
- **API versions.** Security contacts (2023-12-01-preview) and subscription diagnostic
  settings (2021-05-01-preview) have no GA version. Newer GA versions exist for storage, Key
  Vault and network; the current versions were kept to match the PowerShell collector.
- **Subscription visibility.** Subscriptions invisible to the signed-in account are not
  assessed (warning on every Azure dataset).
- **Principal names.** Azure principal name resolution is limited to `maxFanoutRequests`
  (200) principals. Beyond that there is a warning, and the guest-privilege control reviews
  unresolved users.
- **On-premises.** No on-premises collection exists online.
