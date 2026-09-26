# AdminSecOps online test deployment

Status: multitenant administrator onboarding test release (21 September 2026).

## Test site and scope

- URL: https://app.adminsecops.com (custom domain configured 24 September 2026; see CUSTOM-DOMAIN.md).
- Registration home tenant: Contoso (fictional example), aaaaaaaa-0000-4000-8000-000000000002.
- Open onboarding accepts Microsoft work accounts with a supported active tenant-wide directory role.
- Entra app client ID: `<client-id>`. Copy it from **Application (client) ID** on the app
  registration's Overview page in the Microsoft Entra admin center; the App Service holds it in `AZURE_CLIENT_ID`.
- Callback: https://app.adminsecops.com/auth/callback.
- Multitenant test release; customer administrator consent is required in each organization.
- Microsoft sign-in and delegated read-only Graph consent required. No administrator password stored.
- No sample uploads or downloaded collectors required by the online flow.

The current collector (hosted collector 0.3.0) supports these workloads:

- **Entra:** organization, subscribed licences, guest users, security defaults, authorization
  policy, authentication methods policy, Conditional Access policies, MFA registration details,
  role definitions and assignments, and allow-listed directory settings.
- **SharePoint/OneDrive:** tenant settings.
- **Teams:** app settings and per-team member/guest settings.
- **Intune:** compliance settings, device overview, and compliance policies with assignments.

The collector also implements PIM, application metadata, Azure and Exchange/Defender for Office 365 datasets. Azure and Exchange need separate connections. Teams tenant policies and on-premises modules remain unavailable online. See docs/ONLINE-CONNECTORS.md for current coverage and live-validation limitations. See docs/ONLINE-WORKLOADS.md for the
endpoint/permission matrix, limitations and consent steps. Missing evidence is not a pass; each
assessment's Coverage page shows what was and was not assessed.

## Runtime and cost

Resource group: rg-adminsecops-test-neu, North Europe.
Linux App Service B1 hosts the frontend, authenticated API and one durable-job worker.
PostgreSQL Flexible Server B1ms has 32 GB storage, 7-day local backup retention, no HA or geo-backup.
The app uses a restricted database login, TLS certificate validation and firewall rules limited to
the site's possible outbound addresses. Temporary developer database access was removed.

North Europe was selected because Azure explicitly restricts this subscription from PostgreSQL in
West Europe. The unused West Europe app and plan from the failed attempt were removed.
The earlier UAE North resource group remains empty.

Retail baseline checked 2026-09-21 in USD:
- Linux App Service B1: 0.018/hour x 730 = 13.14/month.
- PostgreSQL B1ms: 0.018/hour x 730 = 13.14/month.
- PostgreSQL storage: 0.1265/GB-month x 32 = 4.048/month.
- Baseline total: approximately 30.33/month, before transfer, extra backup storage, taxes and
  subscription credits/discounts.
- Resource-group budget: 50/month; email notifications at 50%, 80%, 100% to `<admin-upn>`.
  `<admin-upn>` is the administrator account that owns the test subscription and receives its budget alerts.
  Azure budgets notify; they do not cap or stop spending.

No paid static frontend, Container Registry, AI API, Kubernetes or extra worker service is needed.
The App Service plan continues billing even if the app is stopped.

## Security and retention

OIDC code flow uses PKCE, state, nonce, signature/issuer/audience/tenant validation and explicit user
allowlist. Server session IDs are hashed in PostgreSQL. Graph tokens use AES-256-GCM encryption.
Cookies are Secure, HttpOnly and SameSite=Lax; mutating API calls require matching Origin and the
application header. Login and job rate limits are per instance; keep the test app at one instance.
Only health, static assets and the sign-in endpoints are public. `GET /api/usage` ignores the session
and requires its own bearer secret (below); it returns 404 unless `USAGE_API_SECRET` is set. Every
assessment/job read is scoped to the authenticated tenant.

Secrets are held in Azure app settings, not source control. Deployment-machine recovery copies use
Windows DPAPI under the user's .AdminSecOps-test directory. The client credential expires after
three months; rotate before expiry. Key Vault integration is a future hardening task, not implemented.
Basic FTP/SCM publishing authentication is disabled; deployment uses Entra bearer authentication.

Raw collected package data is processed in memory. Derived results are stored for 30 days;
audit events for 90 days; expired sessions and completed-job encrypted tokens are removed.
Backups can retain deleted data until their retention expires. No billing/remediation/AI features exist.
Anonymous aggregate usage counts (tables `aso_usage_daily` and `aso_usage_orgs`) are deleted after
`USAGE_RETENTION_DAYS` (default 400). The same `cleanup()` pass applies all of these deletions.
A failed or interrupted worker job is marked failed after 15 minutes; queued jobs expire after one hour.
There is no full scheduler or cross-instance distributed API rate limiter yet.

## Build and deployment

1. npm ci
2. npm run build:packages
3. npm run build -w @adminsecops/control-plane
4. npm run build:online -w @adminsecops/web
5. npm test
6. npm run typecheck
7. npx eslint apps/control-plane/src --max-warnings=0

The online build is apps/web/dist-online. The server starts with:
node apps/control-plane/dist/main.js

Required environment variables: PUBLIC_URL, AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
ALLOWED_USER_IDS, TOKEN_ENCRYPTION_KEY (base64 32 random bytes), DATABASE_URL, GRAPH_SCOPES.
GRAPH_SCOPES accepts only the read-only scopes in READ_ONLY_GRAPH_SCOPES (config.ts); the full
online set is listed in docs/ONLINE-WORKLOADS.md. Scopes absent from GRAPH_SCOPES are not requested,
and datasets that need them are reported Unauthorized and not assessed.
The Node runtime supplies PORT. DATABASE_URL must not disable TLS certificate verification.

Optional usage settings (see docs/PRIVACY.md, "Usage counts in the online service"):

- `USAGE_COUNTING` - `true` (default) or `false`. When on, the server keeps anonymous daily counts
  of assessments started, completed and failed (by fixed reason code), collectors that returned data,
  controls evaluated, report downloads by format and distinct organisations. No tenant ID, domain,
  user ID, error text or finding is stored.
- `USAGE_HASH_SALT` - at least 32 random characters. Keys the one-way hash used to count distinct
  organisations per day. Set it whenever counting is on; without it, every other counter still runs
  and only the distinct-organisation counter is skipped. Changing it restarts distinct counting.
- `USAGE_API_SECRET` - at least 32 random characters. Enables `GET /api/usage?days=N` for the
  author's insights page. `N` is a whole number of UTC days from 0 to 400 including today (default
  30; 0 = all retained days; for example 7, 30, 90, or the day of the month for month-to-date);
  anything else returns 400. `distinctOrganisations` counts distinct organisation hashes across
  the whole window, not a sum of daily counts. The caller sends
  `Authorization: Bearer <secret>`; the server compares SHA-256 digests in constant time. Without
  the setting the endpoint returns 404; a missing or wrong secret returns 401. A session cookie is
  neither required nor accepted. The response has `Cache-Control: no-store` and the shape
  `{ service, from, to, totals, distinctOrganisations, days: [{ day, counters }] }`.
- `USAGE_RETENTION_DAYS` - whole days from 1 to 3650, default 400 (about 13 months).

Generate the two secrets separately, for example with
`node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"`, and store them only
as app settings.

The online-test.json ARM template provisions the App Service plan, HTTPS-only site and database.
It intentionally excludes credential values, Entra registration, firewall IPs and runtime settings.
It is not a one-command unattended provisioner. Deployment packaging contains compiled workspace
packages, server, online UI and production dependencies only. Publish with Entra-authenticated Kudu
ZIP deployment. Container Apps packaging is deferred; App Service is the active test host.

## Validation

- Existing full test suite: 1,188 tests passed before final collector review.
- Reviewed control-plane suite: 45 tests passed, including 35 collector tests.
- Online web suite: 66 tests passed; online production build succeeded.
- Live PostgreSQL verification: restricted role, session persistence, tenant-scoped jobs,
  exclusive job claim and failed-job persistence; synthetic records removed.
- Live site verified: root and health return 200; unauthenticated identity and assessment requests return 401; sign-in page renders and redirects to the correct Microsoft tenant.
- Real Microsoft sign-in/consent and a live read-only tenant assessment completed on 2026-09-21.
- Follow-up validation compared policy states, role counts and MFA registration scope with live Graph reads.
  Private tenant evidence remains outside source control. No tenant configuration was changed.
- Validation corrections: 1,229 automated tests and 45 PowerShell replay tests passed; typecheck,
  focused lint and online/server builds passed. Excluded applications/platforms, device filters,
  MFA-strength requirements and grant alternatives cannot establish unrestricted coverage.
  Unknown administrator sync state and incomplete administrator coverage require review.
- Existing saved assessments retain their original results. Customer tenant consent and the first
  customer assessment require an administrator to complete Microsoft sign-in.


## Multitenant onboarding

With OPEN_TENANT_ONBOARDING=true, the default Microsoft sign-in uses the organizations
endpoint. An optional tenant ID directs sign-in to a specific organization, including guest
administrator scenarios. Personal Microsoft accounts are not a supported default audience.

The Entra application registration must use signInAudience=AzureADMultipleOrgs and
groupMembershipClaims=DirectoryRole so verified ID tokens carry tenant-wide directory roles.
The app accepts Global Administrator, Privileged Role Administrator, Security Administrator,
Global Reader and Security Reader. Activate eligible PIM roles before signing in. A role without
permission to grant the requested Microsoft Graph scopes needs an authorized tenant administrator
to grant consent first. Customer tenant policy may require a separate approval workflow.

Authentication verifies the signature, exact tenant issuer, audience, expiry, nonce and directory
role. The tenant from an unverified ID token is used only to select Microsoft metadata; it cannot
create a session until verification succeeds. Refresh uses the verified tenant endpoint.
Sessions, jobs, assessment lists, individual reports and comparisons remain tenant-scoped.
A browser has one active organization session; sign out to switch. Results are shared among
supported signed-in administrators of the same tenant, not across customer tenants.

Role approval lasts at most one hour and requires a fresh sign-in afterwards. Role removal is
not continuously synchronized during that interval. Queued work also requires current approval.
Missing directory-role claims fail closed. Microsoft consent is not automatically granted by this app.

Restricted testing remains available with OPEN_TENANT_ONBOARDING=false and an
ALLOWED_TENANT_USERS JSON map of tenant UUIDs to arrays of user object UUIDs. When this map
is absent, AZURE_TENANT_ID and ALLOWED_USER_IDS retain legacy home-tenant restrictions.
Changing a customer allowlist must not involve copying customer credentials into source control.

Rollback: disable OPEN_TENANT_ONBOARDING and retain the known home tenant/user settings;
restore the prior artifact if needed. Do not delete customer results or app consent as part of rollback.

Multitenant release validation: 1,242 automated tests passed, including signed-token rejection,
role-expiry enforcement, worker authorization and cross-tenant report isolation. Typecheck, builds,
focused lint and an independent Claude code review completed. Live customer consent is not simulated.
