# AdminSecOps online test deployment

Status: deployed for first-user sign-in testing (21 September 2026).

## Test site and scope

- URL: https://adminsecops-test-neu-palani.azurewebsites.net
- Tenant: Palani Lab, c15f03d1-1adc-4b27-b475-c65192c029a7.
- Allowed user: cloudadmin@palanilab.com (object ID 5c48b50f-8463-4707-95bf-8d63661fca83).
- Entra app client ID: bb1cbc8b-51c1-472d-93a6-0476478eb71e.
- Callback: https://adminsecops-test-neu-palani.azurewebsites.net/auth/callback.
- Single-tenant private test, not a production multitenant SaaS release.
- Microsoft sign-in and delegated read-only Graph consent required. No administrator password stored.
- No sample uploads or downloaded collectors required by the online flow.

The current collector supports organization, subscribed licences, guest users, security defaults,
authorization policy, authentication methods policy, conditional access policies, MFA registration
details, role definitions and role assignments. General user inventory, PIM eligibility, Exchange,
Intune, Defender, Azure resources and on-premises modules are not collected yet. The full roadmap
is retained; missing evidence is not a pass.

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
- Resource-group budget: 50/month; email notifications at 50%, 80%, 100% to cloudadmin@palanilab.com.
  Azure budgets notify; they do not cap or stop spending.

No paid static frontend, Container Registry, AI API, Kubernetes or extra worker service is needed.
The App Service plan continues billing even if the app is stopped.

## Security and retention

OIDC code flow uses PKCE, state, nonce, signature/issuer/audience/tenant validation and explicit user
allowlist. Server session IDs are hashed in PostgreSQL. Graph tokens use AES-256-GCM encryption.
Cookies are Secure, HttpOnly and SameSite=Lax; mutating API calls require matching Origin and the
application header. Login and job rate limits are per instance; keep the test app at one instance.
Only health, static assets and the sign-in endpoints are public. Every assessment/job read is scoped
to the authenticated tenant.

Secrets are held in Azure app settings, not source control. Deployment-machine recovery copies use
Windows DPAPI under the user's .AdminSecOps-test directory. The client credential expires after
three months; rotate before expiry. Key Vault integration is a future hardening task, not implemented.
Basic FTP/SCM publishing authentication is disabled; deployment uses Entra bearer authentication.

Raw collected package data is processed in memory. Derived results are stored for 30 days;
audit events for 90 days; expired sessions and completed-job encrypted tokens are removed.
Backups can retain deleted data until their retention expires. No billing/remediation/AI features exist.
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
The Node runtime supplies PORT. DATABASE_URL must not disable TLS certificate verification.

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
- First real Microsoft sign-in/consent and live tenant assessment remain user-assisted validation.
  Do not claim a real tenant assessment has passed until it is completed.
