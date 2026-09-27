# Connector deployment — 2026-09-24

Deployed to https://app.adminsecops.com/ with deployment ID `<deployment-id>` (Azure status 4, active). Includes hosted collector 0.3.0 and control library 0.4.0 (105 controls).

The owner explicitly approved Graph OnPremDirectorySynchronization.Read.All, Azure Service Management user_impersonation and Exchange Online Exchange.Manage. Added these delegated permissions to the app registration, preserving existing entries. No customer tenant consent or role assignment was performed.

Applied additive encrypted_connectors columns to aso_sessions and aso_jobs. Enabled ONLINE_CONNECTORS=azure exchange. Installed PowerShell 7.6.4 after verifying the release SHA256 and ExchangeOnlineManagement 3.10.1. The fixed runner's hosted runtime probe passed. Azure reserves PSModulePath as an app-setting name, so EXCHANGE_MODULE_PATH supplies that path only to the isolated child process.

Validation:
- Prior complete suite: 1,414 tests across 69 files passed.
- Follow-up auth/server tests: 33 passed.
- Exchange runner tests after the environment mapping change: 9 passed.
- Control-plane build, focused lint, secret/hygiene scan and diff whitespace checks passed.
- Final live checks: health and frontend HTTP 200; unauthenticated session and both connector routes HTTP 401; Microsoft sign-in HTTP 302 with the new Graph scope and canonical callback verified.

The hosted Exchange runtime probe verifies dependencies, not authenticated Exchange collection. Real Azure/Exchange evidence collection remains unverified until an authorized user signs in, reviews Microsoft consent, connects each workload and runs a new assessment. Existing reports do not update automatically. The 42 on-premises controls remain unsupported online.

Rollback package: out/adminsecops-before-connectors.zip. Preserve that package. Disable optional connectors with ONLINE_CONNECTORS if necessary; the additive database columns can remain. Do not remove pre-existing registration permissions when reverting new scopes.
