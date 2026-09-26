# AdminSecOps custom domain

Configured 24 September 2026.

- Application: https://app.adminsecops.com
- Existing Azure host: adminsecops-test-neu-palani.azurewebsites.net
- Resource group: rg-adminsecops-test-neu (North Europe)
- GoDaddy CNAME `app`: `adminsecops-test-neu-palani.azurewebsites.net`
- GoDaddy TXT `asuid.app`: Azure App Service domain verification ID (retain it).
- Root domain and `www` records continue to point to the existing GoDaddy website.
- Azure App Service Managed Certificate: `app-adminsecops-com`, SNI binding enabled.
- App setting `PUBLIC_URL`: `https://app.adminsecops.com`.
- Microsoft Entra web redirect URI: `https://app.adminsecops.com/auth/callback`.
- Previous Entra redirect URI retained for rollback.

Use the custom domain to begin sign-in. Cookies belong to each hostname, so sign in again at the new address. The old Azure origin is not the configured application origin for authenticated writes or sign-in transactions. Do not start a new login there.

No application code, collector permissions, customer data, or hosting plan changed for this domain configuration. The pending connector work is a separate release.

The previously reported Chrome Safe Browsing warning remains a separate investigation; changing the hostname does not resolve or validate that report.

Rollback: set PUBLIC_URL back to the existing Azure HTTPS origin, restart the app, verify the matching Microsoft callback, and direct testers to that origin. Keep the registered callback and existing DNS records until any rollback has been tested.

Validation: valid HTTPS; root and /api/health return 200; unauthenticated /api/me returns 401; /auth/login returns 302 to login.microsoftonline.com with redirect_uri=https://app.adminsecops.com/auth/callback. New sign-in page rendered in browser. Interactive Microsoft sign-in on the new hostname remains for the tester.
