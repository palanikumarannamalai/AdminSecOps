# Exchange connector sign-in correction — 2026-09-24

The user reported AADSTS650053: Exchange.Manage was being resolved against Microsoft Graph (00000003-0000-0000-c000-000000000000). The app previously hid this identifier behind a generic consent failure.

Changed the delegated Exchange scope to the Exchange resource's canonical https://outlook.office.com/Exchange.Manage URI and put the explicit resource scope before the OIDC scopes. Authorization-code and refresh requests share the same resource definition. Accepted Exchange audiences now include outlook.office.com while retaining the Exchange GUID and office365 aliases; Graph audiences remain rejected. No permissions or customer consent were added by this correction.

Connector callback errors now expose only an allow-listed OAuth error name and bounded AADSTS identifier. Raw descriptions, account details and tokens are not reflected. Tests cover redaction and oversized/unrecognized inputs.

Validation: 33 auth/server tests passed. Live tenant Exchange consent and collection must be retried by the user; synthetic tests cannot establish that those succeeded.

Microsoft resource metadata was read directly from the Exchange service principal. Microsoft's support example uses the canonical resource URI: https://learn.microsoft.com/en-us/answers/questions/1636448/error-aadsts650053-the-application-x-asked-for-sco

Deployment 4d6878ac-03db-45fd-abcd-e316f9d4f70f completed and became active. Deployed compiled auth and server files contain the correction. Post-deployment health and frontend returned HTTP 200, protected connector routes returned 401 without a session, and Microsoft sign-in returned the expected 302. Build, focused lint and diff checks passed. User retry is still required to verify the Microsoft consent flow end to end.
