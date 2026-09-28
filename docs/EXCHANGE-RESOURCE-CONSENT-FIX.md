# Exchange resource consent correction — 28 September 2026

A fresh lab callback reported AADSTS650053: Exchange.Manage was resolved against Microsoft Graph (00000003-0000-0000-c000-000000000000). The deployed request already used outlook.office.com/Exchange.Manage. Directory metadata confirmed the enabled Exchange.Manage delegated scope and matching app registration.

Use https://outlook.office365.com/.default for Exchange authorization, code exchange and refresh. Continue requiring Exchange audience, Exchange.Manage claim, matching tenant and user, ID-token signature/nonce, PKCE and session binding. No app permissions or tenant policies were changed. Static consent can display all configured required permissions; review the Microsoft consent screen. The registered Exchange permission remains only the previously approved Exchange.Manage delegated permission.

Reference: https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc
Reference: https://learn.microsoft.com/en-us/exchange/reference/admin-api-authentication

A live reconnect is required to verify Microsoft accepts the revised request. A successful connection does not by itself validate the PowerShell collection.
