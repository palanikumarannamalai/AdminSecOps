# Privacy

AdminSecOps is designed to collect the minimum data needed to assess configuration, to
keep the administrator informed about where it is processed. Processing depends on the mode.

## What is collected

Configuration metadata described dataset-by-dataset in [DATA-COLLECTION.md](DATA-COLLECTION.md),
including some personal data:

- identifiers of administrators and other accounts relevant to a control (UPN, display
  name, SAM account name, SID, object ID);
- activity metadata where a control needs it (last sign-in of guest users, last logon of
  privileged AD accounts and computers);
- MFA registration state (registered yes/no, method types - not the phone numbers or keys).

## What is excluded from assessment evidence

Passwords or password hashes, tokens, private keys, authentication cookies, e-mail message
bodies or subjects, Teams messages, SharePoint/OneDrive documents, LAPS passwords, client
secret values or hints, security contact e-mail addresses, custom banned password lists.
The engine rejects evidence files containing such material (see EVIDENCE-MODEL.md).

## Online service

The online app at app.adminsecops.com collects configuration server-side with delegated
Microsoft access. Authentication necessarily uses tokens and session cookies; these are
not assessment evidence. Raw configuration evidence is processed in memory. Assessment
results are retained for 30 days and audit events for 90 days. Downloaded reports remain
under your control and are not removed by server retention. Review the requested consent
and [connector permissions](ONLINE-CONNECTORS.md) before connecting a tenant, and confirm the
app name and publisher on Microsoft's consent screen before granting (see
[Customer activation](ONLINE-CONNECTORS.md#customer-activation)).

### Usage counts in the online service

The online service records anonymous aggregate usage counts, computed on its server. The
browser sends nothing extra for this: there is no client-side tracking, no analytics script
and no additional cookie. For each UTC day it keeps only these totals:

- assessments started, completed and failed;
- failed assessments by a fixed reason code (`NOT_APPROVED`, `CONSENT_OR_TOKEN`,
  `COLLECTION_FAILED`, `TIMEOUT`, `QUEUE_EXPIRED`, `UNKNOWN`), never the error text;
- completed assessments in which each collector returned data (Entra, Microsoft 365,
  Intune, Azure, Exchange Online, DNS);
- the number of controls evaluated;
- report downloads by format (JSON, HTML);
- the number of distinct organisations.

No tenant identifier, domain, user identifier, display name or finding is stored with these
counts. To count distinct organisations, the server stores a salted one-way hash
(HMAC-SHA-256 with a secret server-side salt) of the tenant ID for the day, so the same
organisation is counted once per day and the hash cannot be turned back into the tenant ID.
The counts stay in the service's own database and are not sent to any third party; the
author reads the totals through an authenticated server endpoint. They are kept for about
13 months (400 days) and then deleted.

## Where data goes in the local application

Nowhere, by default. The collector writes an evidence package to a folder you choose.
The local application processes it in memory on your machine and stores only the
processed result under `%LOCALAPPDATA%\AdminSecOps\data` (or `ADMINSECOPS_DATA_DIR`).
The raw evidence package is not copied by the application. The local application has no
telemetry and makes no outbound network calls.

## Your control

- Delete an assessment from the dashboard (Assessments > Delete) or by deleting its JSON
  file from the data directory. Delete the evidence ZIP yourself when no longer needed.
- Reports are files you control; treat them as confidential.

## Recommendations for administrators

- Store evidence packages and reports in a location with restricted access (e.g. an
  encrypted, access-controlled folder), and delete them when the work is complete.
- Assessment output is covered by your organisation's data-protection obligations
  (it contains personal data of employees and guests).
- Do not attach evidence packages to tickets or e-mail.
