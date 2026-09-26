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

## Where data goes in the local application

Nowhere, by default. The collector writes an evidence package to a folder you choose.
The local application processes it in memory on your machine and stores only the
processed result under `%LOCALAPPDATA%\AdminSecOps\data` (or `ADMINSECOPS_DATA_DIR`).
The raw evidence package is not copied by the application. There is no telemetry and the
application makes no outbound network calls.

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
