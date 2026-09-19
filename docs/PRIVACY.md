# Privacy

AdminSecOps is designed to collect the minimum data needed to assess configuration, to
process it locally, and to keep the administrator in control of it.

## What is collected

Configuration metadata described dataset-by-dataset in [DATA-COLLECTION.md](DATA-COLLECTION.md),
including some personal data:

- identifiers of administrators and other accounts relevant to a control (UPN, display
  name, SAM account name, SID, object ID);
- activity metadata where a control needs it (last sign-in of guest users, last logon of
  privileged AD accounts and computers);
- MFA registration state (registered yes/no, method types - not the phone numbers or keys).

## What is never collected

Passwords or password hashes, tokens, private keys, authentication cookies, e-mail message
bodies or subjects, Teams messages, SharePoint/OneDrive documents, LAPS passwords, client
secret values or hints, security contact e-mail addresses, custom banned password lists.
The engine rejects evidence files containing such material (see EVIDENCE-MODEL.md).

## Where data goes

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
