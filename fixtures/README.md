# Sample assessment fixtures

This folder holds **sanitized, entirely fictional** evidence packages that look like the output of
the AdminSecOps PowerShell collector. They are used for demos, UI development and automated tests.

> **All data here is fictional.** No real tenant, organisation, person, or credential appears in
> these files. Organisation names (Contoso, Fabrikam, Northwind) are Microsoft's standard fictional
> names. Domains use the reserved `.example` TLD. The only exception is the initial domain
> `contoso.onmicrosoft.com`, which follows Microsoft's naming pattern so that controls that exclude
> `*.onmicrosoft.com` behave as they would in a real tenant. IP addresses come only from the
> documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Domain SIDs are obviously
> synthetic (`S-1-5-21-1111111111-2222222222-3333333333`). GUIDs are generated from fixed seeds.
> Public Microsoft identifiers that controls rely on (built-in Entra role template IDs, Azure
> built-in role IDs, the guest user role ID, first-party application IDs such as Microsoft Graph,
> and Microsoft Graph/Exchange app role IDs) are real, because they are the same in every tenant.
> No file contains a password, secret, token, key, hash or message content. The GPP `cpassword`
> finding is recorded as a file path only, as the real collector does. Every file passes the
> engine's secret-content scan.

## Layout

```
fixtures/assessments/<environment>/
  evidence-manifest.json               manifest with SHA-256 and size of every evidence file
  evidence/<module>/<datasetName>.json one evidence envelope per dataset
```

Each directory is an extracted evidence package. You can load it with `readDirectoryPackage` and
`loadEvidenceBundle`, or use `assessDirectory` from `@adminsecops/engine`. You can also zip a directory
and upload it like a real collector package.

## Environments

| Directory          | Assessed at (UTC)  | Modules                                               | Datasets |
| ------------------ | ------------------ | ----------------------------------------------------- | -------- |
| `contoso`          | 2026-08-10 10:05   | Entra, M365, Exchange, Intune, Azure, AD, ADCS, GPO, Windows | all 55   |
| `contoso-followup` | 2026-09-09 09:40   | same as `contoso`                                     | all 55   |
| `fabrikam`         | 2026-09-05 14:20   | AD, ADCS, GPO, Windows (cloud modules not run)       | 15       |

### Contoso: initial assessment (`contoso`)

Contoso is a hybrid organisation with about 500 users (tenant `Contoso`; domains `contoso.example`,
`mail.contoso.example` and `contoso.onmicrosoft.com`; AD forest `corp.contoso.example`, NetBIOS
`CONTOSO`). It is **partly secured**: some controls are in place, and there are realistic gaps. The
data is designed so that, as the control library grows, its results cover every control outcome:
PASS, FAIL, REVIEW, NOT_APPLICABLE (for example, Defender for Office 365 controls) and NOT_ASSESSED
(for example, domain controller settings and soft-match blocking).

**Collection states demonstrated**

| Dataset                           | Status        | Why                                                                                              |
| --------------------------------- | ------------- | ------------------------------------------------------------------------------------------------ |
| `entra.onPremisesSynchronization` | Unauthorized  | The collecting account is a Global Reader. This API requires Global Administrator or Hybrid Identity Administrator. |
| `entra.servicePrincipals`         | Partial       | Graph paging failed on page 3 (HTTP 503), so the listing is incomplete.                         |
| `exchange.atpPolicy`              | NotApplicable | There is no Defender for Office 365 licence (`data` is null).                                    |
| `ad.domainControllerSettings`     | NotCollected  | The optional `-IncludeDomainControllerSettings` switch was not used (`data` is null).            |

Because of these datasets, the Entra module is reported as `CompletedWithErrors`.

**Intentional configuration (strengths and weaknesses)**

- **Entra ID, authentication:** Security defaults are off.
  - `CA001 - Require MFA for all users` exists but is only **report-only**.
  - `CA002 - Require MFA for administrators` is enabled, but it is missing Application, Authentication, Billing, Cloud Application, Helpdesk, Password and Privileged Authentication Administrator.
  - `CA003` blocks legacy authentication (enabled).
  - No policy requires phishing-resistant MFA for admins, and no policy blocks device code flow.
  - A disabled device-compliance pilot policy and an enabled location block policy (narrowed by named location) are also present.
  - The SMS authentication method is enabled for all users (voice is disabled). Around 9% of users have not registered for MFA.
- **Entra ID, privileged access:**
  - There are 6 Global Administrators: 2 emergency-access accounts, 3 cloud-only admin accounts, and **Jordan IT, a user synchronised from AD**.
  - Several highly privileged roles are held as permanent active assignments. PIM eligibility exists for a few roles, and one SharePoint Administrator activation is in progress.
  - Exchange Administrator `adm-riley` has **no MFA method registered**.
  - A service principal holds User Administrator.
- **Entra ID, applications and guests:**
  - Users can register applications, and user consent uses the legacy "allow all" policy (`microsoft-user-default-legacy`).
  - Guest invitations are allowed from `everyone`.
  - Stale guests: sign-ins older than 90, 180 and 365 days, plus pending invitations more than 180 days old.
  - `Contoso HR Connector` has a **2-year client secret**, and `Legacy Reporting Tool` has an expired secret.
  - `Contoso Identity Automation` holds the Graph application permission **RoleManagement.ReadWrite.Directory**.
  - `Contoso Mail Archiver` holds Exchange `full_access_as_app`.
- **Hybrid:**
  - Directory synchronisation is healthy (last sync 23 minutes before collection) with password hash sync.
  - On-premises Entra Password Protection runs in **Audit** mode.
  - Soft-match blocking cannot be assessed because that dataset is Unauthorized. The follow-up assessment shows it is **not blocked**.
- **Exchange Online and Microsoft 365:**
  - The unified audit log and mailbox auditing are on.
  - SMTP AUTH is disabled organisation-wide, but **two mailboxes explicitly re-enable it**.
  - The custom outbound spam policy "Executive Assistants - Allow Forwarding" sets `AutoForwardingMode On`.
  - Mailbox `robin.sales@contoso.example` **forwards to `personal-mail.example`**.
  - DKIM is enabled for `contoso.example` but **not for `mail.contoso.example`**.
  - SPF is `~all` for `contoso.example` and **missing** for `mail.contoso.example`.
  - DMARC is **`p=none`**.
  - SharePoint allows **Anyone links** (`externalUserAndGuestSharing`).
- **Intune:**
  - Licensed, with 368 Windows and 64 iOS devices enrolled.
  - `secureByDefault` is **false**.
  - The only compliance policy is for Windows (BitLocker required). **iOS has no compliance policy.**
- **Azure (2 subscriptions):**
  - Production has **5 Owners**, including a **guest**.
  - Defender for Cloud is mostly **Free**; only Servers P1 is enabled on production.
  - Storage accounts: `stcontosowebprod` has `allowBlobPublicAccess: true`, and `stcontosodevdata` has it unset (`null`) and uses **TLS 1.0**.
  - `kv-contoso-dev` has **no purge protection**.
  - `nsg-mgmt-prod` **allows 3389 from Internet**.
  - The activity log is exported for production only.
  - Security contacts are configured for production only.
- **Active Directory:**
  - Password policy: minimum password length **8**, and lockout threshold **0** (no lockout).
  - The KRBTGT password is **400 days** old.
  - `svc-legacyapp` has **pre-authentication disabled**.
  - Domain Admin `svc-backup` **has an SPN**, and non-privileged `svc-sql` has SPNs.
  - `PRINT01` has **unconstrained delegation**.
  - `MachineAccountQuota` is **10**. The recycle bin is enabled, and the domain and forest functional levels are 2016.
  - About **60%** of non-DC computers have LAPS.
  - `LEGACY01` runs **Windows Server 2012 R2**. The DCs run 2019 and 2022.
  - There is an external trust to `legacy.northwind.example` **without SID filtering (quarantine)**.
- **AD CS:**
  - `Contoso Issuing CA 01` publishes `ContosoWebClientLegacy`, an **ESC1** template: the enrollee supplies the subject, it has the Client Authentication EKU, Domain Users can enroll, and no approval is required.
  - It also publishes safe templates: `User`, `ContosoVPNUser`, and `WebServer` (admins only).
- **Group Policy:**
  - A GPP `Groups.xml` with a `cpassword` attribute was found. **Only its path is recorded.**
  - The GPO "Old - Test Policy" is **unlinked**.
  - "CONTOSO - Server Baseline" sets **LmCompatibilityLevel 3**.
- **Windows host (`APP01`):**
  - SMBv1 is disabled.
  - The **Domain firewall profile is disabled**.
  - RDP is enabled, with NLA.
  - **RunAsPPL is not configured**, and WDigest is not set (`null`).
  - Defender real-time protection is on.
  - **Script block logging is off**, and **Credential Guard is not running**.

### Contoso: follow-up (`contoso-followup`)

The same tenant about 30 days later, after partial remediation. It has a different `assessmentId`.
Use it to demonstrate comparison and drift.

- **Fixed:**
  - CA001 is switched to On. This enforces MFA for all users and therefore every admin role.
  - User consent is restricted to low-risk permissions from verified publishers.
  - `adm-riley` registered MFA.
  - The external mailbox forward was removed.
  - One SMTP AUTH exception was removed.
  - Public blob access was disabled on `stcontosowebprod`.
  - The Internet RDP NSG rule was removed.
  - The KRBTGT password was reset.
  - Manager approval is now required on the ESC1 template.
- **New issue:** The legacy authentication block policy (CA003) was switched to **report-only**
  while a line-of-business application was being troubleshot.
- **Newly collected:** `entra.onPremisesSynchronization` is now `Success`, because the collecting
  account was granted Hybrid Identity Administrator. It shows soft-match blocking disabled. The
  service principal listing also completed this time, so the Entra module is `Completed`.

Everything else is unchanged. Activity timestamps (last sign-in and last logon) move with the
assessment date, so stale objects become about 30 days staler.

### Fabrikam (`fabrikam`)

Fabrikam is a small on-premises-only organisation (`corp.fabrikam.example`, NetBIOS `FABRIKAM`,
around 60 users). Only the AD, ADCS, GPO and Windows modules were run. The Entra, Microsoft 365
and Azure modules were not run, and `environment.tenantId` is `null`. Cloud controls are therefore
NOT_ASSESSED.

Fabrikam is mostly well configured:

- The minimum password length is 14 and lockout is enabled.
- The KRBTGT password was reset about 90 days ago.
- `MachineAccountQuota` is 0.
- LAPS is on every member computer.
- The admin account is in Protected Users.
- DC LDAP signing and channel binding are enforced (DC settings were collected).
- There are no trusts and no GPP passwords.

It has two intentional issues:

- **ESC4:** Template `FabrikamWorkstationAuth` grants Authenticated Users `WriteProperty` and `WriteDacl`.
- **SMBv1:** SMBv1 is enabled on `FAB-FS01`.

## Regenerating

The fixtures are generated from TypeScript sources in `scripts/fixtures/`. The environment data is
typed with each dataset schema's input type and validated with the real schemas at build time.

```
npm run fixtures        # or: npx tsx scripts/build-fixtures.ts
```

The output is byte-for-byte deterministic:

- It uses fixed timestamps and seeded GUIDs.
- It uses stable key order.
- Files use LF line endings and end with a trailing newline.
- The SHA-256 values in the manifest are computed from the exact bytes written.

The build fails loudly in any of these cases:

- A payload does not parse with its dataset schema.
- An envelope or manifest is invalid.
- A file contains secret-like content.
- Contoso does not cover every dataset registered in the engine.

`tests/fixtures.test.ts` regenerates the packages in memory and compares them with the committed
files. It also checks the following:

- Integrity is verified.
- There is no sensitive content.
- Every usable dataset passes schema validation.
- `runAssessment` with the full control library produces no `ERROR` results.
- Comparing `contoso` with `contoso-followup` reports both resolved and new findings.

After you change a dataset schema or the fixture sources, run `npm run fixtures` and commit the
regenerated JSON. Do not edit the JSON files by hand: the manifest hashes would no longer match.
