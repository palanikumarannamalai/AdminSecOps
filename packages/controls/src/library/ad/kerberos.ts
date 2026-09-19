import { daysSince } from '@adminsecops/inventory';
import { defineControl } from '../../define.js';
import { affected, eqi, fact, fail, notAssessed, pass, plural, review } from '../../helpers.js';
import { AD_REF } from './references.js';
import {
  disabledNote,
  isKrbtgtAccount,
  isPrivileged,
  optionalPrivilegedSids,
  privilegedBySid,
  qualifiedName,
  PRIVILEGED_UNAVAILABLE_NOTE,
  userObject,
  type AdUser,
} from './shared.js';

function passwordAgeDetail(user: AdUser, at: Date): string {
  const age = daysSince(user.pwdLastSet, at);
  const agePart = age === null ? 'password age unknown' : `password last set ${age} days ago`;
  return `${agePart}${user.passwordNeverExpires ? ', password never expires' : ''}`;
}

export const adKrbtgtPasswordAge = defineControl({
  id: 'AD-KRB-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'KRBTGT account password has been changed within the last 180 days',
  technology: 'ad',
  category: 'Kerberos',
  subcategory: 'KRBTGT',
  description:
    'Checks that the password of the KRBTGT account in every domain was changed within the configured number of days (default 180), using the pwdLastSet timestamp only.',
  rationale:
    'Every Kerberos ticket-granting ticket in a domain is protected with keys derived from the KRBTGT password. If those keys were ever exposed (for example in a past compromise or through a stolen backup of a domain controller), an attacker can forge tickets for any account ("golden tickets") for as long as the password is unchanged. Regular rotation limits how long stolen KRBTGT keys stay useful. Microsoft Defender for Identity flags KRBTGT passwords older than 180 days.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Every Active Directory domain in the collected forest.' },
  requiredEvidence: ['ad.krbtgt'],
  optionalEvidence: ['ad.domains'],
  evaluation: {
    logic:
      'For each domain in ad.krbtgt: FAIL when pwdLastSet is older than maxPasswordAgeDays at the assessment date; REVIEW when pwdLastSet is unknown. When ad.domains is available, domains that have no KRBTGT entry are reported as REVIEW. PASS when every domain rotated the password within the limit. Only the timestamp is read, never the password.',
    parameters: { maxPasswordAgeDays: 180 },
  },
  expectedState: 'The KRBTGT password in every domain was changed within the last 180 days (reset twice when responding to a compromise).',
  remediation: {
    summary: 'Reset the KRBTGT password in each affected domain using the Microsoft-documented procedure, allowing replication (and ticket lifetime) to complete between resets.',
    steps: [
      'Confirm that Active Directory replication is healthy in the domain (repadmin /replsummary) before starting; a reset during broken replication causes authentication failures.',
      'Follow the Microsoft procedure "Reset the krbtgt password" for the affected domain. For routine rotation, reset the password once; to invalidate potentially forged tickets after a compromise, reset it twice.',
      'When resetting twice, wait at least the maximum user ticket lifetime (10 hours by default) and confirm replication between the two resets so existing legitimate tickets remain valid.',
      'Read-only domain controllers have their own krbtgt_<number> accounts; rotate those as part of the same maintenance where applicable.',
      'Schedule the rotation (for example every 180 days) and record the date.',
    ],
    scriptExample: [
      '# Review the Microsoft procedure first; run as a Domain Admin. AdminSecOps never runs this.',
      '# Check replication health and the current password age:',
      'repadmin /replsummary',
      "Get-ADUser -Identity krbtgt -Properties PasswordLastSet -Server contoso.com | Select-Object Name, PasswordLastSet",
      '# The reset itself is performed through Active Directory Users and Computers (Reset Password on the krbtgt account)',
      '# or with a reviewed script that follows the documented procedure; the password value is ignored by the KDC.',
    ].join('\n'),
    effort: 'medium',
  },
  implementationConsiderations: [
    'A single reset is safe when replication is healthy: domain controllers accept tickets protected by both the current and the previous KRBTGT key.',
    'Resetting twice in quick succession invalidates all existing tickets and can interrupt services; only do so deliberately (incident response) and follow the documented wait period.',
    'Applications or devices that cache Kerberos tickets for long periods may need to re-authenticate after a double reset.',
  ],
  impact: 'Routine single resets have no user impact when replication is healthy. A double reset forces all users and services to obtain new tickets.',
  rollback: [
    'A KRBTGT password change cannot be reverted. If authentication problems appear, verify replication, then let clients obtain new tickets (klist purge or sign out and in).',
  ],
  validation: [
    "Run Get-ADUser krbtgt -Properties PasswordLastSet in each domain and confirm the date is recent.",
    'Monitor domain controller System and Security logs for Kerberos errors after the reset.',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-KRB-001 is PASS.',
  ],
  references: [AD_REF.krbtgtReset, AD_REF.mdiKrbtgt, AD_REF.attackGoldenTicket],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5' },
    { framework: 'NIST-800-53r5', id: 'SC-12' },
    { framework: 'MITRE-ATTACK', id: 'T1558.001' },
  ],
  tags: ['kerberos', 'krbtgt', 'credential-exposure', 'active-directory'],
  evaluate: (ctx) => {
    const maxAge = ctx.num('maxPasswordAgeDays');
    const entries = ctx.data('ad.krbtgt');
    const domainsFact = ctx.fact('ad.domains');
    const missingDomains = domainsFact.available
      ? domainsFact.data.filter((d) => !entries.some((e) => eqi(e.domain, d.dnsRoot) || eqi(e.domain, d.netBIOSName)))
      : [];
    if (entries.length === 0 && missingDomains.length === 0) {
      return notAssessed({
        reason: 'The KRBTGT dataset contains no domains, so the password age could not be evaluated.',
        summary: 'No KRBTGT account information was returned.',
      });
    }
    const aged = entries.map((e) => ({ entry: e, age: daysSince(e.pwdLastSet, ctx.assessedAt) }));
    const stale = aged.filter((a) => a.age !== null && a.age > maxAge);
    const unknown = aged.filter((a) => a.age === null);
    const facts = [
      fact('Domains evaluated', entries.length),
      fact('Maximum password age (days)', maxAge),
      fact('Domains with an older KRBTGT password', stale.length),
      fact('Domains with unknown KRBTGT password age', unknown.length + missingDomains.length),
    ];
    const affectedObjects = [
      ...stale.map((a) => affected('adUser', qualifiedName(a.entry.domain, 'krbtgt'), qualifiedName(a.entry.domain, 'krbtgt'), `Password last set ${a.age} days ago (${a.entry.pwdLastSet})`)),
      ...unknown.map((a) => affected('adUser', qualifiedName(a.entry.domain, 'krbtgt'), qualifiedName(a.entry.domain, 'krbtgt'), 'pwdLastSet could not be read')),
      ...missingDomains.map((d) => affected('adDomain', d.dnsRoot, d.dnsRoot, 'No KRBTGT information was collected for this domain')),
    ];
    if (stale.length > 0) {
      return fail({
        reason: `The KRBTGT password is older than ${maxAge} days in ${plural(stale.length, 'domain')}.`,
        summary: stale.map((a) => `${a.entry.domain}: ${a.age} days`).join('; '),
        facts,
        affectedObjects,
      });
    }
    if (unknown.length > 0 || missingDomains.length > 0) {
      return review({
        reason: 'The KRBTGT password age could not be determined for every domain; it cannot be confirmed as recently rotated.',
        summary: `${plural(unknown.length + missingDomains.length, 'domain')} without a readable KRBTGT password date.`,
        facts,
        affectedObjects,
      });
    }
    return pass({
      reason: `The KRBTGT password was changed within the last ${maxAge} days in every domain.`,
      summary: aged.map((a) => `${a.entry.domain}: ${a.age} days`).join('; '),
      facts,
    });
  },
});

export const adKrbPreauthDisabled = defineControl({
  id: 'AD-KRB-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'No enabled accounts have Kerberos pre-authentication disabled',
  technology: 'ad',
  category: 'Kerberos',
  subcategory: 'Account settings',
  description:
    'Finds enabled user accounts with the "Do not require Kerberos preauthentication" option (DONT_REQ_PREAUTH) set, in every domain.',
  rationale:
    'Pre-authentication proves knowledge of the password before a domain controller issues a ticket. When it is disabled, anyone on the network can request authentication data for the account that is encrypted with a key derived from its password and try to crack it offline without ever triggering lockout (AS-REP roasting). Weak or old passwords on these accounts are recovered quickly.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Every Active Directory domain in the collected forest.' },
  requiredEvidence: ['ad.users'],
  optionalEvidence: ['ad.privilegedGroups'],
  evaluation: {
    logic:
      'FAIL when any enabled user account has doesNotRequirePreAuth = true; affected accounts are listed with their domain, and privileged accounts are highlighted when privileged group evidence is available. Disabled accounts with the flag are reported in a note only. PASS when no enabled account has the flag.',
    parameters: {},
  },
  expectedState: 'Kerberos pre-authentication is required for every enabled account.',
  remediation: {
    summary: 'Clear "Do not require Kerberos preauthentication" on each listed account and change the password of any account that had it set.',
    steps: [
      'For each account, identify the owner and why pre-authentication was disabled (usually a very old UNIX/MIT Kerberos integration or an application that no longer exists).',
      'In Active Directory Users and Computers, open the account > Account tab > Account options and clear "Do not require Kerberos preauthentication".',
      'Change the password of each affected account to a long random value, because its previous password may already have been captured and cracked offline.',
      'Test the dependent application; modern Kerberos clients perform pre-authentication automatically.',
    ],
    scriptExample: [
      '# Review, then run as an account administrator. AdminSecOps never runs this.',
      'Get-ADUser -Filter "DoesNotRequirePreAuth -eq $true -and Enabled -eq $true" -Properties DoesNotRequirePreAuth | Select-Object SamAccountName',
      "Set-ADAccountControl -Identity 'svc-legacy' -DoesNotRequirePreAuth $false",
    ].join('\n'),
    effort: 'low',
  },
  implementationConsiderations: [
    'Very old non-Windows Kerberos clients may fail to authenticate after the change; test with the application owner.',
    'Changing the password of a service account requires updating it wherever the service is configured.',
  ],
  impact: 'Accounts must pre-authenticate; the only visible effect is on legacy clients that cannot, which then fail to authenticate.',
  rollback: ['Re-enable the option on the specific account with Set-ADAccountControl -DoesNotRequirePreAuth $true (only if an application demonstrably requires it).'],
  validation: [
    'Run Get-ADUser -Filter "DoesNotRequirePreAuth -eq $true" in each domain and confirm no enabled accounts are returned.',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-KRB-002 is PASS.',
  ],
  references: [AD_REF.mdiUnsecureAccountAttributes, AD_REF.userAccountControlFlags, AD_REF.attackAsRepRoasting],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-2' },
    { framework: 'NIST-800-53r5', id: 'CM-6' },
    { framework: 'MCSB', id: 'IM-8' },
    { framework: 'MITRE-ATTACK', id: 'T1558.004' },
  ],
  tags: ['kerberos', 'credential-exposure', 'account-settings', 'active-directory'],
  evaluate: (ctx) => {
    const { users } = ctx.data('ad.users');
    const privileged = optionalPrivilegedSids(ctx);
    const flagged = users.filter((u) => u.doesNotRequirePreAuth);
    const enabled = flagged.filter((u) => u.enabled);
    const disabled = flagged.filter((u) => !u.enabled);
    const privilegedCount = privileged === null ? null : enabled.filter((u) => privileged.has(u.sid.toUpperCase())).length;
    const facts = [
      fact('Accounts evaluated', users.length),
      fact('Enabled accounts without pre-authentication', enabled.length),
      fact('Of which privileged', privilegedCount),
      fact('Disabled accounts without pre-authentication', disabled.length),
    ];
    const notes = [...disabledNote(disabled, 'Kerberos pre-authentication disabled'), ...(privileged === null ? [PRIVILEGED_UNAVAILABLE_NOTE] : [])];
    if (enabled.length > 0) {
      return fail({
        reason: `${plural(enabled.length, 'enabled account')} do not require Kerberos pre-authentication.`,
        summary: `Accounts in ${[...new Set(enabled.map((u) => u.domain))].join(', ')} can be targeted for offline password cracking without authenticating.`,
        facts,
        affectedObjects: enabled.map((u) =>
          userObject(u, `Pre-authentication disabled${privileged?.has(u.sid.toUpperCase()) ? '; PRIVILEGED account' : ''}; ${passwordAgeDetail(u, ctx.assessedAt)}`),
        ),
        notes,
      });
    }
    return pass({
      reason: 'No enabled account has Kerberos pre-authentication disabled.',
      summary: `${plural(users.length, 'collected account')} checked.`,
      facts,
      notes,
    });
  },
});

export const adKrbPrivilegedSpn = defineControl({
  id: 'AD-KRB-003',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'No privileged user accounts have service principal names',
  technology: 'ad',
  category: 'Kerberos',
  subcategory: 'Service accounts',
  description:
    'Finds enabled user accounts that are (recursively) members of privileged built-in groups such as Domain Admins, Enterprise Admins or Administrators and also have one or more service principal names (SPNs).',
  rationale:
    'Any authenticated user can request a Kerberos service ticket for an account that has an SPN. Part of that ticket is encrypted with a key derived from the account password and can be cracked offline (Kerberoasting) without lockout or alerts on the target. When the account is privileged, cracking its password gives an attacker control of the domain. Microsoft Defender for Identity recommends removing SPNs from sensitive accounts.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Every Active Directory domain in the collected forest.' },
  requiredEvidence: ['ad.users', 'ad.privilegedGroups'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'Privileged accounts are the members (recursive, by SID) of the privileged built-in groups defined in the inventory (Domain Admins, Schema Admins, Enterprise Admins, Key Admins, Enterprise Key Admins, Administrators, Account/Server/Print/Backup Operators). FAIL when any enabled privileged user account has servicePrincipalNameCount > 0 (KRBTGT is excluded). Disabled privileged accounts with SPNs and accounts with adminCount=1 that are no longer in a privileged group are reported in notes. PASS otherwise.',
    parameters: {},
  },
  expectedState: 'Privileged accounts have no SPNs; services run under dedicated non-privileged accounts, preferably group managed service accounts.',
  remediation: {
    summary: 'Move the service off the privileged account (preferably to a gMSA with only the rights it needs), then remove the SPNs from the privileged account and change its password.',
    steps: [
      'List the SPNs on each account (setspn -L <account>) and identify the service that uses them.',
      'Create a group managed service account (gMSA) or dedicated low-privileged service account, grant only the permissions the service actually needs, and reconfigure the service to use it.',
      'Move the SPNs to the new account (setspn -D from the old account, setspn -S on the new one) so Kerberos keeps working.',
      'If the privileged account is an administrator\'s personal account, simply remove the SPNs.',
      'Change the password of the privileged account to a long random value because its current password may already have been captured.',
      'Consider adding remaining privileged user accounts to the Protected Users group (see AD-PRIV-001).',
    ],
    scriptExample: [
      '# Review, then run as a Domain Admin. AdminSecOps never runs this.',
      'setspn -L svc-sql-admin',
      '# After the service has moved to a gMSA:',
      'setspn -D MSSQLSvc/sql01.contoso.com:1433 svc-sql-admin',
      'setspn -S MSSQLSvc/sql01.contoso.com:1433 CONTOSO\\gmsa-sql01$',
    ].join('\n'),
    effort: 'medium',
  },
  implementationConsiderations: [
    'Removing an SPN that a service still uses breaks Kerberos authentication to that service (clients may fall back to NTLM or fail). Move the SPN to the new account in the same change window.',
    'Many services run as privileged accounts only out of convenience; reducing their rights can surface missing permissions, so test with the application owner.',
    'gMSAs require a KDS root key in the domain and a Windows Server 2012 or later domain controller.',
  ],
  impact: 'The service identity changes; clients continue to use Kerberos once the SPN is registered on the new account.',
  rollback: [
    'Re-register the SPN on the original account (setspn -S) and switch the service back to it.',
  ],
  validation: [
    'Run setspn -L for each affected account and confirm no SPNs remain.',
    'Confirm the service authenticates with Kerberos (klist on a client shows a ticket for the SPN).',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-KRB-003 is PASS.',
  ],
  references: [AD_REF.mdiUnsecureAccountAttributes, AD_REF.gmsaOverview, AD_REF.privilegedGroupsAppendixB, AD_REF.attackKerberoasting],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-6(5)' },
    { framework: 'NIST-800-53r5', id: 'IA-5' },
    { framework: 'MCSB', id: 'PA-1' },
    { framework: 'MITRE-ATTACK', id: 'T1558.003' },
  ],
  tags: ['kerberos', 'privileged-access', 'credential-exposure', 'service-accounts', 'active-directory'],
  evaluate: (ctx) => {
    const { users } = ctx.data('ad.users');
    const privileged = privilegedBySid(ctx);
    const withSpn = users.filter((u) => u.servicePrincipalNameCount > 0 && !isKrbtgtAccount(u));
    const privWithSpn = withSpn.filter((u) => isPrivileged(privileged, u.sid) !== undefined);
    const enabled = privWithSpn.filter((u) => u.enabled);
    const disabled = privWithSpn.filter((u) => !u.enabled);
    const staleAdminCount = withSpn.filter((u) => u.enabled && u.adminCount && isPrivileged(privileged, u.sid) === undefined);
    const facts = [
      fact('Privileged accounts (all object types)', privileged.size),
      fact('Enabled privileged user accounts with SPNs', enabled.length),
      fact('Disabled privileged user accounts with SPNs', disabled.length),
    ];
    const notes = [
      ...disabledNote(disabled, 'SPNs while being privileged'),
      ...(staleAdminCount.length > 0
        ? [
            `${plural(staleAdminCount.length, 'account')} with SPNs have adminCount=1 but are not currently in a privileged group (${staleAdminCount
              .slice(0, 10)
              .map((u) => qualifiedName(u.domain, u.samAccountName))
              .join(', ')}). They were privileged in the past; confirm they no longer hold administrative rights and review them under AD-KRB-004.`,
          ]
        : []),
    ];
    if (enabled.length > 0) {
      return fail({
        reason: `${plural(enabled.length, 'enabled privileged account')} have service principal names and can be targeted by Kerberoasting.`,
        summary: enabled.map((u) => qualifiedName(u.domain, u.samAccountName)).join(', '),
        facts,
        affectedObjects: enabled.map((u) => {
          const account = isPrivileged(privileged, u.sid);
          return userObject(
            u,
            `${plural(u.servicePrincipalNameCount, 'SPN')}; member of ${account?.groups.join(', ') ?? 'a privileged group'}; ${passwordAgeDetail(u, ctx.assessedAt)}`,
          );
        }),
        notes,
      });
    }
    return pass({
      reason: 'No enabled privileged user account has a service principal name.',
      summary: `${plural(privileged.size, 'privileged account')} checked.`,
      facts,
      notes,
    });
  },
});

export const adKrbUserSpn = defineControl({
  id: 'AD-KRB-004',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'User-based service accounts with SPNs are reviewed (prefer gMSA)',
  technology: 'ad',
  category: 'Kerberos',
  subcategory: 'Service accounts',
  description:
    'Lists enabled, non-privileged user accounts that have service principal names (SPNs). These are services running under ordinary user accounts whose password strength and rotation depend on administrators.',
  rationale:
    'Any authenticated user can request a service ticket for an SPN and try to crack the service account password offline (Kerberoasting). A user-based service account is only as safe as its password: human-chosen or never-changed passwords are commonly cracked, and service accounts often hold more rights than their group membership suggests (local administrator on servers, database owner). Group managed service accounts (gMSA) use long random passwords rotated automatically and remove this risk.',
  severity: 'medium',
  confidence: 'medium',
  applicability: { description: 'Every Active Directory domain in the collected forest.' },
  requiredEvidence: ['ad.users', 'ad.privilegedGroups'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'REVIEW when any enabled user account that is not a member of a privileged built-in group has servicePrincipalNameCount > 0 (KRBTGT excluded; privileged accounts are covered by AD-KRB-003). Each account is listed with its password age and "password never expires" flag so the oldest can be prioritised. PASS when no such account exists. The result is REVIEW rather than FAIL because an SPN on a user account is a legitimate configuration when the password is long, random and rotated, which cannot be verified from directory metadata.',
    parameters: {},
  },
  expectedState: 'Services use group managed service accounts; any remaining user-based service accounts have long random passwords (25+ characters), AES-only Kerberos encryption and only the rights they need.',
  remediation: {
    summary: 'Migrate services to group managed service accounts where supported; otherwise give each remaining service account a long random password, rotate it, and restrict its rights.',
    steps: [
      'For each listed account, identify the service and host (setspn -L <account>) and the application owner.',
      'If the application supports gMSA (Windows services, IIS application pools, scheduled tasks, SQL Server), create a gMSA (New-ADServiceAccount), allow the host(s) to retrieve its password, install it on the host and reconfigure the service. Move the SPNs to the gMSA.',
      'If the application cannot use a gMSA, set a random password of at least 25 characters, store it in your privileged password vault and rotate it on a schedule.',
      'Enable AES encryption for the account ("This account supports Kerberos AES 256 bit encryption") so tickets are not issued with RC4, which is much faster to crack.',
      'Remove unnecessary rights (local administrator, broad file or database rights) and disable accounts whose service no longer exists.',
    ],
    scriptExample: [
      '# Review, then run as a Domain Admin. AdminSecOps never runs this.',
      '# One-time per domain if no KDS root key exists yet (takes effect after replication):',
      '# Add-KdsRootKey -EffectiveImmediately',
      "New-ADServiceAccount -Name gmsa-web01 -DNSHostName gmsa-web01.contoso.com -PrincipalsAllowedToRetrieveManagedPassword 'WEB01$'",
      '# On WEB01: Install-ADServiceAccount gmsa-web01 ; then set the service logon account to CONTOSO\\gmsa-web01$',
      '# For accounts that must remain user accounts, enforce AES:',
      "Set-ADUser -Identity svc-app -KerberosEncryptionType AES128,AES256",
    ].join('\n'),
    effort: 'high',
  },
  implementationConsiderations: [
    'Changing a service account password or identity requires updating every place the service is configured; plan a maintenance window per application.',
    'Not every product supports gMSA; check vendor documentation. Standalone managed service accounts (sMSA) are an option for single-server services.',
    'Restricting an account to AES encryption can break very old clients or applications that only support RC4; test first.',
    'Some SPNs are left behind on user accounts by old installations; if the service no longer exists, remove the SPN or disable the account instead.',
  ],
  impact: 'Services move to automatically managed credentials; brief service restarts are needed during migration.',
  rollback: ['Switch the service back to the previous account and move the SPNs back with setspn.'],
  validation: [
    'Run Get-ADUser -Filter "ServicePrincipalName -like \'*\'" -Properties ServicePrincipalName and confirm only reviewed accounts remain.',
    'Confirm migrated services run as gMSAs (Get-ADServiceAccount) and authenticate successfully.',
    'Re-run the AdminSecOps Active Directory collector and review AD-KRB-004.',
  ],
  references: [AD_REF.gmsaOverview, AD_REF.mdiUnsecureAccountAttributes, AD_REF.attackKerberoasting],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5' },
    { framework: 'NIST-800-53r5', id: 'AC-2' },
    { framework: 'MCSB', id: 'IM-8' },
    { framework: 'MITRE-ATTACK', id: 'T1558.003' },
  ],
  tags: ['kerberos', 'service-accounts', 'credential-exposure', 'active-directory'],
  evaluate: (ctx) => {
    const { users } = ctx.data('ad.users');
    const privileged = privilegedBySid(ctx);
    const candidates = users.filter(
      (u) => u.enabled && u.servicePrincipalNameCount > 0 && !isKrbtgtAccount(u) && isPrivileged(privileged, u.sid) === undefined,
    );
    const neverExpires = candidates.filter((u) => u.passwordNeverExpires).length;
    const facts = [
      fact('Enabled non-privileged user accounts with SPNs', candidates.length),
      fact('Of which password never expires', neverExpires),
    ];
    if (candidates.length > 0) {
      const sorted = [...candidates].sort(
        (a, b) => (daysSince(b.pwdLastSet, ctx.assessedAt) ?? Number.MAX_SAFE_INTEGER) - (daysSince(a.pwdLastSet, ctx.assessedAt) ?? Number.MAX_SAFE_INTEGER),
      );
      return review({
        reason: `${plural(candidates.length, 'enabled user account')} run services with SPNs; their passwords can be attacked offline and should be long, random and rotated, or replaced by gMSAs.`,
        summary: `User-based service accounts found in ${[...new Set(candidates.map((u) => u.domain))].join(', ')}.`,
        facts,
        affectedObjects: sorted.map((u) => userObject(u, `${plural(u.servicePrincipalNameCount, 'SPN')}; ${passwordAgeDetail(u, ctx.assessedAt)}`)),
      });
    }
    return pass({
      reason: 'No enabled non-privileged user account has a service principal name.',
      summary: 'No user-based service accounts with SPNs were found.',
      facts,
    });
  },
});
