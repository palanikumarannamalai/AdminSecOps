import { functionalLevelRank } from '@adminsecops/inventory';
import { defineControl } from '../../define.js';
import { affected, fact, fail, pass, plural, review } from '../../helpers.js';
import { AD_REF } from './references.js';
import { computerObject, disabledNote, privilegedBySid, qualifiedName, userObject, type AdUser } from './shared.js';

const USER_CLASSES = new Set(['user', 'inetorgperson']);

export const adUnconstrainedDelegation = defineControl({
  id: 'AD-DEL-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'No unconstrained Kerberos delegation outside domain controllers',
  technology: 'ad',
  category: 'Kerberos',
  subcategory: 'Delegation',
  description:
    'Finds enabled computer accounts that are not domain controllers, and enabled user accounts, that are trusted for unconstrained Kerberos delegation (TRUSTED_FOR_DELEGATION).',
  rationale:
    'A service trusted for unconstrained delegation receives a reusable copy of the Kerberos ticket-granting ticket of every user who authenticates to it. Anyone who controls that server or service account can impersonate those users, including administrators, to any service in the forest. Attackers also coerce domain controllers into authenticating to such hosts to obtain domain controller tickets. Domain controllers need this setting by design; no other account should have it.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Every Active Directory domain in the collected forest.' },
  requiredEvidence: ['ad.computers', 'ad.users'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'FAIL when any enabled computer account with isDomainController = false (primary group is not 516 Domain Controllers or 521 Read-only Domain Controllers) has trustedForDelegation = true, or any enabled user account has trustedForDelegation = true. Disabled accounts with the flag are noted. Accounts configured for constrained delegation with protocol transition are counted in a note but do not fail this control. PASS otherwise.',
    parameters: {},
  },
  expectedState: 'Only domain controllers are trusted for unconstrained delegation; services that need delegation use constrained or resource-based constrained delegation.',
  remediation: {
    summary: 'Replace unconstrained delegation with Kerberos constrained delegation (or resource-based constrained delegation) limited to the specific back-end services, or remove delegation entirely.',
    steps: [
      'For each listed account, ask the application owner which back-end services (for example SQL Server, file shares, HTTP) it must access on behalf of users. Many settings are left over from old installations and are no longer needed.',
      'In Active Directory Users and Computers, open the account > Delegation tab and select "Trust this computer for delegation to specified services only", then add only the required services. Or configure resource-based constrained delegation on the back-end account with Set-ADComputer -PrincipalsAllowedToDelegateToAccount.',
      'If no delegation is needed, select "Do not trust this computer for delegation".',
      'Protect privileged accounts from delegation meanwhile (see AD-PRIV-001), so their tickets are never forwarded even if a host keeps delegation temporarily.',
    ],
    scriptExample: [
      '# Review, then run as a Domain Admin. AdminSecOps never runs this.',
      'Get-ADComputer -Filter "TrustedForDelegation -eq $true -and PrimaryGroupID -eq 515" -Properties TrustedForDelegation | Select-Object Name',
      "Set-ADAccountControl -Identity 'APP01$' -TrustedForDelegation $false",
      '# Example resource-based constrained delegation on the back-end server:',
      "Set-ADComputer -Identity SQL01 -PrincipalsAllowedToDelegateToAccount (Get-ADComputer APP01)",
    ].join('\n'),
    effort: 'medium',
  },
  implementationConsiderations: [
    'Applications that rely on unconstrained delegation (double-hop web applications, some print or file workflows) fail to access back-end resources until constrained delegation is configured; test with the owner.',
    'Constrained delegation to services in another domain requires resource-based constrained delegation.',
    'Microsoft Edge and other browsers need additional configuration for Kerberos delegation scenarios; verify end-to-end.',
  ],
  impact: 'The service can no longer impersonate users to arbitrary services; configured constrained delegation keeps required access working.',
  rollback: ['Re-enable "Trust this computer for delegation to any service" on the account (temporary only) while the constrained delegation design is corrected.'],
  validation: [
    'Run Get-ADComputer -Filter "TrustedForDelegation -eq $true" and Get-ADUser -Filter "TrustedForDelegation -eq $true" and confirm only domain controllers are returned.',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-DEL-001 is PASS.',
  ],
  references: [AD_REF.mdiUnsecureDelegation, AD_REF.kerberosConstrainedDelegation, AD_REF.userAccountControlFlags, AD_REF.attackKerberosTickets],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-6' },
    { framework: 'NIST-800-53r5', id: 'CM-6' },
    { framework: 'MCSB', id: 'PA-7' },
    { framework: 'MITRE-ATTACK', id: 'T1558' },
  ],
  tags: ['kerberos', 'delegation', 'privileged-access', 'active-directory'],
  evaluate: (ctx) => {
    const computers = ctx.data('ad.computers');
    const { users } = ctx.data('ad.users');
    const dcCount = computers.filter((c) => c.isDomainController).length;
    const computersFlagged = computers.filter((c) => !c.isDomainController && c.trustedForDelegation);
    const usersFlagged = users.filter((u) => u.trustedForDelegation);
    const enabledComputers = computersFlagged.filter((c) => c.enabled);
    const enabledUsers = usersFlagged.filter((u) => u.enabled);
    const disabledComputers = computersFlagged.filter((c) => !c.enabled);
    const protocolTransition =
      computers.filter((c) => c.enabled && !c.isDomainController && c.trustedToAuthForDelegation).length +
      users.filter((u) => u.enabled && u.trustedToAuthForDelegation).length;
    const facts = [
      fact('Computers evaluated', computers.length),
      fact('Domain controllers (excluded)', dcCount),
      fact('Enabled non-DC computers with unconstrained delegation', enabledComputers.length),
      fact('Enabled user accounts with unconstrained delegation', enabledUsers.length),
      fact('Accounts with constrained delegation and protocol transition', protocolTransition),
    ];
    const notes = [
      ...disabledNote(usersFlagged.filter((u) => !u.enabled), 'unconstrained delegation'),
      ...(disabledComputers.length > 0
        ? [`${plural(disabledComputers.length, 'disabled computer account')} also have unconstrained delegation; clear it or delete the stale objects.`]
        : []),
      ...(protocolTransition > 0
        ? [
            `${plural(protocolTransition, 'account')} use constrained delegation with protocol transition ("use any authentication protocol"). This is safer than unconstrained delegation but still lets the service impersonate users to its listed services; review that those accounts are well protected.`,
          ]
        : []),
    ];
    const total = enabledComputers.length + enabledUsers.length;
    if (total > 0) {
      return fail({
        reason: `${plural(total, 'enabled account')} outside the domain controllers are trusted for unconstrained delegation.`,
        summary: `${plural(enabledComputers.length, 'computer')} and ${plural(enabledUsers.length, 'user account')} can capture and reuse the Kerberos tickets of any user who connects to them.`,
        facts,
        affectedObjects: [
          ...enabledComputers.map((c) => computerObject(c, `Unconstrained delegation on a non-domain-controller computer (${c.operatingSystem ?? 'OS unknown'})`)),
          ...enabledUsers.map((u) => userObject(u, 'Unconstrained delegation on a user (service) account')),
        ],
        notes,
      });
    }
    return pass({
      reason: 'No enabled account other than domain controllers is trusted for unconstrained delegation.',
      summary: `${plural(computers.length, 'computer')} and ${plural(users.length, 'collected user account')} checked.`,
      facts,
      notes,
    });
  },
});

export const adPrivilegedNotDelegated = defineControl({
  id: 'AD-PRIV-001',
  version: '1.1.0',
  lifecycle: 'stable',
  title: 'Privileged accounts are protected from Kerberos delegation',
  technology: 'ad',
  category: 'Privileged access',
  subcategory: 'Credential protection',
  description:
    'Checks that every enabled privileged user account has "Account is sensitive and cannot be delegated" set or is a member of the Protected Users group, so its credentials are never forwarded by a delegating service.',
  rationale:
    'If an administrator authenticates to a server that is trusted for delegation, the server can act as that administrator towards other services. Marking privileged accounts as sensitive (NOT_DELEGATED), or placing them in Protected Users (which also blocks delegation, NTLM, weak Kerberos encryption and credential caching), prevents their identity from being delegated even when a delegation setting elsewhere is abused. Microsoft Defender for Identity recommends this for all privileged accounts.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Every Active Directory domain in the collected forest.' },
  requiredEvidence: ['ad.users', 'ad.privilegedGroups'],
  optionalEvidence: ['ad.domains'],
  evaluation: {
    logic:
      'Privileged accounts are the recursive members of the privileged built-in groups (see AD-KRB-003). For each privileged member whose object class is user or inetOrgPerson: FAIL when the account is enabled and has neither accountNotDelegated = true nor memberOfProtectedUsers = true. Privileged members that are not present in the user evidence produce REVIEW because their settings cannot be read. Protected Users-only protection produces REVIEW unless ad.domains confirms Windows Server 2012 R2 or later functional level for that account domain. Disabled accounts, computers and managed service accounts are skipped (computers and gMSAs are noted). PASS when every enabled privileged user is protected.',
    parameters: {},
  },
  expectedState: 'Every enabled privileged user account has "Account is sensitive and cannot be delegated" set, or is a member of Protected Users.',
  remediation: {
    summary: 'Set "Account is sensitive and cannot be delegated" on every privileged user account, and add administrators\' accounts to the Protected Users group after testing.',
    steps: [
      'In Active Directory Users and Computers, open each listed account > Account tab > Account options, select "Account is sensitive and cannot be delegated" and apply.',
      'For interactive administrator accounts, also consider adding them to the Protected Users group (Users container), starting with one test administrator.',
      'Do not add service accounts or computer accounts to Protected Users: it blocks NTLM, delegation and cached credentials, which services often need.',
      'Keep at least one emergency (break-glass) account outside Protected Users so an administrator can still sign in if Kerberos is unavailable, but still mark it as sensitive.',
    ],
    scriptExample: [
      '# Review, then run as a Domain Admin. AdminSecOps never runs this.',
      "Set-ADAccountControl -Identity 'adm-jsmith' -AccountNotDelegated $true",
      "Add-ADGroupMember -Identity 'Protected Users' -Members 'adm-jsmith'",
    ].join('\n'),
    effort: 'low',
  },
  implementationConsiderations: [
    'Marking an account as sensitive only affects delegation; the account can still sign in normally. Administrative workflows that rely on delegation (for example PowerShell remoting second hop with CredSSP alternatives) may need adjustment.',
    'Protected Users membership changes sign-in behaviour: no NTLM, no DES/RC4 Kerberos, no cached credentials for offline sign-in and a 4-hour ticket lifetime. Test before adding all administrators. The domain controller-side protections require the Windows Server 2012 R2 domain functional level or later.',
    'Accounts that run services must not be placed in Protected Users; use "Account is sensitive and cannot be delegated" instead where the service does not need delegation of its own identity.',
  ],
  impact: 'Privileged credentials can no longer be delegated by any service. Protected Users members additionally lose NTLM and cached sign-in.',
  rollback: [
    "Clear the option with Set-ADAccountControl -Identity <account> -AccountNotDelegated $false.",
    "Remove the account from Protected Users with Remove-ADGroupMember 'Protected Users' -Members <account> and have it sign in again.",
  ],
  validation: [
    'Run Get-ADUser <account> -Properties AccountNotDelegated,MemberOf for each privileged account and confirm protection.',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-PRIV-001 is PASS.',
  ],
  references: [AD_REF.mdiPrivilegedNotDelegated, AD_REF.protectedUsers, AD_REF.privilegedGroupsAppendixB, AD_REF.attackKerberosTickets],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-6(5)' },
    { framework: 'NIST-800-53r5', id: 'IA-5' },
    { framework: 'MCSB', id: 'PA-1' },
    { framework: 'MITRE-ATTACK', id: 'T1558' },
  ],
  tags: ['privileged-access', 'delegation', 'kerberos', 'active-directory'],
  evaluate: (ctx) => {
    const { users } = ctx.data('ad.users');
    const privileged = privilegedBySid(ctx);
    const domains = ctx.fact('ad.domains');
    const protectedUsersLevel = functionalLevelRank('Windows2012R2Domain');
    const protectionUnknown: ReturnType<typeof userObject>[] = [];
    const userBySid = new Map(users.map((u) => [u.sid.toUpperCase(), u]));
    const privilegedUsers = [...privileged.values()].filter((a) => USER_CLASSES.has(a.objectClass.toLowerCase()));
    const nonUser = privileged.size - privilegedUsers.length;
    const unprotected: { user: AdUser; groups: string[] }[] = [];
    const missing: typeof privilegedUsers = [];
    let enabledCount = 0;
    for (const account of privilegedUsers) {
      const user = userBySid.get(account.sid.toUpperCase());
      if (user === undefined) {
        missing.push(account);
        continue;
      }
      if (!user.enabled) continue;
      enabledCount += 1;
      if (!user.accountNotDelegated) {
        if (!user.memberOfProtectedUsers) unprotected.push({ user, groups: account.groups });
        else {
          const domain = domains.available ? domains.data.find((d) => [d.dnsRoot, d.netBIOSName].some((name) => name.toLowerCase() === user.domain.toLowerCase())) : undefined;
          if (domain === undefined || functionalLevelRank(domain.domainMode) < protectedUsersLevel) {
            protectionUnknown.push(userObject(user, 'Protected Users membership is present, but Windows Server 2012 R2 or later domain functional level could not be confirmed; verify delegation protection or set AccountNotDelegated.'));
          }
        }
      }
    }
    const facts = [
      fact('Privileged user accounts', privilegedUsers.length),
      fact('Enabled privileged user accounts', enabledCount),
      fact('Unprotected from delegation', unprotected.length),
      fact('Privileged members without user evidence', missing.length),
      fact('Protected Users members without confirmed functional-level prerequisite', protectionUnknown.length),
    ];
    const notes =
      nonUser > 0
        ? [
            `${plural(nonUser, 'privileged member')} are computers or managed service accounts and were not evaluated; privileged groups should normally contain only user accounts.`,
          ]
        : [];
    const affectedObjects = [
      ...protectionUnknown,
      ...unprotected.map(({ user, groups }) => userObject(user, `Not marked sensitive and not in Protected Users; member of ${groups.join(', ')}`)),
      ...missing.map((a) =>
        affected('adUser', a.sid, qualifiedName(a.domain, a.samAccountName), `Member of ${a.groups.join(', ')}; account settings were not present in the user evidence`),
      ),
    ];
    if (unprotected.length > 0) {
      return fail({
        reason: `${plural(unprotected.length, 'enabled privileged account')} can be delegated by services trusted for delegation.`,
        summary: unprotected.map(({ user }) => qualifiedName(user.domain, user.samAccountName)).join(', '),
        facts,
        affectedObjects,
        notes,
      });
    }
    if (missing.length > 0 || protectionUnknown.length > 0) {
      return review({
        reason: `Delegation protection could not be verified for ${plural(missing.length + protectionUnknown.length, 'privileged account')} because user evidence or the Protected Users domain functional-level prerequisite is missing or insufficient.`,
        summary: 'Delegation protection could not be confirmed for every privileged account.',
        facts,
        affectedObjects,
        notes,
      });
    }
    return pass({
      reason: 'Every enabled privileged user account is marked sensitive or is a member of Protected Users.',
      summary: `${plural(enabledCount, 'enabled privileged account')} protected from delegation.`,
      facts,
      notes,
    });
  },
});
