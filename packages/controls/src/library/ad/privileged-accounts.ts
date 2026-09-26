import { daysSince, sidDomainPart, sidRid } from '@adminsecops/inventory';
import { defineControl } from '../../define.js';
import { affected, fact, fail, notAssessed, pass, plural, review } from '../../helpers.js';
import { AD_REF } from './references.js';
import { isBuiltInAdministrator, privilegedBySid, qualifiedName, userObject } from './shared.js';

const USER_CLASSES = new Set(['user', 'inetorgperson']);

export const adStalePrivilegedAccounts = defineControl({
  id: 'AD-PRIV-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'No stale enabled privileged accounts',
  technology: 'ad',
  category: 'Privileged access',
  subcategory: 'Account lifecycle',
  description:
    'Finds enabled user accounts in privileged built-in groups that have not signed in for the configured number of days (default 90), or have never signed in since being created more than that many days ago.',
  rationale:
    'Privileged accounts that nobody uses still grant full control of the domain. Because no one notices their activity, they are attractive to attackers: their passwords are often old, their owners may have left, and misuse is less likely to be spotted. Microsoft Defender for Identity reports dormant accounts in sensitive groups for the same reason.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Every Active Directory domain in the collected forest.' },
  requiredEvidence: ['ad.users', 'ad.privilegedGroups'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each enabled user account that is a recursive member of a privileged built-in group: stale when lastLogonTimestamp is older than staleDays at the assessment date, or when lastLogonTimestamp is empty and whenCreated is older than staleDays. FAIL when any account is stale. REVIEW when an account has neither timestamp, or a privileged member is missing from the user evidence. PASS otherwise. lastLogonTimestamp replicates with a delay of up to about 14 days, which is small compared with the threshold.',
    parameters: { staleDays: 90 },
  },
  expectedState: 'Every enabled privileged account is actively used by a known owner; unused privileged accounts are removed from privileged groups or disabled.',
  remediation: {
    summary: 'Confirm the owner of each stale privileged account; remove it from privileged groups and disable it if it is not needed.',
    steps: [
      'For each listed account, identify the owner and whether it is a documented emergency (break-glass) account.',
      'If the account is not needed, remove it from all privileged groups, disable it, and delete it after your retention period.',
      'If it is an emergency account, keep it, but make sure its password is long, stored securely, rotated after each use, and that its sign-ins are alerted on. Record an exception for this control.',
      'Introduce a periodic review (for example quarterly) of privileged group membership.',
    ],
    scriptExample: [
      '# Review, then run as a Domain Admin. AdminSecOps never runs this.',
      "Get-ADGroupMember 'Domain Admins' -Recursive | Get-ADUser -Properties LastLogonTimestamp | Select-Object SamAccountName, @{n='LastLogon';e={[datetime]::FromFileTime($_.LastLogonTimestamp)}}",
      "Remove-ADGroupMember -Identity 'Domain Admins' -Members 'old-admin' -Confirm:$false",
      "Disable-ADAccount -Identity 'old-admin'",
    ].join('\n'),
    effort: 'low',
  },
  implementationConsiderations: [
    'Some privileged accounts are intentionally unused emergency accounts; keep them but protect and monitor them, and document the exception.',
    'Accounts used only by services or scheduled tasks still update lastLogonTimestamp when they authenticate; a stale value usually means the service is gone.',
    'Disabling rather than deleting first allows a quick rollback if a forgotten dependency appears.',
  ],
  impact: 'Removed or disabled accounts can no longer be used; forgotten dependencies (scripts, services) that used them will fail.',
  rollback: ['Re-enable the account (Enable-ADAccount) and add it back to the required group if a legitimate dependency is found.'],
  validation: [
    'Re-run the AdminSecOps Active Directory collector and confirm AD-PRIV-002 is PASS or that the remaining accounts are documented exceptions.',
  ],
  references: [AD_REF.mdiDormantSensitive, AD_REF.privilegedGroupsAppendixB, AD_REF.securingActiveDirectory, AD_REF.attackDomainAccounts],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-2(3)' },
    { framework: 'NIST-800-53r5', id: 'AC-6(7)' },
    { framework: 'MCSB', id: 'PA-1' },
    { framework: 'MITRE-ATTACK', id: 'T1078.002' },
  ],
  tags: ['privileged-access', 'account-lifecycle', 'active-directory'],
  evaluate: (ctx) => {
    const staleDays = ctx.num('staleDays');
    const { users } = ctx.data('ad.users');
    const privileged = privilegedBySid(ctx);
    const userBySid = new Map(users.map((u) => [u.sid.toUpperCase(), u]));
    const stale: ReturnType<typeof userObject>[] = [];
    const unknown: ReturnType<typeof userObject>[] = [];
    let enabledCount = 0;
    for (const account of privileged.values()) {
      if (!USER_CLASSES.has(account.objectClass.toLowerCase())) continue;
      const user = userBySid.get(account.sid.toUpperCase());
      if (user === undefined) {
        unknown.push(
          affected('adUser', account.sid, qualifiedName(account.domain, account.samAccountName), `Member of ${account.groups.join(', ')}; not present in the user evidence`),
        );
        continue;
      }
      if (!user.enabled) continue;
      enabledCount += 1;
      const lastLogon = daysSince(user.lastLogonTimestamp, ctx.assessedAt);
      const created = daysSince(user.whenCreated, ctx.assessedAt);
      const builtIn = isBuiltInAdministrator(user.sid) ? ' (built-in Administrator: if this is your documented emergency account, record an exception)' : '';
      if (lastLogon !== null) {
        if (lastLogon > staleDays) stale.push(userObject(user, `Last sign-in about ${lastLogon} days ago; member of ${account.groups.join(', ')}${builtIn}`));
      } else if (created !== null) {
        if (created > staleDays) stale.push(userObject(user, `Never signed in; created ${created} days ago; member of ${account.groups.join(', ')}${builtIn}`));
      } else {
        unknown.push(userObject(user, `No sign-in or creation date available; member of ${account.groups.join(', ')}`));
      }
    }
    const facts = [
      fact('Enabled privileged user accounts', enabledCount),
      fact('Stale threshold (days)', staleDays),
      fact('Stale privileged accounts', stale.length),
      fact('Privileged accounts with unknown activity', unknown.length),
    ];
    if (stale.length > 0) {
      return fail({
        reason: `${plural(stale.length, 'enabled privileged account')} have not signed in for more than ${staleDays} days.`,
        summary: 'Unused privileged accounts keep full administrative rights without an active owner.',
        facts,
        affectedObjects: [...stale, ...unknown],
      });
    }
    if (unknown.length > 0) {
      return review({
        reason: `Sign-in activity could not be determined for ${plural(unknown.length, 'privileged account')}.`,
        summary: 'Activity of some privileged accounts could not be verified.',
        facts,
        affectedObjects: unknown,
      });
    }
    return pass({
      reason: `Every enabled privileged account signed in within the last ${staleDays} days (or was created recently).`,
      summary: `${plural(enabledCount, 'enabled privileged account')} checked.`,
      facts,
    });
  },
});

const FOREST_GROUP_RIDS: Readonly<Record<string, string>> = { '519': 'Enterprise Admins', '518': 'Schema Admins' };

export const adForestAdminGroupsEmpty = defineControl({
  id: 'AD-PRIV-003',
  version: '1.1.0',
  lifecycle: 'stable',
  title: 'Enterprise Admins and Schema Admins have no standing members',
  technology: 'ad',
  category: 'Privileged access',
  subcategory: 'Forest administration',
  description:
    'Checks that the forest-wide Enterprise Admins and Schema Admins groups have no standing members, including nested members. Only Enterprise Admins permits an exception for the secured forest root built-in Administrator (RID 500).',
  rationale:
    'Enterprise Admins control every domain in the forest and Schema Admins can change the definition of every object. Microsoft guidance is that Enterprise Admins should have no day-to-day members (with the possible exception of the secured forest root Administrator account) and that Schema Admins should stay empty except while a schema change is being made. Permanent membership multiplies the number of accounts whose compromise means losing the whole forest.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'The forest root domain, where Enterprise Admins and Schema Admins exist.' },
  requiredEvidence: ['ad.privilegedGroups'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'Groups are identified by SID (RID 519 Enterprise Admins, RID 518 Schema Admins), so renamed groups are still found. FAIL when Schema Admins has any recursive member, or Enterprise Admins has a recursive member other than the secured forest root built-in Administrator (RID 500); an Administrator account from a child domain is a failure. PASS when both groups are present, Schema Admins is empty and Enterprise Admins is empty or contains only that account; REVIEW when only one of the two groups is present and it has no standing members. NOT_ASSESSED when neither group is present in the evidence (for example only a child domain was collected). FAIL rather than REVIEW is used because Microsoft states these groups should have no standing members.',
    parameters: {},
  },
  expectedState: 'Schema Admins is empty; Enterprise Admins is empty or contains only the secured forest root Administrator; members are added temporarily for a specific task and removed afterwards.',
  remediation: {
    summary: 'Remove standing members from Enterprise Admins and Schema Admins and adopt a temporary-membership process for forest-level changes.',
    steps: [
      'List the current members, including nested groups: Get-ADGroupMember "Enterprise Admins" -Recursive (run in the forest root domain).',
      'Confirm with each member which forest-level tasks they actually perform. Most daily administration only needs Domain Admins rights or narrower delegated permissions.',
      'Remove the members in Active Directory Users and Computers (forest root domain > Users > Enterprise Admins / Schema Admins > Members tab), or with Remove-ADGroupMember.',
      'Document a procedure to add an account temporarily when a forest-level or schema change is planned, and remove it immediately after. Consider a time-bound membership (Privileged Access Management feature, Windows Server 2016 forest functional level) to automate removal.',
      'Configure auditing and alerting for membership changes to these groups (event 4728/4732/4756).',
    ],
    scriptExample: [
      '# Review, then run as an Enterprise Admin in the forest root domain. AdminSecOps never runs this.',
      "Get-ADGroupMember -Identity 'Enterprise Admins' -Recursive | Select-Object SamAccountName, objectClass",
      "Get-ADGroupMember -Identity 'Schema Admins' -Recursive | Select-Object SamAccountName, objectClass",
      "Remove-ADGroupMember -Identity 'Schema Admins' -Members 'jsmith-admin' -Confirm:$false",
    ].join('\n'),
    effort: 'low',
  },
  implementationConsiderations: [
    'Keep Enterprise Admins nested in each domain\'s Administrators group; Microsoft states this default nesting is required for forest recovery.',
    'Some product installers (Exchange, AD CS enterprise CA installation, schema extensions) require Enterprise Admins or Schema Admins rights; add the installing account temporarily for that task.',
    'Make sure at least one secured account (for example the forest root Administrator stored for emergencies) can still be added to the groups when needed.',
  ],
  impact: 'Removed members lose forest-wide rights. Their domain-level rights through other groups are unchanged.',
  rollback: ['Add the account back to the group (Add-ADGroupMember) if a forest-level task is in progress, then remove it again afterwards.'],
  validation: [
    'Run Get-ADGroupMember -Recursive for both groups in the forest root domain and confirm Schema Admins is empty and Enterprise Admins contains only the secured forest root Administrator or nobody.',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-PRIV-003 is PASS.',
  ],
  references: [AD_REF.enterpriseAdminsAppendixE, AD_REF.schemaAdminsEmpty, AD_REF.privilegedGroupsAppendixB, AD_REF.attackDomainAccounts],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-6(5)' },
    { framework: 'NIST-800-53r5', id: 'AC-2(7)' },
    { framework: 'MCSB', id: 'PA-1' },
    { framework: 'MITRE-ATTACK', id: 'T1078.002' },
  ],
  tags: ['privileged-access', 'least-privilege', 'active-directory'],
  evaluate: (ctx) => {
    const groups = ctx.data('ad.privilegedGroups');
    const forestGroups = new Map<string, (typeof groups)[number]>();
    for (const group of groups) {
      const rid = sidRid(group.groupSid);
      if (group.groupSid.toUpperCase().startsWith('S-1-5-21-') && rid in FOREST_GROUP_RIDS) {
        forestGroups.set(group.groupSid.toUpperCase(), group);
      }
    }
    if (forestGroups.size === 0) {
      return notAssessed({
        reason: 'Neither Enterprise Admins nor Schema Admins was present in the privileged group evidence (these groups exist only in the forest root domain). Collect the forest root domain to assess this control.',
        summary: 'Forest-level administrative groups were not collected.',
      });
    }
    const standing: ReturnType<typeof affected>[] = [];
    const notes: string[] = [];
    for (const group of forestGroups.values()) {
      const groupDomain = sidDomainPart(group.groupSid);
      const label = FOREST_GROUP_RIDS[sidRid(group.groupSid)] ?? group.groupName;
      for (const member of group.members) {
        const isRootAdministrator =
          isBuiltInAdministrator(member.sid) && sidDomainPart(member.sid) === groupDomain && USER_CLASSES.has(member.objectClass.toLowerCase());
        if (isRootAdministrator && sidRid(group.groupSid) === '519') {
          notes.push(
            `${label} contains the forest root built-in Administrator account (${member.samAccountName}). Microsoft accepts this only if the account is secured (long password stored offline, marked sensitive, sign-ins monitored).`,
          );
          continue;
        }
        standing.push(
          affected(
            'adGroupMember',
            `${group.groupSid}:${member.sid}`,
            qualifiedName(group.domain, `${group.groupName} > ${member.samAccountName}`),
            `${member.objectClass} is a standing member of ${label}${isBuiltInAdministrator(member.sid) && !isRootAdministrator ? ' (Administrator account of a different domain)' : ''}`,
          ),
        );
      }
    }
    const facts = [
      fact('Forest groups evaluated', [...forestGroups.values()].map((g) => g.groupName).join(', ')),
      fact('Standing members', standing.length),
    ];
    if (standing.length > 0) {
      return fail({
        reason: `${plural(standing.length, 'standing member')} found in Enterprise Admins or Schema Admins.`,
        summary: 'Forest-wide administrative groups have permanent members.',
        facts,
        affectedObjects: standing,
        notes,
      });
    }
    if (forestGroups.size < 2) {
      return review({
        reason: `Only ${[...forestGroups.values()].map((g) => g.groupName).join(', ')} was present in the evidence; it has no standing members, but the other forest-level group could not be checked.`,
        summary: 'One of the two forest-level administrative groups was not collected.',
        facts,
        notes,
      });
    }
    return pass({
      reason: 'Schema Admins is empty and Enterprise Admins has no standing members other than the forest root built-in Administrator.',
      summary: 'Schema Admins is empty; Enterprise Admins is empty or contains only the forest root built-in Administrator.',
      facts,
      notes,
    });
  },
});
