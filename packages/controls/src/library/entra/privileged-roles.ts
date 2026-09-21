import {
  builtInRoleName,
  ENTRA_ROLE_TEMPLATES,
  HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS,
  MFA_ADMIN_ROLE_TEMPLATE_IDS,
  resolveEntraRoleAssignments,
  type ResolvedRoleAssignment,
} from '@adminsecops/inventory';
import { defineControl, EvidenceUnavailableError, type ControlContext } from '../../define.js';
import { affected, fact, fail, pass, plural, review } from '../../helpers.js';
import { REF } from '../../references.js';

const GA = ENTRA_ROLE_TEMPLATES.globalAdministrator;

function resolved(ctx: ControlContext): ResolvedRoleAssignment[] {
  // Mark datasets as used for evidence references, then join them.
  ctx.data('entra.roleAssignments');
  ctx.fact('entra.roleDefinitions');
  const fact = resolveEntraRoleAssignments(ctx.inventory);
  if (!fact.available) throw new EvidenceUnavailableError('entra.roleAssignments', fact.reason);
  return fact.data;
}

/** Distinct principals holding a role, from active and (optionally) eligible assignments. */
function globalAdminPrincipals(ctx: ControlContext): { principals: Map<string, string>; eligibleIncluded: boolean; groups: string[] } {
  const principals = new Map<string, string>();
  const groups: string[] = [];
  for (const a of resolved(ctx)) {
    if (a.roleTemplateId !== GA || a.directoryScopeId !== '/') continue;
    principals.set(a.principalId.toLowerCase(), a.principalName);
    if (a.principalType === 'group') groups.push(a.principalName);
  }
  const eligible = ctx.fact('entra.roleEligibilitySchedules');
  if (eligible.available) {
    for (const e of eligible.data) {
      if (e.roleDefinitionId.toLowerCase() !== GA || e.directoryScopeId !== '/') continue;
      if (!principals.has(e.principalId.toLowerCase())) principals.set(e.principalId.toLowerCase(), `${e.principalId} (eligible)`);
    }
  }
  return { principals, eligibleIncluded: eligible.available, groups };
}

const PRIV_REFERENCES = [REF.entraRoleBestPractices, REF.emergencyAccess, REF.entraBuiltInRoles];

export const entraGlobalAdminMaximum = defineControl({
  id: 'ENTRA-PRIV-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Fewer than five principals hold the Global Administrator role',
  technology: 'entra',
  category: 'Privileged access',
  subcategory: 'Global Administrators',
  description:
    'Counts the distinct principals assigned the Global Administrator role at tenant scope (active assignments, plus PIM-eligible assignments when that evidence is available) and compares the count with Microsoft guidance to keep it below five.',
  rationale:
    'Global Administrator has unrestricted control of the tenant and every connected Microsoft service. Each additional Global Administrator increases the chance that one of them is phished or misused. Most administrative work can be done with less privileged, task-specific roles.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'All Microsoft Entra tenants.' },
  requiredEvidence: ['entra.roleAssignments'],
  optionalEvidence: ['entra.roleDefinitions', 'entra.roleEligibilitySchedules'],
  evaluation: {
    logic:
      'Count distinct principals with an active Global Administrator assignment at directory scope "/", plus principals with an eligible assignment when entra.roleEligibilitySchedules is available. FAIL when the count is greater than maxGlobalAdmins. Role-assignable groups count as one principal and are noted because their members also hold the role.',
    parameters: { maxGlobalAdmins: 4 },
  },
  expectedState: 'No more than four principals (including emergency access accounts) hold Global Administrator.',
  remediation: {
    summary: 'Replace unnecessary Global Administrator assignments with least-privileged roles.',
    steps: [
      'Review each Global Administrator listed in this finding and identify the tasks they actually perform.',
      'Assign the least-privileged built-in role for those tasks (for example User Administrator, Exchange Administrator, Security Administrator).',
      'Remove the Global Administrator assignment in Entra ID > Roles & admins > Global Administrator.',
      'Keep two cloud-only emergency access accounts with Global Administrator.',
    ],
    effort: 'medium',
  },
  implementationConsiderations: [
    'Confirm the replacement role covers every task before removing Global Administrator; use "Least privileged roles by task" in Microsoft Learn.',
    'Some legacy tools and partner relationships assume Global Administrator; test them with the reduced role.',
  ],
  impact: 'Removed administrators lose tenant-wide rights; they keep only the permissions of their new roles.',
  rollback: ['Re-assign the Global Administrator role to the affected account in Entra ID > Roles & admins (preferably as a PIM-eligible assignment).'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-PRIV-001 is PASS.', 'Review Entra ID > Roles & admins > Global Administrator > Assignments.'],
  references: PRIV_REFERENCES,
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-6(5)' },
    { framework: 'MCSB', id: 'PA-1' },
    { framework: 'CISA-SCuBA', id: 'MS.AAD.7.1v1', note: 'SCuBA allows up to eight; this control applies the stricter Microsoft guidance of fewer than five' },
    { framework: 'MITRE-ATTACK', id: 'T1078.004' },
  ],
  tags: ['privileged-access', 'identity'],
  evaluate: (ctx) => {
    const max = ctx.num('maxGlobalAdmins');
    const { principals, eligibleIncluded, groups } = globalAdminPrincipals(ctx);
    const facts = [
      fact('Global Administrator principals', principals.size),
      fact('Maximum recommended', max),
      fact('PIM eligible assignments included', eligibleIncluded),
    ];
    const notes: string[] = [];
    if (!eligibleIncluded) notes.push('PIM eligible assignments were not available; only active assignments were counted, so the real number may be higher.');
    if (groups.length > 0) notes.push(`Role-assignable groups hold Global Administrator (${groups.join(', ')}); every member of these groups is also a Global Administrator.`);
    const objects = [...principals.entries()].map(([id, name]) => affected('principal', id, name, 'Global Administrator'));
    if (principals.size > max) {
      return fail({
        reason: `${principals.size} principals hold Global Administrator; the recommended maximum is ${max}.`,
        summary: `${principals.size} Global Administrators found.`,
        facts,
        affectedObjects: objects,
        notes,
      });
    }
    return pass({ reason: `${principals.size} principals hold Global Administrator (maximum ${max}).`, summary: `${principals.size} Global Administrators found.`, facts, notes });
  },
});

export const entraGlobalAdminMinimum = defineControl({
  id: 'ENTRA-PRIV-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'At least two principals hold the Global Administrator role',
  technology: 'entra',
  category: 'Privileged access',
  subcategory: 'Global Administrators',
  description:
    'Checks that at least two principals hold Global Administrator so that the tenant cannot be locked out if one account is unavailable.',
  rationale:
    'With a single Global Administrator, losing that account (departure, lockout, MFA device loss, Conditional Access mistake) can leave nobody able to administer the tenant. Microsoft recommends at least two cloud-only emergency access accounts.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'All Microsoft Entra tenants.' },
  requiredEvidence: ['entra.roleAssignments'],
  optionalEvidence: ['entra.roleDefinitions', 'entra.roleEligibilitySchedules'],
  evaluation: {
    logic: 'Count distinct Global Administrator principals as in ENTRA-PRIV-001. FAIL when fewer than minGlobalAdmins.',
    parameters: { minGlobalAdmins: 2 },
  },
  expectedState: 'At least two principals, including emergency access accounts, hold Global Administrator.',
  remediation: {
    summary: 'Create a second, cloud-only emergency access account with Global Administrator.',
    steps: [
      'Create a cloud-only account on the *.onmicrosoft.com domain that is not tied to an individual.',
      'Protect it with a FIDO2 security key or certificate-based authentication stored securely.',
      'Assign Global Administrator permanently and exclude it only from policies that could lock it out.',
      'Monitor sign-ins for the account and test it periodically.',
    ],
    effort: 'low',
  },
  implementationConsiderations: ['Emergency access account credentials must be stored and monitored securely; document the break-glass procedure.'],
  impact: 'None for users; improves resilience against administrative lockout.',
  rollback: ['Remove the additional Global Administrator assignment.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-PRIV-002 is PASS.'],
  references: PRIV_REFERENCES,
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'CP-2' },
    { framework: 'MCSB', id: 'PA-5' },
    { framework: 'CISA-SCuBA', id: 'MS.AAD.7.1v1' },
  ],
  tags: ['privileged-access', 'identity'],
  evaluate: (ctx) => {
    const min = ctx.num('minGlobalAdmins');
    const { principals } = globalAdminPrincipals(ctx);
    const facts = [fact('Global Administrator principals', principals.size), fact('Minimum recommended', min)];
    if (principals.size < min) {
      return fail({ reason: `Only ${principals.size} principal(s) hold Global Administrator.`, summary: 'The tenant can be locked out if the only Global Administrator becomes unavailable.', facts });
    }
    return pass({ reason: `${principals.size} principals hold Global Administrator.`, summary: 'Global Administrator is held by more than one principal.', facts });
  },
});

export const entraPrivilegedCloudOnly = defineControl({
  id: 'ENTRA-PRIV-003',
  version: '1.0.1',
  lifecycle: 'stable',
  title: 'Highly privileged roles are held by cloud-only accounts',
  technology: 'entra',
  category: 'Privileged access',
  subcategory: 'Hybrid isolation',
  description: 'Checks that no user account synchronized from on-premises Active Directory holds an active highly privileged Microsoft Entra role.',
  rationale:
    'A synchronized account is controlled from Active Directory: anyone who compromises the on-premises domain can reset its password or change its attributes and then use it in the cloud. Microsoft recommends that Microsoft 365 and Entra administrator accounts are cloud-only so an on-premises breach cannot become a cloud breach.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'All tenants; relevant mainly to hybrid tenants that synchronize from Active Directory.' },
  requiredEvidence: ['entra.roleAssignments'],
  optionalEvidence: ['entra.roleDefinitions'],
  evaluation: {
    logic: 'FAIL when any active assignment of a highly privileged role at any scope belongs to a user principal with onPremisesSyncEnabled = true. REVIEW when any assessed user principal has an unknown synchronization state and no synchronized assignment is confirmed.',
    parameters: {},
  },
  expectedState: 'Every account with a highly privileged role is a cloud-only account.',
  remediation: {
    summary: 'Create cloud-only administrator accounts and remove privileged roles from synchronized accounts.',
    steps: [
      'For each affected person create a separate cloud-only admin account (for example admin-name@<tenant>.onmicrosoft.com).',
      'Register phishing-resistant MFA for the new account and assign the required roles (preferably PIM-eligible).',
      'Remove the role assignments from the synchronized account.',
    ],
    effort: 'medium',
  },
  implementationConsiderations: [
    'Administrators will use a separate account for administration; plan licensing (admin accounts usually need no mailbox) and communication.',
    'Automation that uses the synchronized account must be moved to a workload identity.',
  ],
  impact: 'Administrators sign in with a dedicated cloud account for privileged tasks.',
  rollback: ['Re-assign the role to the synchronized account (not recommended).'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-PRIV-003 is PASS.'],
  references: [REF.protectM365FromOnPrem, REF.entraRoleBestPractices],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-6(5)' },
    { framework: 'MCSB', id: 'PA-1' },
    { framework: 'CISA-SCuBA', id: 'MS.AAD.7.3v1' },
    { framework: 'MITRE-ATTACK', id: 'T1078.004' },
  ],
  tags: ['privileged-access', 'identity', 'hybrid'],
  evaluate: (ctx) => {
    const privileged = resolved(ctx).filter((a) => a.isHighlyPrivileged && a.principalType === 'user');
    const synced = privileged.filter((a) => a.onPremisesSyncEnabled === true);
    const unknown = privileged.filter((a) => a.onPremisesSyncEnabled === null);
    const facts = [fact('Privileged user assignments', privileged.length), fact('Held by synchronized accounts', synced.length), fact('Unknown synchronization state', unknown.length)];
    const notes = unknown.length > 0 ? [`${plural(unknown.length, 'assignment')} have no synchronization state in the evidence; cloud-only status cannot be confirmed.`] : [];
    if (synced.length > 0) {
      return fail({
        reason: `${plural(synced.length, 'highly privileged role assignment')} are held by accounts synchronized from on-premises.`,
        summary: 'Synchronized on-premises accounts hold highly privileged cloud roles.',
        facts,
        affectedObjects: synced.map((a) => affected('user', a.principalId, a.userPrincipalName ?? a.principalName, `${a.roleName} (synchronized from on-premises)`)),
        notes,
      });
    }
    if (unknown.length > 0) {
      return review({ reason: 'Synchronization state is unknown for some privileged user assignments.', summary: 'Cloud-only status could not be confirmed for every assessed privileged account.', facts, notes, affectedObjects: unknown.map((a) => affected('user', a.principalId, a.userPrincipalName ?? a.principalName, `${a.roleName} (synchronization state unknown)`)) });
    }
    return pass({ reason: 'No synchronized account holds a highly privileged role.', summary: 'Highly privileged roles are held by cloud-only accounts.', facts, notes });
  },
});

export const entraPrivilegedNoPermanent = defineControl({
  id: 'ENTRA-PRIV-004',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Highly privileged roles use just-in-time (PIM) instead of permanent assignments',
  technology: 'entra',
  category: 'Privileged access',
  subcategory: 'Privileged Identity Management',
  description:
    'Uses Privileged Identity Management assignment instances to find permanent (non-expiring, not activated) assignments of highly privileged roles to users.',
  rationale:
    'Standing privileged access means a stolen administrator session or password is immediately usable. With PIM, administrators are eligible and activate the role only when needed, with MFA, justification and time limits, which shrinks the window for misuse.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Tenants licensed for Privileged Identity Management (Microsoft Entra ID P2 or Entra ID Governance).' },
  requiredEvidence: ['entra.roleAssignmentScheduleInstances'],
  optionalEvidence: ['entra.roleAssignments'],
  evaluation: {
    logic:
      'Select instances with assignmentType "Assigned" (not "Activated") and no endDateTime for highly privileged roles at any scope. Up to emergencyAccessAllowance permanent Global Administrator assignments are tolerated as emergency access accounts (REVIEW so they can be confirmed). FAIL when other permanent assignments exist. Group and service principal assignments are included.',
    parameters: { emergencyAccessAllowance: 2 },
  },
  expectedState: 'Highly privileged roles are PIM-eligible; only emergency access accounts hold permanent Global Administrator.',
  remediation: {
    summary: 'Convert permanent privileged assignments to PIM-eligible assignments.',
    steps: [
      'Configure PIM role settings for each highly privileged role: require MFA (or an authentication strength) and justification on activation, maximum activation 8 hours or less, approval for Global Administrator and Privileged Role Administrator.',
      'In Entra ID > Privileged Identity Management > Microsoft Entra roles > Assignments, add an eligible assignment for each affected administrator.',
      'Remove the active permanent assignment.',
    ],
    effort: 'medium',
  },
  implementationConsiderations: [
    'Administrators must activate roles before privileged tasks; train them and set reasonable activation durations.',
    'Service principals cannot activate PIM roles; replace their directory roles with least-privileged application permissions where possible.',
  ],
  impact: 'Administrators have no standing privileges; they activate roles on demand.',
  rollback: ['Add an active permanent assignment again in PIM > Assignments > Active assignments.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-PRIV-004 is PASS or only lists your emergency access accounts.'],
  references: [REF.pimOverview, REF.pimDeploymentPlan, REF.emergencyAccess],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-2(7)' },
    { framework: 'NIST-800-53r5', id: 'AC-6(5)' },
    { framework: 'MCSB', id: 'PA-2' },
    { framework: 'CISA-SCuBA', id: 'MS.AAD.7.4v1' },
  ],
  tags: ['privileged-access', 'identity'],
  evaluate: (ctx) => {
    const allowance = ctx.num('emergencyAccessAllowance');
    const instances = ctx.data('entra.roleAssignmentScheduleInstances');
    const names = new Map<string, string>();
    const assignments = ctx.fact('entra.roleAssignments');
    if (assignments.available) {
      for (const a of assignments.data) {
        if (a.principal !== null) names.set(a.principalId.toLowerCase(), a.principal.userPrincipalName ?? a.principal.displayName ?? a.principalId);
      }
    }
    const permanent = instances.filter(
      (i) => i.assignmentType.toLowerCase() === 'assigned' && i.endDateTime === null && HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS.has(i.roleDefinitionId.toLowerCase()),
    );
    const objects = permanent.map((i) =>
      affected('principal', i.principalId, names.get(i.principalId.toLowerCase()) ?? i.principalId, `Permanent ${builtInRoleName(i.roleDefinitionId.toLowerCase())}`),
    );
    const permanentGa = permanent.filter((i) => i.roleDefinitionId.toLowerCase() === GA);
    const others = permanent.filter((i) => i.roleDefinitionId.toLowerCase() !== GA);
    const facts = [fact('Permanent highly privileged assignments', permanent.length), fact('Permanent Global Administrator assignments', permanentGa.length)];
    if (permanent.length === 0) {
      return pass({ reason: 'No permanent highly privileged assignments were found.', summary: 'Highly privileged roles are assigned just-in-time.', facts });
    }
    if (others.length === 0 && permanentGa.length <= allowance) {
      return review({
        reason: `Only ${plural(permanentGa.length, 'permanent Global Administrator assignment')} remain, within the emergency access allowance of ${allowance}. Confirm they are emergency access accounts.`,
        summary: 'Permanent Global Administrator assignments may be emergency access accounts.',
        facts,
        affectedObjects: objects,
      });
    }
    return fail({
      reason: `${plural(permanent.length, 'permanent highly privileged assignment')} found.`,
      summary: 'Administrators hold standing privileged access instead of just-in-time access.',
      facts,
      affectedObjects: objects,
    });
  },
});

export const entraPrivilegedMfaRegistered = defineControl({
  id: 'ENTRA-PRIV-005',
  version: '1.0.1',
  lifecycle: 'stable',
  title: 'Users in the assessed administrator roles are registered for MFA',
  technology: 'entra',
  category: 'Privileged access',
  subcategory: 'MFA registration',
  description: 'Joins direct active user assignments in the highly privileged role catalog and Microsoft administrator MFA template with the registration report. Disabled users are excluded. Group membership and PIM-eligible users are not resolved; incomplete coverage requires review.',
  rationale:
    'An administrator without a registered MFA method can be registered by whoever first signs in with the password. If that is an attacker using a phished or sprayed password, they bind their own authenticator to a privileged account.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Tenants licensed for the registration report (Microsoft Entra ID P1 or P2).' },
  requiredEvidence: ['entra.roleAssignments', 'entra.userRegistrationDetails'],
  optionalEvidence: ['entra.roleDefinitions', 'entra.roleEligibilitySchedules'],
  evaluation: {
    logic:
      'Consider enabled user principals with an active assignment of a highly privileged role or a role from the Microsoft administrator MFA template. FAIL when any of them has isMfaRegistered = false in entra.userRegistrationDetails. REVIEW when registration rows, eligible assignment evidence, or principal coverage are incomplete, when selected eligible assignments exist, or when no user was checked. Groups are not expanded. Roles outside the selected built-in templates are outside this control.',
    parameters: {},
  },
  expectedState: 'Every user in the assessed administrator roles has registered at least one MFA method (preferably phishing-resistant).',
  remediation: {
    summary: 'Have each listed administrator register MFA immediately, or remove their role until they do.',
    steps: [
      'Contact each administrator listed and have them register at https://aka.ms/mysecurityinfo from a trusted device.',
      'Alternatively issue a Temporary Access Pass so they can register a passkey or FIDO2 key securely.',
      'If an account is unused, remove its role assignment or disable it.',
    ],
    effort: 'low',
  },
  implementationConsiderations: ['Verify the identity of the administrator out-of-band before issuing a Temporary Access Pass.'],
  impact: 'None for users once registered.',
  rollback: ['Not applicable - registering an authentication method does not change configuration.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-PRIV-005 is PASS.', 'Compare the affected direct role assignments with Entra ID > Authentication methods > User registration details. The Admin = Yes filter can include roles outside this control; separately review group members and PIM-eligible users.'],
  references: [REF.userRegistrationDetails, REF.caRequireMfaAdmins],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-2(1)' },
    { framework: 'MCSB', id: 'IM-6' },
    { framework: 'MITRE-ATTACK', id: 'T1098' },
  ],
  tags: ['mfa', 'privileged-access', 'identity'],
  evaluate: (ctx) => {
    const adminRoleIds = new Set([...HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS, ...MFA_ADMIN_ROLE_TEMPLATE_IDS]);
    const admins = new Map<string, ResolvedRoleAssignment[]>();
    const selectedAssignments = resolved(ctx).filter((a) => adminRoleIds.has(a.roleTemplateId));
    const unresolved = selectedAssignments.filter((a) => a.principalType !== 'user' && a.principalType !== 'servicePrincipal');
    const eligible = ctx.fact('entra.roleEligibilitySchedules');
    const definitions = ctx.fact('entra.roleDefinitions');
    const templateIds = new Map(definitions.available ? definitions.data.map((d) => [d.id.toLowerCase(), (d.templateId ?? d.id).toLowerCase()]) : []);
    const selectedEligible = eligible.available ? eligible.data.filter((a) => adminRoleIds.has(templateIds.get(a.roleDefinitionId.toLowerCase()) ?? a.roleDefinitionId.toLowerCase())) : [];
    for (const a of selectedAssignments) {
      if (a.principalType !== 'user' || a.accountEnabled === false || !adminRoleIds.has(a.roleTemplateId)) continue;
      const list = admins.get(a.principalId.toLowerCase()) ?? [];
      list.push(a);
      admins.set(a.principalId.toLowerCase(), list);
    }
    const registration = new Map(ctx.data('entra.userRegistrationDetails').map((r) => [r.id.toLowerCase(), r]));
    const unregistered: string[] = [];
    const missing: string[] = [];
    for (const id of admins.keys()) {
      const r = registration.get(id);
      if (r === undefined) missing.push(id);
      else if (!r.isMfaRegistered) unregistered.push(id);
    }
    const describe = (id: string) => {
      const list = admins.get(id) ?? [];
      const first = list[0];
      return affected('user', id, first?.userPrincipalName ?? first?.principalName ?? id, list.map((a) => a.roleName).join(', '));
    };
    const facts = [fact('Administrators checked', admins.size), fact('Not registered for MFA', unregistered.length), fact('Not found in registration report', missing.length), fact('Unresolved group or principal assignments', unresolved.length), fact('PIM eligibility evidence available', eligible.available), fact('Selected PIM-eligible assignments not assessed', selectedEligible.length)];
    const notes = missing.length > 0 ? [`${plural(missing.length, 'administrator')} were not found in the registration report: ${missing.map((m) => describe(m).name).join(', ')}.`] : [];
    notes.push('Checks direct active users in the highly privileged role catalog and Microsoft administrator MFA template; other roles and custom roles are outside this control. MFA registration is not proof of MFA enforcement.');
    if (!eligible.available) notes.push('PIM eligibility evidence was not available; eligible administrators were not assessed.');
    if (selectedEligible.length > 0) notes.push('PIM-eligible assignments in the selected roles were found, but their users and group members were not assessed.');
    if (unresolved.length > 0) notes.push('Some selected assignments belong to groups or unidentified principals; their users could not be assessed.');
    if (admins.size === 0) notes.push('No direct active user in the selected roles was checked.');
    if (unregistered.length > 0) {
      return fail({
        reason: `${plural(unregistered.length, 'administrator')} have not registered an MFA method.`,
        summary: 'Administrator accounts without a registered MFA method exist.',
        facts,
        affectedObjects: unregistered.map(describe),
        notes,
      });
    }
    if (missing.length > 0 || unresolved.length > 0 || !eligible.available || selectedEligible.length > 0 || admins.size === 0) {
      return review({ reason: 'Administrator MFA registration coverage is incomplete.', summary: 'MFA registration could not be confirmed for every administrator.', facts, affectedObjects: missing.map(describe), notes });
    }
    return pass({ reason: 'All assessed direct active administrator users are registered for MFA.', summary: `${plural(admins.size, 'administrator')} checked; all registered for MFA.`, facts, notes });
  },
});
