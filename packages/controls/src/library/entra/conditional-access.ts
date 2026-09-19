import { builtInRoleName, ca, MFA_ADMIN_ROLE_TEMPLATE_IDS } from '@adminsecops/inventory';
import type { ConditionalAccessPolicy } from '@adminsecops/schemas';
import { defineControl, type ControlContext } from '../../define.js';
import { affected, fact, fail, pass, plural, review } from '../../helpers.js';
import { REF } from '../../references.js';

type Policy = ConditionalAccessPolicy;

/** Client app types a baseline MFA/block policy must cover (modern clients). */
function coversModernClients(policy: Policy): boolean {
  if (ca.includesAllClientApps(policy)) return true;
  const types = policy.conditions.clientAppTypes.map((t) => t.toLowerCase());
  return types.includes('browser') && types.includes('mobileappsanddesktopclients');
}

function policyObject(policy: Policy, detail?: string) {
  return affected('conditionalAccessPolicy', policy.id, policy.displayName, detail);
}

function exclusionNote(policies: readonly Policy[]): string[] {
  const notes: string[] = [];
  for (const policy of policies) {
    const ex = ca.exclusions(policy);
    if (ex.total > 0) {
      notes.push(
        `Policy "${policy.displayName}" excludes ${plural(ex.users, 'user')}, ${plural(ex.groups, 'group')} and ${plural(ex.roles, 'role')}${ex.guestsOrExternal ? ' plus guest/external user types' : ''}. Confirm exclusions are limited to emergency access accounts.`,
      );
    }
  }
  return notes;
}

function securityDefaultsEnabled(ctx: ControlContext): boolean {
  return ctx.data('entra.securityDefaults').isEnabled;
}

/**
 * Conditional Access policies, or null when the collector reported the dataset as
 * NotApplicable (tenant not licensed for Conditional Access). Any other unavailability
 * throws EvidenceUnavailableError, which yields NOT_ASSESSED.
 */
function policiesOrUnlicensed(ctx: ControlContext): Policy[] | null {
  const policies = ctx.fact('entra.conditionalAccessPolicies');
  if (!policies.available && policies.collectionStatus === 'NotApplicable') return null;
  return ctx.data('entra.conditionalAccessPolicies');
}

const UNLICENSED_REASON =
  'Security defaults are disabled and the collector reported that Conditional Access is not available in this tenant (no Microsoft Entra ID P1 licence), so no mechanism enforces this requirement.';

/** Tenant-wide policies (all users, all apps, modern clients, no narrowing conditions). */
function isTenantWide(policy: Policy): boolean {
  return ca.includesAllUsers(policy) && ca.includesAllApps(policy) && coversModernClients(policy) && ca.hasNoNarrowingConditions(policy);
}

export const entraCaMfaAllUsers = defineControl({
  id: 'ENTRA-CA-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Multifactor authentication is required for all users',
  technology: 'entra',
  category: 'Authentication',
  subcategory: 'Multifactor authentication',
  description:
    'Checks that every user must complete multifactor authentication (MFA), either through Microsoft Entra security defaults or an enabled Conditional Access policy that targets all users and all cloud apps.',
  rationale:
    'Password-only accounts can be taken over through phishing, password spraying or reuse of leaked passwords. Requiring MFA for every user blocks the large majority of these account compromise attacks and is the single most effective identity control.',
  severity: 'critical',
  confidence: 'high',
  applicability: { description: 'All Microsoft Entra tenants.' },
  requiredEvidence: ['entra.securityDefaults'],
  optionalEvidence: ['entra.conditionalAccessPolicies'],
  evaluation: {
    logic:
      'PASS when security defaults are enabled, or when at least one enabled Conditional Access policy includes all users and all cloud apps, covers browser and modern clients, has no platform/location/risk conditions that narrow it, and always requires MFA or an authentication strength. REVIEW when such a policy exists only in report-only mode, only offers MFA as an alternative (OR with another control), or is narrowed by conditions. FAIL otherwise. If security defaults are disabled and Conditional Access policies could not be collected the control is NOT_ASSESSED.',
    parameters: {},
  },
  expectedState:
    'Security defaults are enabled, or an enabled Conditional Access policy requires MFA for all users and all cloud apps with exclusions limited to emergency access accounts.',
  remediation: {
    summary:
      'Create a Conditional Access policy that requires MFA (preferably an authentication strength) for all users and all resources, or enable security defaults if you do not use Conditional Access.',
    steps: [
      'Create or identify two emergency access (break-glass) accounts and exclude only those from the policy.',
      'In the Microsoft Entra admin center go to Entra ID > Conditional Access > Policies > New policy.',
      'Users: Include "All users"; Exclude your emergency access accounts.',
      'Target resources: Include "All resources" (formerly "All cloud apps").',
      'Grant: "Require authentication strength" (Multifactor authentication or stronger) or "Require multifactor authentication".',
      'Set the policy to Report-only first, review the Conditional Access insights workbook, then switch it to On.',
    ],
    effort: 'medium',
  },
  implementationConsiderations: [
    'Users who have not registered an MFA method will be prompted to register at their next sign-in; communicate the change beforehand.',
    'Service accounts that sign in interactively with a password will break; replace them with managed identities or workload identities.',
    'Security defaults and Conditional Access cannot be used together; disable security defaults before enabling Conditional Access policies.',
    'Exclude only emergency access accounts and monitor their sign-ins.',
  ],
  impact:
    'All users are prompted for MFA according to the policy session settings. Legacy clients that cannot perform MFA stop working.',
  rollback: [
    'Set the Conditional Access policy state to Report-only or Off.',
    'If security defaults were enabled as the fix, disable them in Entra ID > Overview > Properties > Manage security defaults.',
  ],
  validation: [
    'Re-run the AdminSecOps Entra collector and confirm ENTRA-CA-001 is PASS.',
    'Use the Conditional Access "What If" tool for a standard user and all cloud apps and confirm the policy applies with an MFA grant.',
    'Review sign-in logs to confirm "Multifactor authentication" is satisfied for interactive sign-ins.',
  ],
  references: [REF.caRequireMfaAllUsers, REF.securityDefaults, REF.emergencyAccess, REF.attackPasswordSpraying],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-2(1)' },
    { framework: 'NIST-800-53r5', id: 'IA-2(2)' },
    { framework: 'MCSB', id: 'IM-6' },
    { framework: 'MITRE-ATTACK', id: 'T1078.004' },
    { framework: 'MITRE-ATTACK', id: 'T1110.003' },
  ],
  tags: ['mfa', 'conditional-access', 'identity'],
  evaluate: (ctx) => {
    if (securityDefaultsEnabled(ctx)) {
      return pass({
        reason: 'Security defaults are enabled.',
        summary: 'Microsoft Entra security defaults are enabled, which requires all users to register for MFA and prompts them for MFA when necessary.',
        facts: [fact('Security defaults enabled', true)],
        notes: [
          'Security defaults prompt users for MFA based on Microsoft risk evaluation rather than at every sign-in. Conditional Access provides finer control when licensed.',
        ],
      });
    }
    const policies = policiesOrUnlicensed(ctx);
    if (policies === null) {
      return fail({ reason: UNLICENSED_REASON, summary: 'No mechanism requires MFA for all users.', facts: [fact('Security defaults enabled', false)] });
    }
    const candidates = policies.filter((p) => ca.includesAllUsers(p) && ca.includesAllApps(p) && ca.mfaRequirement(p) !== 'none');
    const strict = candidates.filter((p) => ca.isEnabled(p) && isTenantWide(p) && ca.mfaRequirement(p) === 'required');
    const facts = [
      fact('Security defaults enabled', false),
      fact('Conditional Access policies', policies.length),
      fact('Enabled policies requiring MFA for all users and apps', strict.length),
    ];
    if (strict.length > 0) {
      return pass({
        reason: `Enabled Conditional Access policy requires MFA for all users and all cloud apps (${strict.map((p) => p.displayName).join(', ')}).`,
        summary: `${plural(strict.length, 'enabled policy', 'enabled policies')} require MFA for all users and all cloud apps.`,
        facts,
        affectedObjects: [],
        notes: exclusionNote(strict),
      });
    }
    if (candidates.length > 0) {
      return review({
        reason:
          'Policies that require MFA for all users exist but are report-only, disabled, narrowed by conditions, or allow a non-MFA alternative.',
        summary: `${plural(candidates.length, 'policy', 'policies')} partially address MFA for all users, but none enforce it unconditionally.`,
        facts,
        affectedObjects: candidates.map((p) =>
          policyObject(p, `state=${p.state}; MFA=${ca.mfaRequirement(p)}; narrowed=${!ca.hasNoNarrowingConditions(p)}`),
        ),
      });
    }
    return fail({
      reason: 'Security defaults are disabled and no Conditional Access policy requires MFA for all users.',
      summary: 'No mechanism was found that requires multifactor authentication for all users.',
      facts,
    });
  },
});

export const entraCaMfaAdmins = defineControl({
  id: 'ENTRA-CA-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Multifactor authentication is required for administrator roles',
  technology: 'entra',
  category: 'Authentication',
  subcategory: 'Multifactor authentication',
  description:
    "Checks that each administrator role in Microsoft's \"Require MFA for administrators\" Conditional Access template is covered by an enabled policy that always requires MFA for all cloud apps, or that security defaults are enabled.",
  rationale:
    'Administrator accounts are the primary target of identity attacks because a single compromised administrator can take over the tenant. MFA for every administrator sign-in is a baseline expectation of Microsoft, CISA and NIST guidance.',
  severity: 'critical',
  confidence: 'high',
  applicability: { description: 'All Microsoft Entra tenants.' },
  requiredEvidence: ['entra.securityDefaults'],
  optionalEvidence: ['entra.conditionalAccessPolicies'],
  evaluation: {
    logic:
      'PASS when security defaults are enabled or every role in the Microsoft administrator MFA template is included (directly or through "All users") and not excluded by an enabled policy that targets all cloud apps, covers modern clients, has no narrowing conditions and always requires MFA or an authentication strength. FAIL lists roles that are not covered.',
    parameters: {},
  },
  expectedState: 'Every administrator role requires MFA at every sign-in to every cloud app.',
  remediation: {
    summary: 'Create a Conditional Access policy requiring MFA for the administrator directory roles (Microsoft template "Require multifactor authentication for admins").',
    steps: [
      'In the Microsoft Entra admin center go to Entra ID > Conditional Access > Create new policy from templates.',
      'Choose the "Require multifactor authentication for admins" template (or create the policy manually including the administrator roles listed in the finding).',
      'Exclude only your emergency access accounts.',
      'Enable the policy in Report-only mode, verify impact, then turn it On.',
    ],
    effort: 'low',
  },
  implementationConsiderations: [
    'Administrators who have not registered MFA will be required to register; ensure they can do so before enforcement.',
    'Consider requiring phishing-resistant MFA for administrators (see ENTRA-CA-004).',
    'Newly created administrator roles are not automatically added to role-based policies; review the role list periodically.',
  ],
  impact: 'Administrators are prompted for MFA at sign-in. Scripts that use administrator accounts with passwords will stop working.',
  rollback: ['Set the policy to Report-only or Off in Entra ID > Conditional Access.'],
  validation: [
    'Re-run the AdminSecOps Entra collector and confirm ENTRA-CA-002 is PASS.',
    'Use the Conditional Access "What If" tool with a Global Administrator and confirm MFA is required.',
  ],
  references: [REF.caRequireMfaAdmins, REF.securityDefaults, REF.entraBuiltInRoles, REF.attackValidAccounts],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-2(1)' },
    { framework: 'MCSB', id: 'IM-6' },
    { framework: 'MCSB', id: 'PA-1' },
    { framework: 'MITRE-ATTACK', id: 'T1078.004' },
  ],
  tags: ['mfa', 'privileged-access', 'conditional-access', 'identity'],
  evaluate: (ctx) => {
    if (securityDefaultsEnabled(ctx)) {
      return pass({
        reason: 'Security defaults are enabled and require MFA for administrator roles at every sign-in.',
        summary: 'Security defaults are enabled.',
        facts: [fact('Security defaults enabled', true)],
      });
    }
    const allPolicies = policiesOrUnlicensed(ctx);
    if (allPolicies === null) {
      return fail({
        reason: UNLICENSED_REASON,
        summary: 'No mechanism requires MFA for administrator roles.',
        facts: [fact('Security defaults enabled', false)],
        affectedObjects: MFA_ADMIN_ROLE_TEMPLATE_IDS.map((id) => affected('directoryRole', id, builtInRoleName(id))),
      });
    }
    const policies = allPolicies.filter(
      (p) =>
        ca.isEnabled(p) &&
        ca.includesAllApps(p) &&
        coversModernClients(p) &&
        ca.hasNoNarrowingConditions(p) &&
        ca.mfaRequirement(p) === 'required',
    );
    const uncovered = MFA_ADMIN_ROLE_TEMPLATE_IDS.filter((roleId) => !policies.some((p) => ca.coversRole(p, roleId)));
    const facts = [
      fact('Administrator roles checked', MFA_ADMIN_ROLE_TEMPLATE_IDS.length),
      fact('Roles without an enforced MFA policy', uncovered.length),
    ];
    if (uncovered.length === 0) {
      const used = policies.filter((p) => MFA_ADMIN_ROLE_TEMPLATE_IDS.some((r) => ca.coversRole(p, r)));
      return pass({
        reason: 'Every administrator role is covered by an enabled policy that requires MFA.',
        summary: `All ${MFA_ADMIN_ROLE_TEMPLATE_IDS.length} administrator roles require MFA.`,
        facts,
        notes: exclusionNote(used),
      });
    }
    return fail({
      reason: `${plural(uncovered.length, 'administrator role')} are not covered by an enabled MFA policy.`,
      summary: `${plural(uncovered.length, 'administrator role')} can sign in without being required to use MFA.`,
      facts,
      affectedObjects: uncovered.map((id) => affected('directoryRole', id, builtInRoleName(id), 'Not covered by an enabled MFA Conditional Access policy')),
    });
  },
});

export const entraCaBlockLegacyAuth = defineControl({
  id: 'ENTRA-CA-003',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Legacy authentication is blocked',
  technology: 'entra',
  category: 'Authentication',
  subcategory: 'Legacy authentication',
  description:
    'Checks that legacy authentication protocols (Exchange ActiveSync and other clients such as IMAP, POP, SMTP AUTH and older Office clients) are blocked for all users by security defaults or an enabled Conditional Access policy.',
  rationale:
    'Legacy authentication protocols cannot perform MFA, so attackers use them to bypass MFA with stolen or sprayed passwords. Blocking legacy authentication closes this bypass.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'All Microsoft Entra tenants.' },
  requiredEvidence: ['entra.securityDefaults'],
  optionalEvidence: ['entra.conditionalAccessPolicies'],
  evaluation: {
    logic:
      'PASS when security defaults are enabled or an enabled Conditional Access policy includes all users and all cloud apps, targets both the "Exchange ActiveSync clients" and "Other clients" client app types and grants Block. REVIEW when such a policy is only in report-only mode. FAIL otherwise.',
    parameters: {},
  },
  expectedState: 'An enabled Conditional Access policy (or security defaults) blocks legacy authentication for all users.',
  remediation: {
    summary: 'Create a Conditional Access policy that blocks legacy authentication for all users.',
    steps: [
      'Review the sign-in logs filtered by Client app = legacy authentication clients to identify remaining users and applications.',
      'Migrate those clients to modern authentication (for example replace SMTP AUTH devices with an SMTP relay or Microsoft Graph).',
      'Create a Conditional Access policy: Users = All users (exclude emergency access accounts), Target resources = All resources, Conditions > Client apps = Exchange ActiveSync clients and Other clients, Grant = Block access.',
      'Run in Report-only mode, confirm impact, then turn the policy On.',
    ],
    effort: 'medium',
  },
  implementationConsiderations: [
    'Multifunction printers and line-of-business applications that send mail via SMTP AUTH will stop working; plan alternatives first.',
    'Exchange Online has retired Basic authentication for most protocols, but SMTP AUTH and third-party identity provider scenarios can still expose legacy authentication.',
  ],
  impact: 'Clients using basic/legacy authentication can no longer sign in.',
  rollback: ['Set the policy to Report-only or Off.'],
  validation: [
    'Re-run the AdminSecOps Entra collector and confirm ENTRA-CA-003 is PASS.',
    'Check sign-in logs for failures with Client app "Other clients" after enforcement to identify breakage.',
  ],
  references: [REF.caBlockLegacyAuth, REF.securityDefaults, REF.attackPasswordSpraying],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-2(1)' },
    { framework: 'NIST-800-53r5', id: 'CM-7' },
    { framework: 'MCSB', id: 'IM-7' },
    { framework: 'MITRE-ATTACK', id: 'T1110.003' },
  ],
  tags: ['legacy-authentication', 'conditional-access', 'identity'],
  evaluate: (ctx) => {
    if (securityDefaultsEnabled(ctx)) {
      return pass({
        reason: 'Security defaults are enabled and block legacy authentication.',
        summary: 'Security defaults are enabled.',
        facts: [fact('Security defaults enabled', true)],
      });
    }
    const policies = policiesOrUnlicensed(ctx);
    if (policies === null) {
      return fail({ reason: UNLICENSED_REASON, summary: 'Legacy authentication protocols are not blocked.', facts: [fact('Security defaults enabled', false)] });
    }
    const blocking = policies.filter(
      (p) => ca.blocksLegacyAuthentication(p) && ca.includesAllUsers(p) && ca.includesAllApps(p),
    );
    const enforced = blocking.filter((p) => ca.isEnabled(p));
    const facts = [
      fact('Security defaults enabled', false),
      fact('Enabled policies blocking legacy authentication for all users', enforced.length),
    ];
    if (enforced.length > 0) {
      return pass({
        reason: `Legacy authentication is blocked by ${enforced.map((p) => `"${p.displayName}"`).join(', ')}.`,
        summary: 'An enabled Conditional Access policy blocks legacy authentication for all users.',
        facts,
        notes: exclusionNote(enforced),
      });
    }
    if (blocking.length > 0) {
      return review({
        reason: 'A policy that blocks legacy authentication exists but is not enabled (report-only or off).',
        summary: 'Legacy authentication blocking is configured but not enforced.',
        facts,
        affectedObjects: blocking.map((p) => policyObject(p, `state=${p.state}`)),
      });
    }
    return fail({
      reason: 'No enabled Conditional Access policy blocks legacy authentication and security defaults are disabled.',
      summary: 'Legacy authentication protocols are not blocked.',
      facts,
    });
  },
});

