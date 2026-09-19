import {
  builtInRoleName,
  ca,
  HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS,
  licenceView,
  SERVICE_PLANS,
} from '@adminsecops/inventory';
import type { ConditionalAccessPolicy } from '@adminsecops/schemas';
import { defineControl, type Applicability, type ControlContext } from '../../define.js';
import { affected, fact, fail, pass, plural, review } from '../../helpers.js';
import { REF } from '../../references.js';

type Policy = ConditionalAccessPolicy;

const MITRE_CLOUD = { framework: 'MITRE-ATTACK' as const, id: 'T1078.004' };

function requiresP2(ctx: ControlContext): Applicability {
  const licences = licenceView(ctx.data('entra.subscribedSkus'));
  return licences.hasServicePlan(SERVICE_PLANS.entraIdP2)
    ? { applicable: true }
    : {
        applicable: false,
        reason: 'Risk-based Conditional Access requires Microsoft Entra ID P2; no active P2 service plan was found in the tenant licences.',
      };
}

/** Enabled, all apps, no location/platform narrowing (risk conditions are allowed). */
function broadEnabled(policy: Policy): boolean {
  const c = policy.conditions;
  const narrowedByLocation =
    c.locations !== null &&
    (c.locations.excludeLocations.length > 0 ||
      (c.locations.includeLocations.length > 0 && !c.locations.includeLocations.some((l) => l.toLowerCase() === 'all')));
  const narrowedByPlatform =
    c.platforms !== null &&
    c.platforms.includePlatforms.length > 0 &&
    !c.platforms.includePlatforms.some((p) => p.toLowerCase() === 'all');
  return ca.isEnabled(policy) && ca.includesAllApps(policy) && !narrowedByLocation && !narrowedByPlatform;
}

export const entraCaPhishingResistantAdmins = defineControl({
  id: 'ENTRA-CA-004',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Phishing-resistant MFA is required for highly privileged roles',
  technology: 'entra',
  category: 'Authentication',
  subcategory: 'Phishing-resistant MFA',
  description:
    'Checks that every highly privileged Microsoft Entra role is covered by an enabled Conditional Access policy that requires the built-in "Phishing-resistant MFA" authentication strength for all cloud apps.',
  rationale:
    'Adversary-in-the-middle phishing kits routinely capture passwords together with one-time codes and push approvals, then replay the session. Phishing-resistant methods (FIDO2 security keys, passkeys, Windows Hello for Business, certificate-based authentication) are bound to the legitimate site and defeat these attacks. Administrators are the highest-value target, so Microsoft and CISA recommend phishing-resistant MFA for privileged roles first.',
  severity: 'high',
  confidence: 'high',
  applicability: {
    description: 'Tenants licensed for Conditional Access (Microsoft Entra ID P1 or P2). Without Conditional Access the collector reports the policy dataset as not applicable.',
  },
  requiredEvidence: ['entra.conditionalAccessPolicies'],
  evaluation: {
    logic:
      'For each highly privileged role (Global, Privileged Role, Privileged Authentication, Security, Conditional Access, Exchange, SharePoint, User, Application, Cloud Application, Hybrid Identity, Intune and Authentication Policy Administrator) look for an enabled policy that includes the role (directly or via All users), does not exclude it, targets all cloud apps, has no location/platform narrowing and whose grant uses the built-in phishing-resistant authentication strength. PASS when all roles are covered. REVIEW when uncovered roles are only covered by a custom authentication strength (its allowed methods are not in the evidence). FAIL otherwise, listing uncovered roles.',
    parameters: {},
  },
  expectedState: 'Every highly privileged role must satisfy the phishing-resistant MFA authentication strength at every sign-in.',
  remediation: {
    summary: 'Register phishing-resistant credentials for administrators, then enforce the "Phishing-resistant MFA" authentication strength for privileged roles with Conditional Access.',
    steps: [
      'Enable passkey (FIDO2) and/or certificate-based authentication in Entra ID > Authentication methods > Policies.',
      'Have each administrator register a phishing-resistant method (FIDO2 security key, passkey in Microsoft Authenticator, or Windows Hello for Business).',
      'Create a Conditional Access policy from the template "Require phishing-resistant multifactor authentication for admins", including the roles listed in this finding and excluding only emergency access accounts.',
      'Run the policy in Report-only mode, confirm every administrator can satisfy it, then set it to On.',
    ],
    effort: 'medium',
  },
  implementationConsiderations: [
    'Administrators without a registered phishing-resistant method will be locked out once the policy is enforced; confirm registration first.',
    'Some administrative tools and older PowerShell modules may not support phishing-resistant methods from every client; test the tools your team uses.',
    'Keep at least one emergency access account excluded and protected with a FIDO2 key stored securely.',
  ],
  impact: 'Administrators must sign in with a FIDO2 key, passkey, Windows Hello for Business or certificate. One-time codes, SMS and push approvals are no longer accepted for these roles.',
  rollback: ['Set the Conditional Access policy to Report-only or Off, or change its grant to the "Multifactor authentication" strength.'],
  validation: [
    'Re-run the AdminSecOps Entra collector and confirm ENTRA-CA-004 is PASS.',
    'Sign in as an administrator and confirm the sign-in log shows the phishing-resistant authentication strength was satisfied.',
  ],
  references: [REF.caPhishingResistantAdmins, REF.authenticationStrengths, REF.emergencyAccess],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-2(1)' },
    { framework: 'NIST-800-53r5', id: 'IA-2(8)' },
    { framework: 'MCSB', id: 'IM-6' },
    { framework: 'CISA-SCuBA', id: 'MS.AAD.3.6v1' },
    { framework: 'MITRE-ATTACK', id: 'T1557' },
    MITRE_CLOUD,
  ],
  tags: ['mfa', 'privileged-access', 'conditional-access', 'identity'],
  evaluate: (ctx) => {
    const policies = ctx.data('entra.conditionalAccessPolicies').filter(broadEnabled);
    const roles = [...HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS];
    const phishingResistant = policies.filter((p) => p.grantControls?.authenticationStrength?.id === ca.PHISHING_RESISTANT_STRENGTH_ID);
    const builtInIds = new Set([ca.MFA_STRENGTH_ID, ca.PASSWORDLESS_STRENGTH_ID, ca.PHISHING_RESISTANT_STRENGTH_ID]);
    const customStrength = policies.filter((p) => {
      const id = p.grantControls?.authenticationStrength?.id;
      return id !== undefined && !builtInIds.has(id);
    });
    const uncovered = roles.filter((r) => !phishingResistant.some((p) => ca.coversRole(p, r)));
    const facts = [fact('Highly privileged roles checked', roles.length), fact('Roles without phishing-resistant MFA', uncovered.length)];
    if (uncovered.length === 0) {
      return pass({ reason: 'Every highly privileged role requires the phishing-resistant MFA authentication strength.', summary: 'Phishing-resistant MFA is enforced for all highly privileged roles.', facts });
    }
    const customOnly = uncovered.filter((r) => customStrength.some((p) => ca.coversRole(p, r)));
    const objects = uncovered.map((id) =>
      affected(
        'directoryRole',
        id,
        builtInRoleName(id),
        customOnly.includes(id) ? 'Covered only by a custom authentication strength; confirm it allows only phishing-resistant methods' : 'No enabled policy requires phishing-resistant MFA',
      ),
    );
    if (customOnly.length === uncovered.length) {
      return review({
        reason: 'Uncovered roles are protected by a custom authentication strength whose allowed methods are not included in the evidence.',
        summary: `${plural(uncovered.length, 'role')} rely on a custom authentication strength that must be confirmed as phishing-resistant.`,
        facts,
        affectedObjects: objects,
      });
    }
    return fail({
      reason: `${plural(uncovered.length, 'highly privileged role')} are not required to use phishing-resistant MFA.`,
      summary: `${plural(uncovered.length, 'highly privileged role')} can sign in with phishable MFA methods.`,
      facts,
      affectedObjects: objects,
    });
  },
});

export const entraCaBlockDeviceCode = defineControl({
  id: 'ENTRA-CA-005',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Device code flow is blocked by Conditional Access',
  technology: 'entra',
  category: 'Authentication',
  subcategory: 'Authentication flows',
  description:
    'Checks that an enabled Conditional Access policy blocks the device code authentication flow for all users and all cloud apps.',
  rationale:
    'Device code phishing tricks users into entering a code on the legitimate Microsoft sign-in page, which grants the attacker tokens for the victim account even when MFA is used. Most organisations never need the device code flow; Microsoft recommends blocking it wherever possible and allowing it only for the specific users or devices that require it.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Tenants licensed for Conditional Access (Microsoft Entra ID P1 or P2).' },
  requiredEvidence: ['entra.conditionalAccessPolicies'],
  evaluation: {
    logic:
      'PASS when an enabled policy includes all users and all cloud apps, has an authentication flows condition whose transfer methods include deviceCodeFlow, and grants Block. REVIEW when such a policy exists but is report-only or disabled, or when a blocking policy targets only some users. FAIL otherwise.',
    parameters: {},
  },
  expectedState: 'Device code flow is blocked for all users, with narrowly scoped exceptions only where required.',
  remediation: {
    summary: 'Create a Conditional Access policy that blocks the device code flow.',
    steps: [
      'Review sign-in logs (filter: Authentication protocol = Device code) to find legitimate users of the flow, such as meeting-room devices.',
      'Create a policy: Users = All users (exclude emergency access accounts and any group that genuinely needs device code), Target resources = All resources, Conditions > Authentication flows = Device code flow, Grant = Block access.',
      'Run in Report-only mode, review impact, then turn it On.',
    ],
    effort: 'low',
  },
  implementationConsiderations: [
    'Shared devices, Microsoft Teams Rooms and some command-line tools use device code sign-in; scope exceptions to those accounts rather than leaving the flow open.',
    'The authentication flows condition is not available in all clouds or older policy templates; confirm it appears in your admin center.',
  ],
  impact: 'Users can no longer complete sign-ins that use a device code. Excluded accounts are unaffected.',
  rollback: ['Set the policy to Report-only or Off.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-CA-005 is PASS.', 'Attempt a device code sign-in with a test user and confirm it is blocked.'],
  references: [REF.caAuthenticationFlows],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-3' },
    { framework: 'MCSB', id: 'IM-7' },
    { framework: 'MITRE-ATTACK', id: 'T1528' },
    { framework: 'MITRE-ATTACK', id: 'T1566' },
  ],
  tags: ['conditional-access', 'identity', 'credential-exposure'],
  evaluate: (ctx) => {
    const policies = ctx.data('entra.conditionalAccessPolicies');
    const blocking = policies.filter(
      (p) => ca.blocksAccess(p) && ca.transferMethods(p).some((m) => m.toLowerCase() === 'devicecodeflow'),
    );
    const enforcedAll = blocking.filter((p) => ca.isEnabled(p) && ca.includesAllUsers(p) && ca.includesAllApps(p));
    const facts = [fact('Policies blocking device code flow', blocking.length), fact('Enabled for all users and apps', enforcedAll.length)];
    if (enforcedAll.length > 0) {
      return pass({ reason: `Device code flow is blocked by ${enforcedAll.map((p) => `"${p.displayName}"`).join(', ')}.`, summary: 'Device code flow is blocked for all users.', facts });
    }
    if (blocking.length > 0) {
      return review({
        reason: 'Policies that block device code flow exist but are not enabled, or target only some users or apps.',
        summary: 'Device code flow blocking is configured but not enforced tenant-wide.',
        facts,
        affectedObjects: blocking.map((p) => affected('conditionalAccessPolicy', p.id, p.displayName, `state=${p.state}; allUsers=${ca.includesAllUsers(p)}`)),
      });
    }
    return fail({ reason: 'No Conditional Access policy blocks the device code flow.', summary: 'The device code authentication flow is allowed for all users.', facts });
  },
});

function riskControl(kind: 'signIn' | 'user') {
  const signIn = kind === 'signIn';
  return defineControl({
    id: signIn ? 'ENTRA-CA-006' : 'ENTRA-CA-007',
    version: '1.0.0',
    lifecycle: 'stable',
    title: signIn ? 'High-risk sign-ins are challenged or blocked' : 'High-risk users are remediated or blocked',
    technology: 'entra',
    category: 'Identity Protection',
    subcategory: signIn ? 'Sign-in risk' : 'User risk',
    description: signIn
      ? 'Checks that an enabled Conditional Access policy applies to all users and all cloud apps when Microsoft Entra ID Protection rates a sign-in as high risk, and either blocks it or requires MFA.'
      : 'Checks that an enabled Conditional Access policy applies to all users and all cloud apps when a user is rated high risk, and either blocks access or requires a secure password change.',
    rationale: signIn
      ? 'ID Protection detects sign-ins that are likely not performed by the account owner (for example anonymous IP addresses, impossible travel, token anomalies). Without a policy acting on that signal, a detected attack is only reported, not stopped.'
      : 'A high user risk means Microsoft has evidence the account credentials are compromised (for example leaked credentials). Without a policy the compromised password keeps working until an administrator reacts manually.',
    severity: 'high',
    confidence: 'high',
    applicability: { description: 'Tenants with Microsoft Entra ID P2 (required for risk-based Conditional Access).' },
    requiredEvidence: ['entra.conditionalAccessPolicies', 'entra.subscribedSkus'],
    evaluation: {
      logic: signIn
        ? 'NOT_APPLICABLE without an Entra ID P2 service plan. PASS when an enabled policy targets all users and all cloud apps, includes the "high" sign-in risk level and grants Block or requires MFA / an authentication strength. REVIEW when such a policy is report-only. FAIL otherwise.'
        : 'NOT_APPLICABLE without an Entra ID P2 service plan. PASS when an enabled policy targets all users and all cloud apps, includes the "high" user risk level and grants Block or requires a password change. REVIEW when such a policy is report-only. FAIL otherwise.',
      parameters: {},
    },
    expectedState: signIn
      ? 'An enabled risk-based policy requires MFA for (or blocks) high-risk sign-ins for all users.'
      : 'An enabled risk-based policy requires a secure password change for (or blocks) high-risk users.',
    remediation: {
      summary: signIn
        ? 'Create a Conditional Access policy that requires MFA (or blocks) when sign-in risk is high.'
        : 'Create a Conditional Access policy that requires a secure password change (or blocks) when user risk is high.',
      steps: signIn
        ? [
            'Ensure users are registered for MFA (a risk-based MFA challenge cannot be satisfied otherwise).',
            'Create a policy: Users = All users (exclude emergency access accounts), Target resources = All resources, Conditions > Sign-in risk = High (optionally Medium), Grant = Require authentication strength / MFA, Session = Sign-in frequency Every time.',
            'Run in Report-only mode, review the Identity Protection risky sign-ins report, then turn it On.',
          ]
        : [
            'Enable self-service password reset or password writeback for hybrid users so users can remediate risk themselves.',
            'Create a policy: Users = All users (exclude emergency access accounts), Target resources = All resources, Conditions > User risk = High, Grant = Require authentication strength and Require password change, Session = Sign-in frequency Every time.',
            'Run in Report-only mode, review risky users, then turn it On.',
          ],
      effort: 'low',
    },
    implementationConsiderations: [
      'Risk-based policies require Microsoft Entra ID P2 for every user they protect.',
      signIn
        ? 'Users not yet registered for MFA cannot satisfy the challenge and will be blocked.'
        : 'Hybrid users need password writeback for a cloud password change to reach Active Directory.',
      'Microsoft is retiring the legacy Identity Protection user/sign-in risk policies in favour of Conditional Access; configure the Conditional Access version.',
    ],
    impact: signIn ? 'Users are prompted for MFA (or blocked) only when a sign-in is rated high risk.' : 'High-risk users must change their password securely (or are blocked) before continuing.',
    rollback: ['Set the Conditional Access policy to Report-only or Off.'],
    validation: [
      `Re-run the AdminSecOps Entra collector and confirm ${signIn ? 'ENTRA-CA-006' : 'ENTRA-CA-007'} is PASS.`,
      'Use the Conditional Access What If tool with the matching risk level to confirm the policy applies.',
    ],
    references: [signIn ? REF.caSignInRisk : REF.caUserRisk],
    frameworkMappings: [
      { framework: 'NIST-800-53r5', id: 'SI-4' },
      { framework: 'NIST-800-53r5', id: 'AC-2(12)' },
      { framework: 'MCSB', id: 'IM-7' },
      { framework: 'CISA-SCuBA', id: signIn ? 'MS.AAD.2.3v1' : 'MS.AAD.2.1v1' },
      MITRE_CLOUD,
    ],
    tags: ['conditional-access', 'identity'],
    applies: requiresP2,
    evaluate: (ctx) => {
      const policies = ctx.data('entra.conditionalAccessPolicies');
      const matching = policies.filter((p) => {
        const levels = (signIn ? p.conditions.signInRiskLevels : p.conditions.userRiskLevels).map((l) => l.toLowerCase());
        if (!levels.includes('high') || !ca.includesAllUsers(p) || !ca.includesAllApps(p)) return false;
        if (ca.blocksAccess(p)) return true;
        if (signIn) return ca.mfaRequirement(p) === 'required';
        return p.grantControls?.builtInControls.some((c) => c.toLowerCase() === 'passwordchange') ?? false;
      });
      const enforced = matching.filter((p) => ca.isEnabled(p));
      const facts = [fact('Matching policies', matching.length), fact('Enabled matching policies', enforced.length)];
      if (enforced.length > 0) {
        return pass({ reason: `High ${signIn ? 'sign-in' : 'user'} risk is handled by ${enforced.map((p) => `"${p.displayName}"`).join(', ')}.`, summary: 'An enabled risk-based policy covers high risk.', facts });
      }
      if (matching.length > 0) {
        return review({
          reason: 'A risk-based policy exists but is not enabled.',
          summary: 'Risk-based policy is configured but not enforced.',
          facts,
          affectedObjects: matching.map((p) => affected('conditionalAccessPolicy', p.id, p.displayName, `state=${p.state}`)),
        });
      }
      return fail({
        reason: `No enabled Conditional Access policy acts on high ${signIn ? 'sign-in' : 'user'} risk for all users.`,
        summary: `High ${signIn ? 'sign-in' : 'user'} risk detections are not acted on automatically.`,
        facts,
      });
    },
  });
}

export const entraCaSignInRisk = riskControl('signIn');
export const entraCaUserRisk = riskControl('user');
