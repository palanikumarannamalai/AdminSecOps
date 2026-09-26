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

function coversModernClients(policy: Policy): boolean {
  if (ca.includesAllClientApps(policy)) return true;
  const types = policy.conditions.clientAppTypes.map((t) => t.toLowerCase());
  return types.includes('browser') && types.includes('mobileappsanddesktopclients');
}

function hasIdentityExclusions(policy: Policy): boolean {
  const ex = ca.exclusions(policy);
  return ex.users > 0 || ex.groups > 0 || ex.guestsOrExternal;
}

export const entraCaPhishingResistantAdmins = defineControl({
  id: 'ENTRA-CA-004',
  version: '1.0.2',
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
      'For each highly privileged role (Global, Privileged Role, Privileged Authentication, Security, Conditional Access, Exchange, SharePoint, User, Application, Cloud Application, Hybrid Identity, Intune and Authentication Policy Administrator) look for an enabled policy that includes the role (directly or via All users), does not exclude it, targets all cloud apps, covers modern clients, has no narrowing conditions and whose grant unconditionally requires the built-in phishing-resistant authentication strength. PASS when all roles are covered without unverified identity exclusions. REVIEW when coverage depends on identity exclusions or uncovered roles are only covered by a custom authentication strength (its allowed methods are not in the evidence). FAIL otherwise, listing uncovered roles.',
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
    'Re-run the AdminSecOps Entra collector and confirm ENTRA-CA-004 is PASS, or validate documented emergency access exclusions if it is REVIEW.',
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
    const allPolicies = ctx.data('entra.conditionalAccessPolicies');
    const policies = allPolicies.filter((p) => ca.isEnabled(p) && ca.includesAllApps(p) && coversModernClients(p) && ca.hasNoNarrowingConditions(p));
    const roles = [...HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS];
    const phishingResistant = policies.filter((p) => p.grantControls?.authenticationStrength?.id === ca.PHISHING_RESISTANT_STRENGTH_ID && ca.mfaRequirement(p) === 'required' && (p.grantControls.operator === 'AND' || p.grantControls.builtInControls.length === 0));
    const builtInIds = new Set([ca.MFA_STRENGTH_ID, ca.PASSWORDLESS_STRENGTH_ID, ca.PHISHING_RESISTANT_STRENGTH_ID]);
    const customStrength = policies.filter((p) => {
      const id = p.grantControls?.authenticationStrength?.id;
      return id !== undefined && !builtInIds.has(id) && (p.grantControls?.operator === 'AND' || (p.grantControls?.builtInControls.length === 0 && p.grantControls.customAuthenticationFactors.length === 0 && p.grantControls.termsOfUse.length === 0));
    });
    const uncovered = roles.filter((r) => !phishingResistant.some((p) => ca.coversRole(p, r)));
    const facts = [fact('Highly privileged roles checked', roles.length), fact('Roles without phishing-resistant MFA', uncovered.length)];
    const uncertain = roles.filter((r) => !phishingResistant.some((p) => ca.coversRole(p, r) && !hasIdentityExclusions(p)));
    if (uncovered.length === 0 && uncertain.length > 0) {
      return review({
        reason: 'Phishing-resistant role coverage depends on policies with identity exclusions.',
        summary: 'Validate excluded identities and their alternative protection before confirming coverage.',
        facts,
        affectedObjects: uncertain.map((id) => affected('directoryRole', id, builtInRoleName(id), 'Coverage depends on excluded identities')),
      });
    }
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
    const unresolved = allPolicies.filter(p => Boolean(p.grantControls?.authenticationStrength) &&
      (p.conditions.users.includeGroups.length > 0 || p.conditions.users.includeUsers.some(user => user.toLowerCase() !== 'all')));
    if (unresolved.length > 0) return review({ reason: `Authentication-strength policies were found (${unresolved.map(p => p.displayName).join(', ')}), but user/group targeting cannot be resolved to administrator coverage.`, summary: 'Confirm targeted identities and allowed authentication methods before judging privileged coverage.', confidence: 'medium', facts, affectedObjects: unresolved.map(p => affected('conditionalAccessPolicy', p.id, p.displayName)) });
    return fail({
      reason: `${plural(uncovered.length, 'highly privileged role template')} lack a qualifying enforced phishing-resistant MFA policy.`,
      summary: `No qualifying enforced phishing-resistant MFA policy was found for ${plural(uncovered.length, 'highly privileged role template')}.`,
      facts,
      affectedObjects: objects,
    });
  },
});

export const entraCaBlockDeviceCode = defineControl({
  id: 'ENTRA-CA-005',
  version: '1.0.2',
  lifecycle: 'stable',
  title: 'Device code flow blocking is configured or validated',
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
  requiredEvidence: ['entra.securityDefaults'],
  optionalEvidence: ['entra.conditionalAccessPolicies'],
  evaluation: {
    logic:
      'REVIEW when security defaults are enabled because the documented device-code rollout must be verified for this tenant. Otherwise PASS for an enabled tenant-wide device-code block without narrowing or exclusions; REVIEW for incomplete scope or non-enforcing policies; FAIL if no configured block is found. Missing CA evidence is NOT_ASSESSED.',
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
    if (ctx.data('entra.securityDefaults').isEnabled) {
      return review({ reason: 'Security defaults are enabled and may supply device-code blocking; the new-tenant rollout condition is not established from the evidence.', summary: 'Verify effective device-code blocking before adding a duplicate Conditional Access policy.', confidence: 'medium' });
    }
    const policies = ctx.data('entra.conditionalAccessPolicies');
    const blocking = policies.filter(
      (p) => ca.blocksAccess(p) && ca.transferMethods(p).some((m) => m.toLowerCase() === 'devicecodeflow'),
    );
    const enforcedAll = blocking.filter((p) => ca.isEnabled(p) && ca.includesAllUsers(p) && ca.includesAllApps(p) && ca.includesAllClientApps(p) && ca.exclusions(p).total === 0 && ca.hasNoNarrowingConditions({ ...p, conditions: { ...p.conditions, authenticationFlows: null } }));
    const facts = [fact('Policies blocking device code flow', blocking.length), fact('Enabled for all users and apps', enforcedAll.length)];
    if (enforcedAll.length > 0) {
      return pass({ reason: `Device code flow is blocked by ${enforcedAll.map((p) => `"${p.displayName}"`).join(', ')}.`, summary: 'Device code flow is blocked for all users.', facts });
    }
    if (blocking.length > 0) {
      return review({
        reason: 'Policies that block device code flow exist but are not enabled, or have user, app, client or condition scope restrictions requiring validation.',
        summary: 'Device code flow blocking needs enforcement or scope validation.',
        facts,
        affectedObjects: blocking.map((p) => affected('conditionalAccessPolicy', p.id, p.displayName, `state=${p.state}; allUsers=${ca.includesAllUsers(p)}`)),
      });
    }
    return fail({ reason: 'No Conditional Access policy blocks the device code flow.', summary: 'No Conditional Access device code blocking policy was found in the collected evidence.', facts });
  },
});

function riskControl(kind: 'signIn' | 'user') {
  const signIn = kind === 'signIn';
  return defineControl({
    id: signIn ? 'ENTRA-CA-006' : 'ENTRA-CA-007',
    version: '1.0.3',
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
        ? 'NOT_APPLICABLE without P2. PASS for complete high-risk coverage (including unconditional coverage) that blocks access or requires MFA with Every time sign-in frequency. REVIEW for policy scope or fresh-challenge gaps and unknown grants. FAIL when no qualifying configured response is found.'
        : 'NOT_APPLICABLE without P2. PASS for complete high-user-risk coverage that blocks, requires passwordChange AND MFA, or riskRemediation AND authentication strength with Every time sign-in frequency. REVIEW for scope, enforcement or unknown-grant gaps. FAIL when no qualifying response is found.',
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
            'Create a policy: Users = All users with documented emergency exclusions, Resources = All resources, User risk = High, Grant = Require risk remediation and authentication strength, Session = Every time. The legacy password-change alternative requires MFA AND password change.',
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
      { framework: 'CISA-SCuBA', id: signIn ? 'MS.AAD.2.3v1' : 'MS.AAD.2.1v1', note: 'SCuBA requires blocking high risk; this Microsoft-aligned control also accepts MFA/remediation and is not equivalent SCuBA conformance.' },
      MITRE_CLOUD,
    ],
    tags: ['conditional-access', 'identity'],
    applies: requiresP2,
    evaluate: (ctx) => {
      const policies = ctx.data('entra.conditionalAccessPolicies');
      const matching = policies.filter((p) => {
        const levels = (signIn ? p.conditions.signInRiskLevels : p.conditions.userRiskLevels).map((l) => l.toLowerCase());
        if (!levels.includes('high') && !(signIn && levels.length === 0)) return false;
        if (ca.blocksAccess(p)) return true;
        if (signIn) return ca.mfaRequirement(p) === 'required';
        const grant = p.grantControls;
        if (grant?.builtInControls.some(c => c.toLowerCase() === 'riskremediation')) return grant.operator === 'AND' && grant.authenticationStrength !== null;
        if (!grant?.builtInControls.some((c) => c.toLowerCase() === 'passwordchange')) return false;
        return grant.operator === 'AND' && grant.builtInControls.some(c => c.toLowerCase() === 'mfa');
      });
      const freshChallenge = (p: Policy) => ca.blocksAccess(p) || (!signIn && !p.grantControls?.builtInControls.some(c => c.toLowerCase() === 'riskremediation')) || (p.sessionControls?.signInFrequency?.isEnabled === true && p.sessionControls.signInFrequency.frequencyInterval === 'everyTime');
      const enforced = matching.filter((p) => ca.isEnabled(p) && freshChallenge(p) && ca.includesAllUsers(p) && ca.includesAllApps(p) && ca.includesAllClientApps(p) && ca.exclusions(p).total === 0 && ca.hasNoNarrowingConditions({ ...p, conditions: { ...p.conditions, ...(signIn ? { signInRiskLevels: [] } : { userRiskLevels: [] }) } }));
      const facts = [fact('Matching policies', matching.length), fact('Enabled matching policies', enforced.length)];
      if (enforced.length > 0) {
        return pass({ reason: `High ${signIn ? 'sign-in' : 'user'} risk is handled by ${enforced.map((p) => `"${p.displayName}"`).join(', ')}.`, summary: 'An enabled policy covers high risk, either explicitly or by applying to all risk levels.', facts });
      }
      if (matching.length > 0) {
        return review({
          reason: `Potentially protective policies were found (${matching.map(p => p.displayName).join(', ')}), but enforcement, scope, exclusions or fresh sign-in frequency require validation.`,
          summary: 'Policy coverage of high risk needs enforcement or scope validation.',
          facts,
          affectedObjects: matching.map((p) => affected('conditionalAccessPolicy', p.id, p.displayName, `state=${p.state}`)),
        });
      }
      const unknownGrants = policies.filter(p => (signIn ? p.conditions.signInRiskLevels : p.conditions.userRiskLevels).includes('high') && p.grantControls?.builtInControls.includes('unknownFutureValue'));
      if (unknownGrants.length > 0) return review({ reason: 'A high-risk policy uses a grant that this evidence API did not identify. Collect evolvable enum members before evaluating it.', summary: 'Risk protection cannot be determined from unknown grant values.', confidence: 'low', facts });
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
