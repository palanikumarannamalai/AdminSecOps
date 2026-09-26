import { defineControl } from '../../define.js';
import { affected, fact, fail, pass, plural, review } from '../../helpers.js';
import { REF } from '../../references.js';

export const entraMembersRegisteredForMfa = defineControl({
  id: 'ENTRA-AUTH-001',
  version: '1.0.2',
  lifecycle: 'stable',
  title: 'Member users are registered for multifactor authentication',
  technology: 'entra',
  category: 'Authentication',
  subcategory: 'MFA registration',
  description: 'Uses the authentication methods registration report to find member users who have not registered any MFA method.',
  rationale:
    'An MFA policy only protects users who have registered a method. Unregistered users are either blocked or, worse, can be registered by an attacker who signs in first with a stolen password.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Tenants licensed for the registration report (Microsoft Entra ID P1 or P2).' },
  requiredEvidence: ['entra.userRegistrationDetails'],
  evaluation: {
    logic:
      'Consider users whose userType is "member" (case-insensitive). FAIL when the share of members with isMfaRegistered = false exceeds maxUnregisteredPercent (default 0: any unregistered member fails). The report includes disabled accounts; they are counted because the evidence does not include account state.',
    parameters: { maxUnregisteredPercent: 0 },
  },
  expectedState: 'All member users have registered at least one MFA method.',
  remediation: {
    summary: 'Drive MFA registration for the remaining users.',
    steps: [
      'Enable the registration campaign (Entra ID > Authentication methods > Registration campaign) to prompt users to register Microsoft Authenticator or passkeys.',
      'Require registration via a Conditional Access policy on the "Register security information" user action from trusted locations or compliant devices.',
      'Follow up with users listed in this finding; disable or delete accounts that are no longer used.',
    ],
    effort: 'medium',
  },
  implementationConsiderations: [
    'Protect the registration process itself (for example with Temporary Access Pass or trusted network requirements) so attackers cannot register methods.',
    'Shared or service accounts appearing in the list should be replaced by workload identities rather than registered.',
  ],
  impact: 'Users are prompted to register an authentication method at sign-in.',
  rollback: ['Disable the registration campaign or the registration Conditional Access policy.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-AUTH-001 is PASS.'],
  references: [REF.userRegistrationDetails, REF.caRequireMfaAllUsers],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-2(1)' },
    { framework: 'NIST-800-53r5', id: 'IA-2(2)' },
    { framework: 'MCSB', id: 'IM-6' },
  ],
  tags: ['mfa', 'identity'],
  evaluate: (ctx) => {
    const maxPercent = ctx.num('maxUnregisteredPercent');
    const registrations = ctx.data('entra.userRegistrationDetails');
    const members = registrations.filter((u) => u.userType?.toLowerCase() === 'member');
    const unregistered = members.filter((u) => !u.isMfaRegistered);
    const percent = members.length === 0 ? 0 : Math.round((unregistered.length / members.length) * 1000) / 10;
    const facts = [fact('Member users', members.length), fact('Not registered for MFA', unregistered.length), fact('Unregistered (%)', percent)];
    if (unregistered.length > 0 && percent > maxPercent) {
      return fail({
        reason: `${plural(unregistered.length, 'member user')} (${percent}%) have not registered an MFA method.`,
        summary: 'Some members have no registered MFA method; enforced MFA may block their access until registration.',
        facts,
        affectedObjects: unregistered.map((u) => affected('user', u.id, u.userPrincipalName, 'No MFA method registered')),
      });
    }
    if (members.length === 0 || registrations.some(u => u.userType === null)) return review({ reason: 'Member registration coverage cannot be established from an empty report or rows with unknown user type.', summary: 'MFA registration coverage needs validation.', confidence: 'medium', facts });
    return pass({ reason: `MFA registration meets the threshold (${percent}% unregistered).`, summary: 'Member users are registered for MFA.', facts });
  },
});

export const entraWeakMethodsDisabled = defineControl({
  id: 'ENTRA-AUTH-002',
  version: '1.0.2',
  lifecycle: 'stable',
  title: 'SMS and voice call authentication methods are disabled',
  technology: 'entra',
  category: 'Authentication',
  subcategory: 'Authentication methods',
  description: 'Checks whether the SMS and voice call methods are enabled in the authentication methods policy.',
  rationale:
    'SMS and voice are the weakest MFA methods: they are vulnerable to SIM swapping, telephony interception and real-time phishing. Microsoft recommends moving users to Microsoft Authenticator, passkeys or other stronger methods and keeping telephony only where there is no alternative.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'All Microsoft Entra tenants.' },
  requiredEvidence: ['entra.authenticationMethodsPolicy'],
  evaluation: {
    logic:
      'PASS when both Sms and Voice configurations are explicitly disabled and policy migration is complete. Otherwise REVIEW incomplete settings or migration. REVIEW when either is enabled, listing its targets: some organisations still need telephony for specific users, which only an administrator can decide.',
    parameters: {},
  },
  expectedState: 'SMS and voice call are disabled, or enabled only for a small documented group without alternatives.',
  remediation: {
    summary: 'Move users to stronger methods, then disable SMS and voice call.',
    steps: [
      'Use the authentication methods activity report to find users who rely on SMS or voice.',
      'Run a registration campaign for Microsoft Authenticator or passkeys.',
      'In Entra ID > Authentication methods > Policies, disable SMS and Voice call, or scope them to a small exception group.',
    ],
    effort: 'medium',
  },
  implementationConsiderations: [
    'Users who only have SMS or voice registered will be unable to complete MFA; migrate them first.',
    'SMS may still be used for self-service password reset if enabled there; review SSPR settings separately.',
  ],
  impact: 'Users can no longer use text messages or phone calls to complete MFA.',
  rollback: ['Re-enable the SMS and/or Voice call methods in Authentication methods > Policies.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-AUTH-002 is PASS.'],
  references: [REF.smsVoiceMethods, REF.authMethodsManage, REF.nist80063b],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-2(8)' },
    { framework: 'MCSB', id: 'IM-6' },
    { framework: 'MITRE-ATTACK', id: 'T1111' },
  ],
  tags: ['mfa', 'identity'],
  evaluate: (ctx) => {
    const policy = ctx.data('entra.authenticationMethodsPolicy');
    const configs = policy.authenticationMethodConfigurations;
    const weak = configs.filter((c) => ['sms', 'voice'].includes(c.id.toLowerCase()) && c.state.toLowerCase() === 'enabled');
    const facts = [
      fact('SMS enabled', weak.some((c) => c.id.toLowerCase() === 'sms')),
      fact('Voice call enabled', weak.some((c) => c.id.toLowerCase() === 'voice')),
    ];
    if (weak.length === 0 && (policy.policyMigrationState !== 'migrationComplete' || !['sms', 'voice'].every(id => configs.some(c => c.id.toLowerCase() === id && c.state.toLowerCase() === 'disabled')))) return review({ reason: 'Explicit disabled states for both telephony methods or completed policy migration are not established.', summary: 'Confirm authentication policy completeness and legacy method settings.', confidence: 'medium', facts });
    if (weak.length === 0) return pass({ reason: 'SMS and voice call methods are explicitly disabled in the migrated authentication policy.', summary: 'Telephony MFA methods are disabled in this policy.', facts });
    return review({
      reason: `${weak.map((c) => c.id).join(' and ')} ${weak.length === 1 ? 'is' : 'are'} enabled; confirm whether any users still need telephony methods.`,
      summary: 'Weak telephony authentication methods are enabled.',
      facts,
      affectedObjects: weak.map((c) =>
        affected('authenticationMethod', c.id, c.id, `Targets: ${c.includeTargets.map((t) => (t.id === 'all_users' ? 'all users' : `${t.targetType ?? 'target'} ${t.id}`)).join(', ') || 'none'}`),
      ),
    });
  },
});
