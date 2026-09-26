import type { DatasetData } from '@adminsecops/schemas';
import { REF } from '../../references.js';
import { defineControl } from '../../define.js';
import { affected, fact, fail, notAssessed, pass, plural, review } from '../../helpers.js';
import { AD_REF } from './references.js';

type DomainPolicies = DatasetData<'ad.passwordPolicies'>[number];
type FineGrainedPolicy = DomainPolicies['fineGrainedPolicies'][number];

function defaultPolicyObject(domain: string, detail: string) {
  return affected('adPasswordPolicy', `${domain}\\Default Domain Password Policy`, `${domain}: default domain password policy`, detail);
}

function psoObject(domain: string, pso: FineGrainedPolicy, detail: string) {
  return affected('adFineGrainedPasswordPolicy', `${domain}\\${pso.name}`, `${domain}: ${pso.name}`, detail);
}

/** A PSO only has an effect when it is linked to at least one user or group. */
function isApplied(pso: FineGrainedPolicy): boolean {
  return pso.appliesToCount > 0;
}

const NO_POLICIES = {
  reason: 'The password policy dataset was collected but contains no domains, so no policy could be evaluated.',
  summary: 'No domain password policies were returned by the collector.',
};

export const adPwdMinimumLength = defineControl({
  id: 'AD-PWD-001',
  version: '1.1.0',
  lifecycle: 'stable',
  title: 'Default domain password policy requires a minimum length of 15 characters',
  technology: 'ad',
  category: 'Authentication',
  subcategory: 'Password policy',
  description:
    'Checks, for every domain, that the default domain password policy requires passwords of at least 15 characters, and reports fine-grained password policies (PSOs) that apply a shorter minimum to some accounts.',
  rationale:
    'Short passwords can be guessed online or cracked offline quickly once a password hash or Kerberos ticket is captured. Length is the password property that adds the most resistance to guessing. The default domain policy still ships with a 7 character minimum, which is below the NIST-informed default used here.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Every Active Directory domain in the collected forest.' },
  requiredEvidence: ['ad.passwordPolicies'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each domain: FAIL when the default domain password policy minPasswordLength is below the minimumLength parameter. REVIEW when the default policy meets the minimum but a fine-grained password policy that is applied to at least one user or group sets a shorter minimum. PASS when every default policy meets the minimum and no applied PSO weakens it. PSOs that apply to nobody are ignored and noted. The overall result is the worst domain result.',
    parameters: { minimumLength: 15 },
  },
  expectedState: 'Every domain requires passwords of at least 15 characters, including accounts governed by fine-grained password policies. This conservative default assumes passwords can be used as a single factor.',
  remediation: {
    summary: 'Raise the minimum password length in the password policy GPO linked to the domain root (usually the Default Domain Policy) and in any fine-grained password policy that sets a shorter minimum.',
    steps: [
      'Communicate the change first: users are asked for the new length only at their next password change, but help desk staff and password reset tooling must accept longer passwords.',
      'Open Group Policy Management (gpmc.msc), edit the GPO that defines the domain password policy (normally the Default Domain Policy linked at the domain root).',
      'Go to Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy and set "Minimum password length" to 15 or more.',
      'For each fine-grained password policy listed in the finding, open Active Directory Administrative Center (dsac.exe) > System > Password Settings Container, open the policy and raise "Enforce minimum password length".',
      'Consider deploying Microsoft Entra Password Protection for on-premises AD DS to block common and easily guessed passwords as well.',
      'Repeat for every domain listed in the finding (each domain has its own password policy).',
    ],
    scriptExample: [
      '# Review, then run as a Domain Admin in each affected domain. AdminSecOps never runs this.',
      '# Preview the current values first:',
      'Get-ADDefaultDomainPasswordPolicy -Server contoso.com | Select-Object MinPasswordLength',
      'Get-ADFineGrainedPasswordPolicy -Filter * -Server contoso.com | Select-Object Name, MinPasswordLength, AppliesTo',
      '# The default domain policy is normally managed through the Default Domain Policy GPO (preferred).',
      '# Set-ADDefaultDomainPasswordPolicy writes the domain object directly and can be overwritten by the GPO:',
      'Set-ADDefaultDomainPasswordPolicy -Identity contoso.com -MinPasswordLength 15',
      "Set-ADFineGrainedPasswordPolicy -Identity 'ServiceAccountsPSO' -MinPasswordLength 15 -Server contoso.com",
    ].join('\n'),
    effort: 'low',
  },
  implementationConsiderations: [
    'NIST SP 800-63B-4 requires 15 characters for single-factor passwords and permits a minimum of 8 when passwords are used only within MFA. Directory password-policy evidence does not establish MFA enforcement on every authentication path, so this control defaults to 15. It does not certify NIST compliance or impose periodic changes to human passwords.',
    'Existing passwords stay valid; the new minimum applies the next time each user changes or resets a password. Accounts with "password never expires" keep their short password until it is changed, so combine this change with a password rotation plan for service and administrator accounts.',
    'The Group Policy setting accepts values up to 14 unless the "Relax minimum password length limits" setting is enabled on the domain controllers; test any value above 14 with the "Minimum password length audit" setting first because some older clients and applications cannot handle longer passwords.',
    'Only the password policy in a GPO linked to the domain root applies to domain accounts; the same setting in a GPO linked to an OU only affects local accounts on computers.',
    'Longer minimums work best with passphrases and without frequent forced expiry; review your expiry policy together with this change.',
  ],
  impact: 'Users must choose longer passwords at their next change. There is no impact on existing sessions or current passwords.',
  rollback: [
    'Set "Minimum password length" in the domain password policy GPO back to the previous value and run gpupdate on a domain controller (or wait for the next refresh).',
    'Restore the previous MinPasswordLength value on any changed fine-grained password policy with Set-ADFineGrainedPasswordPolicy.',
  ],
  validation: [
    'Run Get-ADDefaultDomainPasswordPolicy in each domain and confirm MinPasswordLength is 15 or more.',
    'Run Get-ADUserResultantPasswordPolicy for a member of each PSO and confirm the effective minimum length.',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-PWD-001 is PASS.',
  ],
  references: [AD_REF.nistPasswordRequirements, AD_REF.m365PasswordRecommendations, AD_REF.minimumPasswordLength, AD_REF.fineGrainedPasswordPolicies, REF.nist80063b, AD_REF.attackPasswordCracking],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5(1)' },
    { framework: 'MITRE-ATTACK', id: 'T1110.001' },
    { framework: 'MITRE-ATTACK', id: 'T1110.002' },
  ],
  tags: ['password-policy', 'authentication', 'active-directory'],
  evaluate: (ctx) => {
    const minimum = ctx.num('minimumLength');
    const domains = ctx.data('ad.passwordPolicies');
    if (domains.length === 0) return notAssessed(NO_POLICIES);
    const failing = domains.filter((d) => d.defaultPolicy.minPasswordLength < minimum);
    const weakPsos = domains.flatMap((d) =>
      d.fineGrainedPolicies.filter((p) => isApplied(p) && p.minPasswordLength < minimum).map((p) => ({ domain: d.domain, pso: p })),
    );
    const unapplied = domains.flatMap((d) => d.fineGrainedPolicies.filter((p) => !isApplied(p)).map((p) => `${d.domain}\\${p.name}`));
    const notes = unapplied.length > 0 ? [`Fine-grained password policies not applied to any user or group were ignored: ${unapplied.join(', ')}.`] : [];
    const facts = [
      fact('Domains evaluated', domains.length),
      fact('Required minimum length', minimum),
      fact('Domains with a shorter default minimum', failing.length),
      fact('Applied PSOs with a shorter minimum', weakPsos.length),
    ];
    const affectedObjects = [
      ...failing.map((d) => defaultPolicyObject(d.domain, `Minimum password length ${d.defaultPolicy.minPasswordLength} (required ${minimum})`)),
      ...weakPsos.map(({ domain, pso }) =>
        psoObject(domain, pso, `Minimum password length ${pso.minPasswordLength} for ${plural(pso.appliesToCount, 'linked principal')} (precedence ${pso.precedence})`),
      ),
    ];
    if (failing.length > 0) {
      return fail({
        reason: `The default password policy in ${plural(failing.length, 'domain')} allows passwords shorter than ${minimum} characters.`,
        summary: `${failing.map((d) => `${d.domain}: ${d.defaultPolicy.minPasswordLength}`).join('; ')} (required ${minimum}).`,
        facts,
        affectedObjects,
        notes,
      });
    }
    if (weakPsos.length > 0) {
      return review({
        reason: `Default domain policies meet the ${minimum} character minimum, but ${plural(weakPsos.length, 'applied fine-grained password policy', 'applied fine-grained password policies')} allow shorter passwords for some accounts.`,
        summary: 'Some accounts are governed by a fine-grained password policy with a shorter minimum length.',
        facts,
        affectedObjects,
        notes,
      });
    }
    return pass({
      reason: `Every domain requires passwords of at least ${minimum} characters and no applied fine-grained policy is weaker.`,
      summary: domains.map((d) => `${d.domain}: ${d.defaultPolicy.minPasswordLength}`).join('; '),
      facts,
      notes,
    });
  },
});

export const adPwdReversibleEncryption = defineControl({
  id: 'AD-PWD-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Password policies do not store passwords using reversible encryption',
  technology: 'ad',
  category: 'Authentication',
  subcategory: 'Password policy',
  description:
    'Checks that "Store passwords using reversible encryption" is disabled in the default domain password policy and in every fine-grained password policy (PSO) of every domain.',
  rationale:
    'When reversible encryption is enabled, domain controllers store a form of each new password that can be decrypted back to the clear-text password. Anyone who obtains a copy of the directory database or replication rights can then recover real passwords, which are often reused on other systems. Microsoft states this is essentially equivalent to storing passwords in plain text.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Every Active Directory domain in the collected forest.' },
  requiredEvidence: ['ad.passwordPolicies'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'FAIL when the default domain password policy of any domain, or any fine-grained password policy applied to at least one user or group, has reversibleEncryptionEnabled = true. REVIEW when the only PSOs with the setting are not applied to anyone (no effect today, but one link away from taking effect). PASS otherwise.',
    parameters: {},
  },
  expectedState: 'Reversible password encryption is disabled in the default domain password policy and every fine-grained password policy.',
  remediation: {
    summary: 'Disable "Store passwords using reversible encryption" in the domain password policy GPO and in every fine-grained password policy, then have affected users change their passwords.',
    steps: [
      'Identify why the setting was enabled. It is only required by legacy protocols such as CHAP (remote access / NPS) and IIS Digest Authentication; plan to replace those first.',
      'In Group Policy Management, edit the GPO that defines the domain password policy (normally the Default Domain Policy) and set Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy > "Store passwords using reversible encryption" to Disabled.',
      'In Active Directory Administrative Center > System > Password Settings Container, open each fine-grained policy listed in the finding and clear "Store password using reversible encryption".',
      'Disabling the policy only affects new passwords: reset or require a password change for the accounts that fell under the policy so the reversibly encrypted copy is replaced.',
      'Also run AD-ACC-002 to find individual accounts that have the per-account "Store password using reversible encryption" option set.',
    ],
    scriptExample: [
      '# Review, then run as a Domain Admin. AdminSecOps never runs this.',
      'Get-ADFineGrainedPasswordPolicy -Filter * | Where-Object ReversibleEncryptionEnabled | Select-Object Name, AppliesTo',
      "Set-ADFineGrainedPasswordPolicy -Identity 'LegacyAppPSO' -ReversibleEncryptionEnabled $false",
      '# Default domain policy (prefer editing the Default Domain Policy GPO instead):',
      'Set-ADDefaultDomainPasswordPolicy -Identity contoso.com -ReversibleEncryptionEnabled $false',
    ].join('\n'),
    effort: 'medium',
  },
  implementationConsiderations: [
    'Applications that rely on CHAP or IIS Digest Authentication stop authenticating users once their passwords are no longer stored reversibly; test and migrate them to modern authentication first.',
    'Existing reversibly encrypted passwords remain stored until each password is changed, so plan a password change for the affected users after disabling the setting.',
  ],
  impact: 'New passwords are stored only as one-way hashes. Legacy CHAP or Digest Authentication for the affected accounts stops working after their next password change.',
  rollback: [
    'Re-enable the setting in the GPO or PSO (not recommended). Passwords changed while it was disabled are not recoverable reversibly until they are changed again.',
  ],
  validation: [
    'Run Get-ADDefaultDomainPasswordPolicy and Get-ADFineGrainedPasswordPolicy -Filter * in each domain and confirm ReversibleEncryptionEnabled is False.',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-PWD-002 is PASS.',
  ],
  references: [AD_REF.reversibleEncryptionPolicy, AD_REF.fineGrainedPasswordPolicies, AD_REF.mdiUnsecureAccountAttributes],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5(1)', note: 'store only salted and hashed passwords' },
    { framework: 'MCSB', id: 'IM-8' },
  ],
  tags: ['password-policy', 'credential-exposure', 'active-directory'],
  evaluate: (ctx) => {
    const domains = ctx.data('ad.passwordPolicies');
    if (domains.length === 0) return notAssessed(NO_POLICIES);
    const defaults = domains.filter((d) => d.defaultPolicy.reversibleEncryptionEnabled);
    const psos = domains.flatMap((d) =>
      d.fineGrainedPolicies.filter((p) => p.reversibleEncryptionEnabled).map((p) => ({ domain: d.domain, pso: p })),
    );
    const appliedPsos = psos.filter(({ pso }) => isApplied(pso));
    const unappliedPsos = psos.filter(({ pso }) => !isApplied(pso));
    const facts = [
      fact('Domains evaluated', domains.length),
      fact('Default policies with reversible encryption', defaults.length),
      fact('Applied PSOs with reversible encryption', appliedPsos.length),
      fact('Unapplied PSOs with reversible encryption', unappliedPsos.length),
    ];
    const affectedObjects = [
      ...defaults.map((d) => defaultPolicyObject(d.domain, 'Store passwords using reversible encryption is enabled for every account in the domain')),
      ...appliedPsos.map(({ domain, pso }) => psoObject(domain, pso, `Reversible encryption enabled; applies to ${plural(pso.appliesToCount, 'linked principal')}`)),
      ...unappliedPsos.map(({ domain, pso }) => psoObject(domain, pso, 'Reversible encryption enabled; not currently applied to any user or group')),
    ];
    if (defaults.length > 0 || appliedPsos.length > 0) {
      return fail({
        reason: `Reversible password encryption is enabled in ${plural(defaults.length, 'default domain policy', 'default domain policies')} and ${plural(appliedPsos.length, 'applied fine-grained policy', 'applied fine-grained policies')}.`,
        summary: 'Passwords of affected accounts are stored in a form that can be decrypted to clear text.',
        facts,
        affectedObjects,
      });
    }
    if (unappliedPsos.length > 0) {
      return review({
        reason: `${plural(unappliedPsos.length, 'fine-grained password policy', 'fine-grained password policies')} enable reversible encryption but are not applied to any user or group.`,
        summary: 'Reversible encryption is configured in unused fine-grained policies; delete them or disable the setting before they are linked.',
        facts,
        affectedObjects,
      });
    }
    return pass({
      reason: 'Reversible password encryption is disabled in every default and fine-grained password policy.',
      summary: `${plural(domains.length, 'domain')} checked; no policy stores passwords reversibly.`,
      facts,
    });
  },
});

export const adPwdLockoutThreshold = defineControl({
  id: 'AD-PWD-003',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Account lockout threshold is configured in the default domain policy',
  technology: 'ad',
  category: 'Authentication',
  subcategory: 'Account lockout',
  description:
    'Checks, for every domain, that the default domain policy locks accounts out after a limited number of failed sign-in attempts (Microsoft Security Compliance Toolkit baseline: 10), and reports fine-grained password policies that disable or loosen lockout for some accounts.',
  rationale:
    'Without an account lockout threshold an attacker can guess passwords against domain accounts indefinitely. A threshold limits online guessing and password spraying against on-premises authentication (Kerberos, NTLM, LDAP binds, VPN/RADIUS). The Microsoft Security Compliance Toolkit baseline uses 10 attempts, and NIST SP 800-63B requires limiting consecutive failed attempts to no more than 100.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Every Active Directory domain in the collected forest.' },
  requiredEvidence: ['ad.passwordPolicies'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each domain default policy: FAIL when lockoutThreshold is 0 (accounts never lock out) or greater than hardMaximumThreshold (100, the NIST SP 800-63B ceiling); REVIEW when it is greater than recommendedMaximumThreshold (10, the Microsoft baseline) but not above 100; PASS when it is between 1 and 10. Applied fine-grained password policies with a threshold of 0 or above the recommended maximum produce REVIEW. The overall result is the worst result.',
    parameters: { recommendedMaximumThreshold: 10, hardMaximumThreshold: 100 },
  },
  expectedState: 'Every domain locks accounts after at most 10 failed attempts (with a lockout duration such as 15 minutes), and no fine-grained policy disables lockout without a documented reason.',
  remediation: {
    summary: 'Set "Account lockout threshold" to 10 (or lower) in the domain password policy GPO, with a lockout duration and reset counter of about 15 minutes.',
    steps: [
      'Before enabling lockout, review failed sign-in events (4625, 4771, 4776) to find applications or devices with stale saved credentials that would repeatedly lock accounts.',
      'In Group Policy Management, edit the GPO that defines the domain password policy (normally the Default Domain Policy).',
      'Go to Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Account Lockout Policy.',
      'Set "Account lockout threshold" to 10 invalid logon attempts, "Account lockout duration" to 15 minutes and "Reset account lockout counter after" to 15 minutes.',
      'For each fine-grained password policy in the finding, review whether disabling or loosening lockout is still justified and align it with the domain policy in Active Directory Administrative Center.',
      'Make sure the help desk can unlock accounts (Unlock-ADAccount or ADUC) and monitor event 4740 (account locked out).',
    ],
    scriptExample: [
      '# Review, then run as a Domain Admin. AdminSecOps never runs this.',
      'Get-ADDefaultDomainPasswordPolicy | Select-Object LockoutThreshold, LockoutDuration, LockoutObservationWindow',
      '# Prefer the Default Domain Policy GPO; this writes the domain object directly:',
      'Set-ADDefaultDomainPasswordPolicy -Identity contoso.com -LockoutThreshold 10 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00',
      '# Find locked-out accounts after enforcement:',
      'Search-ADAccount -LockedOut | Select-Object SamAccountName, LastLogonDate',
    ].join('\n'),
    effort: 'low',
  },
  implementationConsiderations: [
    'Microsoft also documents a threshold of 0 as an option when every account has a strong password and failed sign-ins are actively alerted on, because lockout lets an attacker lock out many users deliberately. AdminSecOps reports 0 as a failure because it cannot verify those compensating controls; record an exception if you have them.',
    'Very low thresholds (1 to 3) increase accidental lockouts and help desk calls; values between 5 and 10 are a practical balance.',
    'Devices with saved old passwords (phones, mapped drives, scheduled tasks, services) can cause repeated lockouts after a password change. Identify them from event 4740 on the PDC emulator.',
    'Lockout policy for domain accounts must be set in a GPO linked to the domain root or in a fine-grained password policy; OU-linked GPOs only affect local accounts.',
  ],
  impact: 'Accounts are temporarily locked after repeated failed attempts. Users with stale saved credentials may be locked out until those are updated.',
  rollback: [
    'Set "Account lockout threshold" back to the previous value in the domain password policy GPO and refresh Group Policy on the domain controllers.',
    'Unlock affected accounts with Unlock-ADAccount if needed.',
  ],
  validation: [
    'Run Get-ADDefaultDomainPasswordPolicy in each domain and confirm LockoutThreshold is between 1 and 10.',
    'Test with a non-privileged test account: exceed the threshold and confirm event 4740 is logged and the account unlocks after the duration.',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-PWD-003 is PASS.',
  ],
  references: [AD_REF.lockoutThresholdRecommendation, REF.nist80063b, AD_REF.fineGrainedPasswordPolicies, AD_REF.attackPasswordGuessing, REF.attackPasswordSpraying],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-7' },
    { framework: 'MITRE-ATTACK', id: 'T1110.001' },
    { framework: 'MITRE-ATTACK', id: 'T1110.003' },
  ],
  tags: ['account-lockout', 'password-policy', 'active-directory'],
  evaluate: (ctx) => {
    const recommended = ctx.num('recommendedMaximumThreshold');
    const hardMax = ctx.num('hardMaximumThreshold');
    const domains = ctx.data('ad.passwordPolicies');
    if (domains.length === 0) return notAssessed(NO_POLICIES);
    const failing = domains.filter((d) => d.defaultPolicy.lockoutThreshold === 0 || d.defaultPolicy.lockoutThreshold > hardMax);
    const loose = domains.filter((d) => d.defaultPolicy.lockoutThreshold > recommended && d.defaultPolicy.lockoutThreshold <= hardMax);
    const weakPsos = domains.flatMap((d) =>
      d.fineGrainedPolicies
        .filter((p) => isApplied(p) && (p.lockoutThreshold === 0 || p.lockoutThreshold > recommended))
        .map((p) => ({ domain: d.domain, pso: p })),
    );
    const describe = (threshold: number): string => (threshold === 0 ? 'lockout disabled (threshold 0)' : `threshold ${threshold}`);
    const facts = [
      fact('Domains evaluated', domains.length),
      fact('Recommended maximum threshold', recommended),
      fact('Domains with lockout disabled or above the hard maximum', failing.length),
      fact('Domains above the recommended threshold', loose.length),
      fact('Applied PSOs that disable or loosen lockout', weakPsos.length),
    ];
    const affectedObjects = [
      ...failing.map((d) => defaultPolicyObject(d.domain, describe(d.defaultPolicy.lockoutThreshold))),
      ...loose.map((d) => defaultPolicyObject(d.domain, `${describe(d.defaultPolicy.lockoutThreshold)} (recommended at most ${recommended})`)),
      ...weakPsos.map(({ domain, pso }) =>
        psoObject(domain, pso, `${describe(pso.lockoutThreshold)}; applies to ${plural(pso.appliesToCount, 'linked principal')}`),
      ),
    ];
    if (failing.length > 0) {
      return fail({
        reason: `The default policy in ${plural(failing.length, 'domain')} never locks accounts out or allows more than ${hardMax} failed attempts.`,
        summary: failing.map((d) => `${d.domain}: ${describe(d.defaultPolicy.lockoutThreshold)}`).join('; '),
        facts,
        affectedObjects,
      });
    }
    if (loose.length > 0 || weakPsos.length > 0) {
      return review({
        reason:
          loose.length > 0
            ? `The default policy in ${plural(loose.length, 'domain')} allows more than the recommended ${recommended} failed attempts; this still limits guessing but is weaker than the Microsoft baseline.`
            : `Default policies are within the recommended threshold, but ${plural(weakPsos.length, 'applied fine-grained policy', 'applied fine-grained policies')} disable or loosen lockout for some accounts.`,
        summary: 'Account lockout is configured but looser than recommended for some domains or accounts.',
        facts,
        affectedObjects,
      });
    }
    return pass({
      reason: `Every domain locks accounts after at most ${recommended} failed attempts and no applied fine-grained policy loosens this.`,
      summary: domains.map((d) => `${d.domain}: ${describe(d.defaultPolicy.lockoutThreshold)}`).join('; '),
      facts,
    });
  },
});
