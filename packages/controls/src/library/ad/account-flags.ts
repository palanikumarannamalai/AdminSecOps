import { defineControl } from '../../define.js';
import { fact, fail, pass, plural } from '../../helpers.js';
import { AD_REF } from './references.js';
import { disabledNote, optionalPrivilegedSids, PRIVILEGED_UNAVAILABLE_NOTE, userObject } from './shared.js';

export const adPasswordNotRequired = defineControl({
  id: 'AD-ACC-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'No enabled accounts are exempt from the password requirement (PASSWD_NOTREQD)',
  technology: 'ad',
  category: 'Account security',
  subcategory: 'Account flags',
  description:
    'Finds enabled user accounts with the PASSWD_NOTREQD flag in userAccountControl, which exempts the account from the domain password policy and allows an empty password to be set.',
  rationale:
    'PASSWD_NOTREQD lets an account have a blank or policy-violating password regardless of the domain password policy. The flag is often left behind by provisioning scripts or old migrations. An enabled account that has, or can be given, an empty password is an easy entry point, and Microsoft Defender for Identity flags it as an unsecure account attribute.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Every Active Directory domain in the collected forest.' },
  requiredEvidence: ['ad.users'],
  optionalEvidence: ['ad.privilegedGroups'],
  evaluation: {
    logic:
      'FAIL when any enabled user account has passwordNotRequired = true (privileged accounts are highlighted when privileged group evidence is available). Disabled accounts with the flag are noted only. PASS otherwise. Computer and trust accounts are not part of this evidence.',
    parameters: {},
  },
  expectedState: 'No enabled user account has the PASSWD_NOTREQD flag.',
  remediation: {
    summary: 'Clear the PASSWD_NOTREQD flag on each listed account and set a password that meets the domain policy.',
    steps: [
      'For each account, confirm it has an owner and is still needed; disable accounts that are not.',
      'Set a new password that satisfies the domain password policy (Active Directory Users and Computers > Reset Password), because the current password might be empty or weak.',
      'Clear the flag with Set-ADAccountControl -PasswordNotRequired $false (the flag is not visible in the ADUC account options).',
      'Update provisioning scripts or tools that create accounts with this flag.',
    ],
    scriptExample: [
      '# Review, then run as an account administrator. AdminSecOps never runs this.',
      'Get-ADUser -Filter "PasswordNotRequired -eq $true -and Enabled -eq $true" | Select-Object SamAccountName',
      "Set-ADAccountPassword -Identity 'jdoe' -Reset -NewPassword (Read-Host -AsSecureString 'New password')",
      "Set-ADAccountControl -Identity 'jdoe' -PasswordNotRequired $false",
    ].join('\n'),
    effort: 'low',
  },
  implementationConsiderations: [
    'Clearing the flag does not change the current password; if the account had an empty password it keeps working until a new password is set, so reset the password as part of the fix.',
    'Some third-party provisioning tools set the flag temporarily when creating accounts; check they clear it afterwards.',
  ],
  impact: 'Affected accounts must use a password that meets the domain policy. Applications using those accounts need the new password.',
  rollback: ["Set the flag again with Set-ADAccountControl -PasswordNotRequired $true (not recommended)."],
  validation: [
    'Run Get-ADUser -Filter "PasswordNotRequired -eq $true -and Enabled -eq $true" in each domain and confirm no results.',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-ACC-001 is PASS.',
  ],
  references: [AD_REF.mdiUnsecureAccountAttributes, AD_REF.userAccountControlFlags, AD_REF.attackDomainAccounts],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5(1)' },
    { framework: 'NIST-800-53r5', id: 'CM-6' },
    { framework: 'MITRE-ATTACK', id: 'T1078.002' },
  ],
  tags: ['account-settings', 'password-policy', 'active-directory'],
  evaluate: (ctx) => {
    const { users } = ctx.data('ad.users');
    const privileged = optionalPrivilegedSids(ctx);
    const flagged = users.filter((u) => u.passwordNotRequired);
    const enabled = flagged.filter((u) => u.enabled);
    const disabled = flagged.filter((u) => !u.enabled);
    const facts = [
      fact('Accounts evaluated', users.length),
      fact('Enabled accounts with PASSWD_NOTREQD', enabled.length),
      fact('Of which privileged', privileged === null ? null : enabled.filter((u) => privileged.has(u.sid.toUpperCase())).length),
    ];
    const notes = [...disabledNote(disabled, 'PASSWD_NOTREQD'), ...(privileged === null ? [PRIVILEGED_UNAVAILABLE_NOTE] : [])];
    if (enabled.length > 0) {
      return fail({
        reason: `${plural(enabled.length, 'enabled account')} are not required to have a password.`,
        summary: `Accounts with PASSWD_NOTREQD found in ${[...new Set(enabled.map((u) => u.domain))].join(', ')}.`,
        facts,
        affectedObjects: enabled.map((u) => userObject(u, `PASSWD_NOTREQD set${privileged?.has(u.sid.toUpperCase()) ? '; PRIVILEGED account' : ''}`)),
        notes,
      });
    }
    return pass({
      reason: 'No enabled account has the PASSWD_NOTREQD flag.',
      summary: `${plural(users.length, 'collected account')} checked.`,
      facts,
      notes,
    });
  },
});

export const adAccountReversibleEncryption = defineControl({
  id: 'AD-ACC-002',
  version: '1.1.0',
  lifecycle: 'stable',
  title: 'No accounts are configured to allow reversible password encryption',
  technology: 'ad',
  category: 'Account security',
  subcategory: 'Account flags',
  description:
    'Finds user accounts (enabled or disabled) with the per-account option "Store password using reversible encryption" (ENCRYPTED_TEXT_PWD_ALLOWED) set.',
  rationale:
    'This flag permits future password changes to store a recoverable password copy; directory flags alone cannot prove that such a copy currently exists. Anyone who obtains the directory database, a domain controller backup or replication rights can read the real password, which is frequently reused elsewhere. Disabled accounts are included because disabling an account does not remove any previously stored copy.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Every Active Directory domain in the collected forest.' },
  requiredEvidence: ['ad.users'],
  optionalEvidence: ['ad.privilegedGroups'],
  evaluation: {
    logic:
      'FAIL when any user account has allowReversiblePasswordEncryption = true, whether enabled or disabled (disabled accounts retain the risky configuration and may retain previous password copies). Privileged accounts are highlighted when privileged group evidence is available. PASS otherwise. The domain-wide policy setting is evaluated separately by AD-PWD-002.',
    parameters: {},
  },
  expectedState: 'No account has "Store password using reversible encryption" enabled.',
  remediation: {
    summary: 'Clear "Store password using reversible encryption" on each listed account and then change the account password so the reversible copy is replaced.',
    steps: [
      'Confirm with the account owner whether a legacy protocol (CHAP, IIS Digest Authentication) still needs the setting; plan a replacement if so.',
      'In Active Directory Users and Computers, open the account > Account tab > Account options and clear "Store password using reversible encryption".',
      'Reset or change the account password. The reversible copy is only removed when the password changes.',
      'For disabled accounts that are no longer needed, delete them after your retention period.',
    ],
    scriptExample: [
      '# Review, then run as an account administrator. AdminSecOps never runs this.',
      'Get-ADUser -Filter "AllowReversiblePasswordEncryption -eq $true" | Select-Object SamAccountName, Enabled',
      "Set-ADAccountControl -Identity 'legacy-radius' -AllowReversiblePasswordEncryption $false",
      "Set-ADAccountPassword -Identity 'legacy-radius' -Reset -NewPassword (Read-Host -AsSecureString 'New password')",
    ].join('\n'),
    effort: 'low',
  },
  implementationConsiderations: [
    'Accounts that authenticate through CHAP or Digest Authentication stop working after the password change; migrate those integrations first.',
    'Clearing the option without a password change leaves the reversible copy in the directory.',
  ],
  impact: 'The account password is stored only as a one-way hash after the next change; legacy CHAP/Digest sign-in for that account stops working.',
  rollback: ["Re-enable the option with Set-ADAccountControl -AllowReversiblePasswordEncryption $true and change the password again (not recommended)."],
  validation: [
    'Run Get-ADUser -Filter "AllowReversiblePasswordEncryption -eq $true" in each domain and confirm no results.',
    'Re-run the AdminSecOps Active Directory collector and confirm AD-ACC-002 is PASS.',
  ],
  references: [AD_REF.mdiUnsecureAccountAttributes, AD_REF.reversibleEncryptionPolicy, AD_REF.userAccountControlFlags],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5(1)', note: 'store only salted and hashed passwords' },
    { framework: 'MCSB', id: 'IM-8' },
  ],
  tags: ['account-settings', 'credential-exposure', 'active-directory'],
  evaluate: (ctx) => {
    const { users } = ctx.data('ad.users');
    const privileged = optionalPrivilegedSids(ctx);
    const flagged = users.filter((u) => u.allowReversiblePasswordEncryption);
    const enabledCount = flagged.filter((u) => u.enabled).length;
    const facts = [
      fact('Accounts evaluated', users.length),
      fact('Accounts configured to allow reversible passwords', flagged.length),
      fact('Of which enabled', enabledCount),
      fact('Of which privileged', privileged === null ? null : flagged.filter((u) => privileged.has(u.sid.toUpperCase())).length),
    ];
    const notes = privileged === null ? [PRIVILEGED_UNAVAILABLE_NOTE] : [];
    if (flagged.length > 0) {
      return fail({
        reason: `${plural(flagged.length, 'account')} (${enabledCount} enabled) are configured to allow reversible password encryption.`,
        summary: `Reversible-encryption flags found in ${[...new Set(flagged.map((u) => u.domain))].join(', ')}.`,
        facts,
        affectedObjects: flagged.map((u) =>
          userObject(u, `${u.enabled ? 'Enabled' : 'Disabled'} account${privileged?.has(u.sid.toUpperCase()) ? '; PRIVILEGED' : ''}; reversible encryption permitted by account flag`),
        ),
        notes,
      });
    }
    return pass({
      reason: 'No collected account has its reversible-encryption flag enabled; previously stored material was not inspected.',
      summary: `${plural(users.length, 'collected account')} checked.`,
      facts,
      notes,
    });
  },
});
