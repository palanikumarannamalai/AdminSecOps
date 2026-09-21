import { hostNamesMatch } from '@adminsecops/inventory';
import type { AffectedObject, DatasetData } from '@adminsecops/schemas';
import { defineControl, type ControlContext, type EvaluationOutcome } from '../../define.js';
import { affected, fact, fail, notAssessed, pass, plural, review } from '../../helpers.js';
import { AD_REF } from './references.js';

type DcSetting = DatasetData<'ad.domainControllerSettings'>[number];
type DomainController = DatasetData<'ad.domainControllers'>[number];

type Verdict = { state: 'pass' | 'fail' | 'review'; detail: string };

interface SettingCheck {
  /** Label of the setting for summaries, e.g. "LDAP signing". */
  label: string;
  classify: (setting: DcSetting, dc: DomainController | undefined) => Verdict;
  passReason: string;
  failReason: (count: number) => string;
  reviewReason: string;
  extraNotes?: (settings: readonly DcSetting[]) => string[];
}

function isServer2025(dc: DomainController | undefined): boolean {
  return /2025/.test(dc?.operatingSystem ?? '');
}

function osKnown(dc: DomainController | undefined): boolean {
  return (dc?.operatingSystem ?? null) !== null;
}

/**
 * Shared evaluation for registry-based domain controller settings. Hosts whose registry
 * could not be read (readStatus Failed) and domain controllers missing from the settings
 * evidence never count as passing.
 */
function evaluateDcSetting(ctx: ControlContext, check: SettingCheck): EvaluationOutcome {
  const settings = ctx.data('ad.domainControllerSettings');
  const dcsFact = ctx.fact('ad.domainControllers');
  const dcs = dcsFact.available ? dcsFact.data : [];
  const findDc = (host: string) => dcs.find((dc) => hostNamesMatch(dc.hostName, host));
  const display = (host: string) => {
    const dc = findDc(host);
    return dc === undefined ? host : `${dc.domain}\\${dc.hostName}`;
  };
  const object = (host: string, detail: string): AffectedObject => affected('adDomainController', host, display(host), detail);

  const readable = settings.filter((s) => s.readStatus === 'Success');
  const unreadable = settings.filter((s) => s.readStatus === 'Failed');
  const notCollected = dcs.filter((dc) => !settings.some((s) => hostNamesMatch(dc.hostName, s.hostName)));
  const verdicts = readable.map((s) => ({ setting: s, verdict: check.classify(s, findDc(s.hostName)) }));
  const failing = verdicts.filter((v) => v.verdict.state === 'fail');
  const uncertain = verdicts.filter((v) => v.verdict.state === 'review');
  const facts = [
    fact('Domain controllers with settings read', readable.length),
    fact('Domain controllers whose registry could not be read', unreadable.length),
    fact('Known domain controllers missing from the settings evidence', dcsFact.available ? notCollected.length : null),
    fact(`Domain controllers failing (${check.label})`, failing.length),
  ];
  const notes = [
    ...(check.extraNotes?.(readable) ?? []),
    ...(dcsFact.available ? [] : ['The domain controller list was not available, so completeness of the settings evidence could not be checked.']),
  ];
  const gaps: AffectedObject[] = [
    ...unreadable.map((s) => object(s.hostName, 'Registry settings could not be read from this domain controller')),
    ...notCollected.map((dc) => affected('adDomainController', dc.hostName, `${dc.domain}\\${dc.hostName}`, 'Domain controller was not included in the settings collection')),
  ];
  if (readable.length === 0) {
    return notAssessed({
      reason: `The ${check.label} setting could not be read from any domain controller, so it cannot be assessed.`,
      summary: `${plural(unreadable.length, 'domain controller')} failed the registry read.`,
      facts,
      affectedObjects: gaps,
      notes,
    });
  }
  if (failing.length > 0) {
    return fail({
      reason: check.failReason(failing.length),
      summary: failing.map((v) => `${display(v.setting.hostName)}: ${v.verdict.detail}`).join('; '),
      facts,
      affectedObjects: [
        ...failing.map((v) => object(v.setting.hostName, v.verdict.detail)),
        ...uncertain.map((v) => object(v.setting.hostName, v.verdict.detail)),
        ...gaps,
      ],
      notes,
    });
  }
  if (uncertain.length > 0 || gaps.length > 0) {
    return review({
      reason: check.reviewReason,
      summary: `${plural(uncertain.length, 'domain controller')} with an undetermined setting and ${plural(gaps.length, 'domain controller')} not read.`,
      facts,
      affectedObjects: [...uncertain.map((v) => object(v.setting.hostName, v.verdict.detail)), ...gaps],
      notes,
    });
  }
  return pass({
    reason: check.passReason,
    summary: `${plural(readable.length, 'domain controller')} checked.`,
    facts,
    notes,
  });
}

export const adLdapSigning = defineControl({
  id: 'AD-DC-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'LDAP signing is required on all domain controllers',
  technology: 'ad',
  category: 'Domain controllers',
  subcategory: 'LDAP security',
  description:
    'Checks the LDAPServerIntegrity registry value (policy "Domain controller: LDAP server signing requirements") on every domain controller and expects 2 (require signing).',
  rationale:
    'When domain controllers accept unsigned LDAP binds, an attacker positioned on the network can relay or tamper with LDAP traffic, for example relaying captured NTLM authentication to LDAP to modify directory objects and escalate privileges. Requiring signing makes domain controllers reject SASL binds without signing and simple binds over unencrypted connections.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Every domain controller, when the optional domain controller settings collection was run.' },
  requiredEvidence: ['ad.domainControllerSettings'],
  optionalEvidence: ['ad.domainControllers'],
  evaluation: {
    logic:
      'For each domain controller read successfully: PASS value 2; FAIL value 0 or 1 (signing not required); when the value is not set, FAIL if the domain controller is known to run a version before Windows Server 2025 (Microsoft documents signing as optional by default there), otherwise REVIEW (Windows Server 2025 requires signing by default only for new deployments; upgraded domain controllers keep their previous setting). Domain controllers whose registry read failed, or that appear in ad.domainControllers but not in the settings evidence, never count as passing and make the result REVIEW. NOT_ASSESSED when no domain controller could be read. The overall result is the worst per-DC result.',
    parameters: {},
  },
  expectedState: 'LDAPServerIntegrity = 2 (Require signing) on every domain controller.',
  remediation: {
    summary: 'Find clients that still use unsigned LDAP, fix them, then set "Domain controller: LDAP server signing requirements" to "Require signing" in the Default Domain Controllers Policy.',
    steps: [
      'Enable LDAP interface diagnostic logging (or use the 2886/2887 events already logged) on domain controllers to find clients that perform unsigned or clear-text simple binds.',
      'Reconfigure those clients to use signed LDAP (SASL with signing) or LDAPS (port 636).',
      'In Group Policy Management, edit the Default Domain Controllers Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > "Domain controller: LDAP server signing requirements" = Require signing.',
      'Also set "Network security: LDAP client signing requirements" to at least "Negotiate signing" for member computers.',
      'Run gpupdate /force on domain controllers (or wait for refresh) and monitor for event 2889 and application errors.',
    ],
    scriptExample: [
      '# Read-only checks on a domain controller; review before any change. AdminSecOps never runs this.',
      "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LDAPServerIntegrity",
      "Get-WinEvent -FilterHashtable @{LogName='Directory Service'; Id=2887,2889} -MaxEvents 50",
      '# Configure the setting through the Default Domain Controllers Policy GPO rather than editing the registry directly.',
    ].join('\n'),
    effort: 'medium',
  },
  implementationConsiderations: [
    'Applications, appliances and scripts that use simple binds over port 389 or unsigned SASL binds stop working. Use events 2887 and 2889 to find them before enforcing.',
    'LDAPS (port 636) connections satisfy the signing requirement because the channel is already encrypted.',
    'Configure the setting in a GPO linked to the Domain Controllers OU so every current and future domain controller receives it.',
  ],
  impact: 'Domain controllers reject unsigned LDAP binds; misconfigured clients fail to connect until fixed.',
  rollback: ['Set "Domain controller: LDAP server signing requirements" back to "None" in the Default Domain Controllers Policy and refresh Group Policy on domain controllers.'],
  validation: [
    'On each domain controller confirm LDAPServerIntegrity = 2 and that event 2886 is no longer logged at startup.',
    'Re-run the AdminSecOps collector with domain controller settings enabled and confirm AD-DC-001 is PASS.',
  ],
  references: [AD_REF.ldapSigning, AD_REF.ldapChannelBindingRequirements, AD_REF.attackAdversaryInTheMiddle],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SC-8' },
    { framework: 'NIST-800-53r5', id: 'SC-23' },
    { framework: 'MITRE-ATTACK', id: 'T1557' },
  ],
  tags: ['domain-controllers', 'ldap', 'relay', 'active-directory'],
  evaluate: (ctx) =>
    evaluateDcSetting(ctx, {
      label: 'LDAP signing',
      classify: (s, dc) => {
        const value = s.ldapServerIntegrity;
        if (value === 2) return { state: 'pass', detail: 'LDAPServerIntegrity = 2 (require signing)' };
        if (value === 0 || value === 1) return { state: 'fail', detail: `LDAPServerIntegrity = ${value} (signing not required)` };
        if (value === null) {
          if (osKnown(dc) && !isServer2025(dc)) {
            return { state: 'fail', detail: `LDAPServerIntegrity not set; ${dc?.operatingSystem ?? ''} does not require signing by default` };
          }
          return { state: 'review', detail: 'LDAPServerIntegrity not set; the effective default depends on the Windows version and whether the DC was upgraded' };
        }
        return { state: 'review', detail: `Unexpected LDAPServerIntegrity value ${value}` };
      },
      passReason: 'Every domain controller that was read requires LDAP signing.',
      failReason: (n) => `${plural(n, 'domain controller')} do not require LDAP signing.`,
      reviewReason: 'LDAP signing could not be confirmed on every domain controller (value not set, unexpected, or the registry could not be read).',
    }),
});

export const adLdapChannelBinding = defineControl({
  id: 'AD-DC-002',
  version: '1.1.0',
  lifecycle: 'stable',
  title: 'LDAP channel binding is enforced on all domain controllers',
  technology: 'ad',
  category: 'Domain controllers',
  subcategory: 'LDAP security',
  description:
    'Checks the LdapEnforceChannelBinding registry value (policy "Domain controller: LDAP server channel binding token requirements") on every domain controller and expects 2 (Always).',
  rationale:
    'LDAP signing does not protect LDAPS (LDAP over TLS) connections against relay. Channel binding ties the authentication to the specific TLS session, so credentials relayed by an attacker-in-the-middle into a different TLS session are rejected. Together with LDAP signing it closes the main NTLM relay paths to domain controllers.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Every domain controller, when the optional domain controller settings collection was run.' },
  requiredEvidence: ['ad.domainControllerSettings'],
  optionalEvidence: ['ad.domainControllers'],
  evaluation: {
    logic:
      'For each domain controller read successfully: PASS value 2 (Always); REVIEW value 1 (When supported: clients that send a channel binding token are validated, others are still accepted); FAIL value 0 (Never). When the value is not set: REVIEW if the domain controller is known to run Windows Server 2025 (documented default "When supported"), REVIEW if the OS version is unknown, otherwise FAIL (documented default "Never" on earlier versions). Unreadable or missing domain controllers never count as passing and produce REVIEW. NOT_ASSESSED when no domain controller could be read.',
    parameters: {},
  },
  expectedState: 'LdapEnforceChannelBinding = 2 (Always) on every domain controller.',
  remediation: {
    summary: 'Move from "When supported" to "Always" for LDAP channel binding after confirming that LDAPS clients support channel binding tokens.',
    steps: [
      'Make sure all domain controllers have current cumulative updates (channel binding support was added by the March 2020 updates).',
      'Set "Domain controller: LDAP server channel binding token requirements" to "When supported" in the Default Domain Controllers Policy (Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options).',
      'Monitor Directory Service events 3039 (client does not support CBT) and 3040/3041 on domain controllers to find incompatible LDAPS clients; update or reconfigure them.',
      'When no incompatible clients remain, change the setting to "Always" and continue monitoring.',
    ],
    scriptExample: [
      '# Read-only checks on a domain controller; review before any change. AdminSecOps never runs this.',
      "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name LdapEnforceChannelBinding -ErrorAction SilentlyContinue",
      "Get-WinEvent -FilterHashtable @{LogName='Directory Service'; Id=3039,3040,3041} -MaxEvents 50",
    ].join('\n'),
    effort: 'medium',
  },
  implementationConsiderations: [
    'Older or third-party LDAPS clients (appliances, Java or Linux applications) that do not send channel binding tokens fail when the setting is "Always"; the "When supported" stage with event monitoring identifies them.',
    'Channel binding only affects LDAP over TLS; combine it with LDAP signing (AD-DC-001).',
  ],
  impact: 'LDAPS clients that do not support channel binding are rejected once "Always" is enforced.',
  rollback: ['Set the policy back to "When supported" (or "Never") in the Default Domain Controllers Policy and refresh Group Policy.'],
  validation: [
    'On each domain controller confirm LdapEnforceChannelBinding = 2.',
    'Re-run the AdminSecOps collector with domain controller settings enabled and confirm AD-DC-002 is PASS.',
  ],
  references: [AD_REF.ldapChannelBindingRequirements, AD_REF.ldapSigning, AD_REF.attackAdversaryInTheMiddle],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SC-8' },
    { framework: 'NIST-800-53r5', id: 'SC-23' },
    { framework: 'MITRE-ATTACK', id: 'T1557' },
  ],
  tags: ['domain-controllers', 'ldap', 'relay', 'active-directory'],
  evaluate: (ctx) =>
    evaluateDcSetting(ctx, {
      label: 'LDAP channel binding',
      classify: (s, dc) => {
        const value = s.ldapEnforceChannelBinding;
        if (value === 2) return { state: 'pass', detail: 'LdapEnforceChannelBinding = 2 (Always)' };
        if (value === 1) return { state: 'review', detail: 'LdapEnforceChannelBinding = 1 (When supported)' };
        if (value === 0) return { state: 'fail', detail: 'LdapEnforceChannelBinding = 0 (Never)' };
        if (value === null) {
          if (!osKnown(dc)) return { state: 'review', detail: 'LdapEnforceChannelBinding not set and Windows Server version unknown; effective default cannot be determined' };
          return isServer2025(dc)
            ? { state: 'review', detail: 'LdapEnforceChannelBinding not set; Windows Server 2025 default is "When supported"' }
            : { state: 'fail', detail: 'LdapEnforceChannelBinding not set; default before Windows Server 2025 is "Never"' };
        }
        return { state: 'review', detail: `Unexpected LdapEnforceChannelBinding value ${value}` };
      },
      passReason: 'Every domain controller that was read always enforces LDAP channel binding.',
      failReason: (n) => `${plural(n, 'domain controller')} never enforce LDAP channel binding.`,
      reviewReason: 'LDAP channel binding is only enforced "when supported", or could not be confirmed, on some domain controllers.',
    }),
});

export const adDcSmbSigning = defineControl({
  id: 'AD-DC-003',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'SMB signing is required on domain controllers',
  technology: 'ad',
  category: 'Domain controllers',
  subcategory: 'SMB security',
  description:
    'Checks the LanmanServer RequireSecuritySignature registry value (policy "Microsoft network server: Digitally sign communications (always)") on every domain controller and expects 1.',
  rationale:
    'Signed SMB sessions cannot be tampered with or relayed. Domain controllers serve SYSVOL and NETLOGON (Group Policy and logon scripts) over SMB; without required signing an attacker-in-the-middle can modify policy traffic or relay authentication to the domain controller. Microsoft notes that domain controllers require SMB signing by default, so a missing requirement indicates the default was weakened.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Every domain controller, when the optional domain controller settings collection was run.' },
  requiredEvidence: ['ad.domainControllerSettings'],
  optionalEvidence: ['ad.domainControllers'],
  evaluation: {
    logic:
      'For each domain controller read successfully: PASS when smbRequireSecuritySignature = 1; FAIL when 0; REVIEW when the value is not set (the default for domain controllers comes from the Default Domain Controllers Policy, which normally writes this value, so its absence cannot be interpreted safely). Unreadable or missing domain controllers never count as passing and produce REVIEW. NOT_ASSESSED when no domain controller could be read. SMBv1 being enabled is reported as a note.',
    parameters: {},
  },
  expectedState: 'RequireSecuritySignature = 1 for the SMB server on every domain controller.',
  remediation: {
    summary: 'Set "Microsoft network server: Digitally sign communications (always)" to Enabled in the Default Domain Controllers Policy.',
    steps: [
      'In Group Policy Management, edit the Default Domain Controllers Policy (or the GPO linked to the Domain Controllers OU that manages security options).',
      'Go to Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options and set "Microsoft network server: Digitally sign communications (always)" to Enabled.',
      'Check that no other GPO linked to the Domain Controllers OU sets it to Disabled (use gpresult /h on a domain controller).',
      'Refresh Group Policy on domain controllers and confirm clients can still read SYSVOL.',
    ],
    scriptExample: [
      '# Read-only check on a domain controller; review before any change. AdminSecOps never runs this.',
      'Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSMB1Protocol',
      '# Configure through the Default Domain Controllers Policy; direct equivalent for reference only:',
      '# Set-SmbServerConfiguration -RequireSecuritySignature $true',
    ].join('\n'),
    effort: 'low',
  },
  implementationConsiderations: [
    'Very old or third-party SMB clients that cannot sign cannot connect to domain controller shares; such clients are rare and should be replaced.',
    'Signing adds some CPU cost on busy file servers; on domain controllers the impact is negligible.',
  ],
  impact: 'All SMB sessions to domain controllers are signed.',
  rollback: ['Set the policy back to Not Defined or Disabled in the GPO and refresh Group Policy (not recommended).'],
  validation: [
    'Run Get-SmbServerConfiguration on each domain controller and confirm RequireSecuritySignature is True.',
    'Re-run the AdminSecOps collector with domain controller settings enabled and confirm AD-DC-003 is PASS.',
  ],
  references: [AD_REF.smbSigning, AD_REF.attackAdversaryInTheMiddle],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SC-8' },
    { framework: 'NIST-800-53r5', id: 'SC-23' },
    { framework: 'MITRE-ATTACK', id: 'T1557' },
  ],
  tags: ['domain-controllers', 'smb', 'relay', 'active-directory'],
  evaluate: (ctx) =>
    evaluateDcSetting(ctx, {
      label: 'SMB signing',
      classify: (s) => {
        const value = s.smbRequireSecuritySignature;
        if (value === 1) return { state: 'pass', detail: 'RequireSecuritySignature = 1' };
        if (value === 0) return { state: 'fail', detail: 'RequireSecuritySignature = 0 (SMB signing not required)' };
        if (value === null) return { state: 'review', detail: 'RequireSecuritySignature not set; effective value unknown' };
        return { state: 'review', detail: `Unexpected RequireSecuritySignature value ${value}` };
      },
      passReason: 'Every domain controller that was read requires SMB signing.',
      failReason: (n) => `${plural(n, 'domain controller')} do not require SMB signing.`,
      reviewReason: 'SMB signing could not be confirmed on every domain controller.',
      extraNotes: (settings) => {
        const smb1 = settings.filter((s) => s.smb1Enabled === 1).map((s) => s.hostName);
        return smb1.length > 0 ? [`SMBv1 is enabled on ${smb1.join(', ')}; disable it unless a documented legacy dependency exists.`] : [];
      },
    }),
});
