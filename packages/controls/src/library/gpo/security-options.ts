import {
  enabledGpoLinks,
  gpoAppliesToComputers,
  gpoNamedSettings,
  gpoRegistrySettings,
  settingEnabledState,
  settingNumber,
  type GroupPolicyObject,
} from '@adminsecops/inventory';
import { defineControl } from '../../define.js';
import { affected, fact, fail, notAssessed, pass, plural, review } from '../../helpers.js';
import { REGISTRY, LM_LEVEL_LABELS } from '../windows/registry.js';
import { WIN_REF } from '../windows/references.js';
import { GPO_REF } from './references.js';

function gpoObject(gpo: GroupPolicyObject, detail: string) {
  return affected('groupPolicyObject', gpo.id, gpo.displayName, detail);
}

function linksText(gpo: GroupPolicyObject): string {
  const links = enabledGpoLinks(gpo).map((l) => l.somPath);
  return links.length === 0 ? 'no enabled links' : `linked to ${links.join('; ')}`;
}

const NO_GPOS = 'The evidence contains no Group Policy objects, although every domain has at least the Default Domain Policy. Confirm the collector could read Group Policy.';

export const gpoLanManagerAuthLevel = defineControl({
  id: 'GPO-SEC-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Group Policy enforces LAN Manager authentication level 5 (NTLMv2 only)',
  technology: 'gpo',
  category: 'Authentication',
  subcategory: 'NTLM',
  description:
    'Checks that linked Group Policy sets "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM" (LmCompatibilityLevel 5) and that no linked GPO sets a lower level.',
  rationale:
    'LM and NTLMv1 responses can be cracked or relayed quickly, exposing account passwords and allowing attackers to impersonate users. Windows defaults to level 3, at which clients send NTLMv2 but servers and domain controllers still accept LM and NTLMv1 from any client that offers them. Level 5, enforced domain-wide by Group Policy, makes domain controllers and servers refuse LM and NTLMv1. Microsoft security baselines configure level 5.',
  severity: 'medium',
  confidence: 'medium',
  applicability: { description: 'Active Directory domains whose Group Policy objects were collected.' },
  requiredEvidence: ['gpo.groupPolicyObjects'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'Considers GPOs that apply to computers (at least one enabled link and computer settings not disabled) and reads their computer-scope LmCompatibilityLevel setting (registry path ...\\Control\\Lsa\\LmCompatibilityLevel, matched case-insensitively with MACHINE\\ or HKEY_LOCAL_MACHINE\\ prefixes). FAIL when any such GPO sets a value below 5, because depending on link order and OU placement it can win for some computers. REVIEW when a value cannot be interpreted as a number. PASS when at least one such GPO sets 5 and none sets less. FAIL when no applying GPO configures the setting, because computers then use the Windows default of 3 (documented in the LocalPoliciesSecurityOptions policy CSP). GPOs that set the value but do not apply are mentioned in notes. Link order, security filtering and WMI filters are not evaluated; confirm effective values with WIN-NTLM-001.',
    parameters: { requiredLevel: 5 },
  },
  expectedState: 'A GPO linked at the domain (or to every OU containing computers, including Domain Controllers) sets LAN Manager authentication level to "Send NTLMv2 response only. Refuse LM & NTLM", and no GPO sets a lower level.',
  remediation: {
    summary: 'Set LAN Manager authentication level 5 in a domain-wide GPO after confirming no system still depends on LM or NTLMv1.',
    steps: [
      'Audit NTLMv1 use first: on domain controllers review Security event 4624 for "Package Name (NTLM only): NTLM V1", and enable the "Network security: Restrict NTLM: Audit NTLM authentication in this domain" policy if needed.',
      'Update or retire systems that still use LM/NTLMv1 (very old devices, some NAS/printers, MS-CHAPv2 VPN/RADIUS configurations).',
      'In GPMC edit a GPO linked to the domain (and the Domain Controllers OU): Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > "Network security: LAN Manager authentication level" = "Send NTLMv2 response only. Refuse LM & NTLM".',
      'Remove or correct any GPO listed in the finding that sets a lower level.',
      'Run gpupdate /force on a pilot server and domain controller, verify authentication, then allow normal Group Policy refresh.',
    ],
    scriptExample:
      '# Review only: report GPOs that configure LmCompatibilityLevel (GroupPolicy module)\nGet-GPO -All | ForEach-Object {\n  $xml = Get-GPOReport -Guid $_.Id -ReportType Xml\n  if ($xml -match "LmCompatibilityLevel") { $_.DisplayName }\n}',
    effort: 'medium',
  },
  implementationConsiderations: [
    'Level 5 on domain controllers rejects NTLMv1 and LM from every client; test with legacy devices, MS-CHAPv2-based VPN or Wi-Fi (NPS) and third-party SMB clients.',
    'Apply the setting to the Domain Controllers OU as well: Default Domain Controllers Policy often takes precedence there.',
    'Kerberos is not affected; the setting only changes which NTLM variants are sent and accepted.',
  ],
  impact: 'Clients and servers stop sending and accepting LM and NTLMv1; systems that only support those protocols can no longer authenticate.',
  rollback: ['Set the policy to "Send NTLMv2 response only" (level 3) or Not Defined in the GPO and run gpupdate /force on affected systems.'],
  validation: [
    'Re-run the AdminSecOps Group Policy and Windows collectors and confirm GPO-SEC-001 and WIN-NTLM-001 are PASS.',
    'On a domain controller run: Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name LmCompatibilityLevel (expect 5).',
  ],
  references: [WIN_REF.lanManagerAuthLevel, WIN_REF.securityBaselines, WIN_REF.azurePolicyWindowsBaseline, GPO_REF.groupPolicyProcessing, WIN_REF.attackAdversaryInTheMiddle],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-2(8)' },
    { framework: 'NIST-800-53r5', id: 'CM-6' },
    { framework: 'NIST-800-53r5', id: 'CM-7' },
    { framework: 'MCSB', id: 'NS-8' },
    { framework: 'MITRE-ATTACK', id: 'T1557' },
  ],
  tags: ['ntlm', 'authentication', 'group-policy', 'legacy-protocols'],
  evaluate: (ctx) => {
    const gpos = ctx.data('gpo.groupPolicyObjects');
    if (gpos.length === 0) return notAssessed({ reason: NO_GPOS, summary: 'No Group Policy objects in evidence.' });
    const valuesOf = (g: GroupPolicyObject) => gpoRegistrySettings(g, REGISTRY.lmCompatibilityLevel).map((s) => ({ raw: s.value, num: settingNumber(s.value) }));
    const configured = gpos.map((g) => ({ gpo: g, values: valuesOf(g) })).filter((e) => e.values.length > 0);
    const applying = configured.filter((e) => gpoAppliesToComputers(e.gpo));
    const notApplying = configured.filter((e) => !gpoAppliesToComputers(e.gpo));
    const weak = applying.filter((e) => e.values.some((v) => v.num !== null && v.num < 5));
    const unreadable = applying.filter((e) => e.values.some((v) => v.num === null));
    const strong = applying.filter((e) => e.values.some((v) => v.num === 5));
    const describe = (e: (typeof configured)[number]) =>
      `Sets ${e.values.map((v) => (v.num !== null ? `${v.num} (${LM_LEVEL_LABELS[v.num] ?? 'unknown level'})` : `"${String(v.raw)}"`)).join(', ')}; ${linksText(e.gpo)}.`;
    const facts = [
      fact('GPOs collected', gpos.length),
      fact('Applying GPOs that configure the setting', applying.length),
      fact('Applying GPOs setting a level below 5', weak.length),
      fact('Applying GPOs setting level 5', strong.length),
    ];
    const notes = notApplying.map(
      (e) => `GPO "${e.gpo.displayName}" configures the setting but is not applied (${linksText(e.gpo)}, status ${e.gpo.gpoStatus}). ${describe(e)}`,
    );
    notes.push('Link order, security filtering and WMI filters are not evaluated; WIN-NTLM-001 checks the effective value on assessed hosts.');
    if (weak.length > 0) {
      return fail({
        reason: `${plural(weak.length, 'linked GPO')} set the LAN Manager authentication level below 5, allowing LM or NTLMv1 to be sent or accepted.`,
        summary: `Weak LAN Manager authentication level configured by ${weak.map((e) => `"${e.gpo.displayName}"`).join(', ')}.`,
        facts,
        affectedObjects: weak.map((e) => gpoObject(e.gpo, describe(e))),
        notes,
      });
    }
    if (unreadable.length > 0) {
      return review({
        reason: 'A linked GPO configures the LAN Manager authentication level with a value that could not be interpreted.',
        summary: 'LAN Manager authentication level value needs manual confirmation.',
        facts,
        affectedObjects: unreadable.map((e) => gpoObject(e.gpo, describe(e))),
        notes,
      });
    }
    if (strong.length > 0) {
      return pass({
        reason: `LAN Manager authentication level 5 is set by ${strong.map((e) => `"${e.gpo.displayName}"`).join(', ')} and no linked GPO sets a lower level.`,
        summary: 'Group Policy enforces NTLMv2 only (refuse LM and NTLM).',
        facts,
        notes,
      });
    }
    return fail({
      reason: 'No linked GPO configures the LAN Manager authentication level, so computers use the Windows default (level 3), at which servers and domain controllers still accept LM and NTLMv1.',
      summary: 'LAN Manager authentication level is not enforced by Group Policy.',
      facts,
      notes,
    });
  },
});

function isWdigestPolicyName(name: string): boolean {
  return name.trim().toLowerCase().startsWith('wdigest authentication');
}

export const gpoNoWdigest = defineControl({
  id: 'GPO-SEC-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'No linked GPO enables WDigest credential caching',
  technology: 'gpo',
  category: 'Credential exposure',
  subcategory: 'Credential protection',
  description:
    'Checks that no linked Group Policy object turns on WDigest authentication (UseLogonCredential = 1, or the "WDigest Authentication" administrative template set to Enabled), which makes Windows keep users\' plaintext passwords in LSASS memory.',
  rationale:
    'With WDigest credential caching enabled, anyone who gains administrative access to a computer can read the plaintext passwords of every user who signed in there with common credential dumping tools. Attackers deliberately switch it on to harvest passwords. A GPO that enables it spreads that exposure to every computer in its scope.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Active Directory domains whose Group Policy objects were collected.' },
  requiredEvidence: ['gpo.groupPolicyObjects'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'Considers GPOs that apply to computers (at least one enabled link and computer settings not disabled). FAIL when any of them sets the registry value ...\\SecurityProviders\\WDigest\\UseLogonCredential to 1 (matched case-insensitively with MACHINE\\ or HKEY_LOCAL_MACHINE\\ prefixes, in any settings category) or sets the MS Security Guide administrative template "WDigest Authentication" to Enabled. PASS otherwise; the reason states whether a GPO explicitly disables WDigest or the setting is left to the operating system default (disabled on Windows 8.1 / Windows Server 2012 R2 and later). GPOs that would enable WDigest but are not applied are reported in notes.',
    parameters: {},
  },
  expectedState: 'No GPO enables WDigest; ideally a domain-wide GPO explicitly disables it (MS Security Guide "WDigest Authentication" = Disabled, as in the Microsoft security baselines).',
  remediation: {
    summary: 'Remove the setting that enables WDigest from the listed GPOs and explicitly disable WDigest domain-wide.',
    steps: [
      'For each GPO in the finding, open it in GPMC and find the setting (Computer Configuration > Preferences > Windows Settings > Registry, or Administrative Templates > MS Security Guide > WDigest Authentication).',
      'Delete the registry preference item or set the administrative template to Disabled.',
      'Import the MS Security Guide administrative templates from the Microsoft Security Compliance Toolkit if they are not available, and set "WDigest Authentication (disabling may require KB2871997)" to Disabled in a domain-wide GPO.',
      'Investigate why WDigest was enabled: attackers enable it to harvest passwords. Review the GPO\'s modification history and who has edit rights.',
      'Because plaintext passwords may already have been exposed, reset the passwords of privileged accounts that signed in to affected computers.',
    ],
    effort: 'low',
  },
  implementationConsiderations: [
    'Very old applications that rely on HTTP Digest authentication with cached credentials may prompt for credentials; this is expected and rarely an issue on current Windows versions.',
    'Disabling WDigest takes effect for new sign-ins; passwords already cached remain in memory until the user signs out or the computer restarts.',
  ],
  impact: 'Windows stops storing plaintext passwords for WDigest; users of legacy Digest-authenticated services may be prompted for credentials.',
  rollback: ['Set the GPO setting back to its previous value (not recommended) and run gpupdate /force.'],
  validation: [
    'Re-run the AdminSecOps Group Policy and Windows collectors and confirm GPO-SEC-002 and WIN-CRED-001 are PASS.',
    'On a computer in scope, confirm HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential is 0 or absent.',
  ],
  references: [WIN_REF.advisory2871997, WIN_REF.azurePolicyWindowsBaseline, WIN_REF.securityBaselines, WIN_REF.attackLsassMemory],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5(1)' },
    { framework: 'NIST-800-53r5', id: 'CM-6' },
    { framework: 'MCSB', id: 'IM-8' },
    { framework: 'MITRE-ATTACK', id: 'T1003.001' },
  ],
  tags: ['credential-exposure', 'wdigest', 'group-policy', 'lsass'],
  evaluate: (ctx) => {
    const gpos = ctx.data('gpo.groupPolicyObjects');
    if (gpos.length === 0) return notAssessed({ reason: NO_GPOS, summary: 'No Group Policy objects in evidence.' });
    const stateOf = (g: GroupPolicyObject): { enables: string[]; disables: string[] } => {
      const enables: string[] = [];
      const disables: string[] = [];
      for (const s of gpoRegistrySettings(g, REGISTRY.wdigestUseLogonCredential)) {
        const n = settingNumber(s.value);
        if (n === 1) enables.push(`UseLogonCredential = 1 (${s.category})`);
        else if (n === 0) disables.push('UseLogonCredential = 0');
      }
      for (const s of gpoNamedSettings(g, 'RegistryPolicy', isWdigestPolicyName)) {
        const state = settingEnabledState(s.value);
        if (state === 'Enabled') enables.push(`"${s.name}" = Enabled`);
        else if (state === 'Disabled') disables.push(`"${s.name}" = Disabled`);
      }
      return { enables, disables };
    };
    const evaluated = gpos.map((g) => ({ gpo: g, applies: gpoAppliesToComputers(g), ...stateOf(g) }));
    const enabling = evaluated.filter((e) => e.applies && e.enables.length > 0);
    const disabling = evaluated.filter((e) => e.applies && e.disables.length > 0 && e.enables.length === 0);
    const dormant = evaluated.filter((e) => !e.applies && e.enables.length > 0);
    const facts = [
      fact('GPOs collected', gpos.length),
      fact('Applying GPOs that enable WDigest', enabling.length),
      fact('Applying GPOs that explicitly disable WDigest', disabling.length),
    ];
    const notes = dormant.map(
      (e) => `GPO "${e.gpo.displayName}" would enable WDigest (${e.enables.join(', ')}) but is not applied (${linksText(e.gpo)}). Remove the setting so it cannot take effect if the GPO is linked.`,
    );
    if (enabling.length > 0) {
      return fail({
        reason: `${plural(enabling.length, 'linked GPO')} enable WDigest, causing plaintext passwords to be kept in memory on computers in scope.`,
        summary: `WDigest credential caching is enabled by ${enabling.map((e) => `"${e.gpo.displayName}"`).join(', ')}.`,
        facts,
        affectedObjects: enabling.map((e) => gpoObject(e.gpo, `${e.enables.join(', ')}; ${linksText(e.gpo)}.`)),
        notes,
      });
    }
    return pass({
      reason:
        disabling.length > 0
          ? `No linked GPO enables WDigest, and ${plural(disabling.length, 'GPO')} explicitly disable it (${disabling.map((e) => `"${e.gpo.displayName}"`).join(', ')}).`
          : 'No linked GPO enables WDigest. The setting is not configured by Group Policy, so computers use the operating system default (disabled on Windows 8.1 / Windows Server 2012 R2 and later).',
      summary: 'Group Policy does not enable WDigest credential caching.',
      facts,
      notes:
        disabling.length === 0
          ? [...notes, 'Consider explicitly disabling WDigest in a domain-wide GPO (as the Microsoft security baselines do) so a local change is overridden.']
          : notes,
    });
  },
});
