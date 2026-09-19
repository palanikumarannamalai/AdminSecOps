import { defineControl } from '../../define.js';
import { fail_, na_, pass_, review_, unknown_, type Verdict } from '../shared/verdicts.js';
import { evaluateHosts, hostBuild, isWindows11Client, osLabel, type WindowsHost } from './hosts.js';
import { LM_LEVEL_LABELS, LM_LEVEL_OS_DEFAULT } from './registry.js';
import { WIN_REF } from './references.js';

const HOST_APPLICABILITY = { description: 'Every Windows host included in the Windows host evidence.' };
const COLLECTOR_VALIDATION = 'Re-run the AdminSecOps Windows host collector on the affected hosts and confirm the control is PASS.';
const dc = (h: WindowsHost) => (h.isDomainController ? ' (domain controller)' : '');

/** Windows 11 22H2 (build 22621) and later. */
const WIN11_22H2_BUILD = 22621;
/** Windows 8.1 / Windows Server 2012 R2. */
const WIN81_BUILD = 9600;
/** Windows Server 2016 / Windows 10 1607. */
const WS2016_BUILD = 14393;
/** Windows Server 2025. */
const WS2025_BUILD = 26100;

function lsaVerdict(h: WindowsHost): Verdict {
  const build = hostBuild(h);
  const win11 = isWindows11Client(h);
  const value = h.lsa.runAsPPL;
  if (value === 1) return pass_('LSA protection enabled with UEFI lock (RunAsPPL = 1).');
  if (value === 2) {
    if (win11 && build !== null && build >= WIN11_22H2_BUILD) return pass_('LSA protection enabled without UEFI lock (RunAsPPL = 2).');
    if (win11 && build === null) return review_('RunAsPPL = 2 is only enforced on Windows 11 22H2 and later and the build was not reported; confirm WinInit event 12 shows LSASS started as a protected process.');
    if (h.isServer && build !== null && build >= WS2025_BUILD) return review_('RunAsPPL = 2 (without UEFI lock); confirm WinInit event 12 shows LSASS started as a protected process, or use value 1.');
    return fail_(`RunAsPPL = 2 is only enforced on Windows 11 22H2 and later; ${osLabel(h)} needs value 1.`);
  }
  if (value === 0) return fail_(`LSA protection is disabled (RunAsPPL = 0)${dc(h)}.`);
  if (value === null) {
    if (win11 && (build === null || build >= WIN11_22H2_BUILD)) {
      return review_('RunAsPPL is not configured. Windows 11 22H2+ enables LSA protection by default only on clean installs that are enterprise-joined and HVCI-capable; confirm WinInit event 12, or configure it explicitly.');
    }
    return fail_(`LSA protection is not configured (RunAsPPL absent, so LSASS is not protected)${dc(h)}.`);
  }
  return unknown_(`Unrecognized RunAsPPL value ${value}.`);
}

export const winLsaProtection = defineControl({
  id: 'WIN-LSA-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'LSA protection (RunAsPPL) is enabled',
  technology: 'windows',
  category: 'Credential protection',
  subcategory: 'LSASS',
  description: 'Checks that the Local Security Authority process (LSASS) runs as a protected process (RunAsPPL), which prevents untrusted code from reading its memory or injecting into it.',
  rationale:
    'LSASS holds password hashes, Kerberos tickets and other credentials of users who signed in. Credential dumping from LSASS memory is one of the most common attacker techniques after gaining administrator rights, and leads directly to lateral movement and domain compromise. LSA protection blocks standard dumping tools and unsigned plug-ins.',
  severity: 'medium',
  confidence: 'high',
  applicability: HOST_APPLICABILITY,
  requiredEvidence: ['windows.hosts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each host (lsa.runAsPPL): PASS when 1 (enabled with UEFI lock), or 2 (enabled without UEFI lock) on Windows 11 build 22621+. Value 2 on other versions is not enforced and FAILs, except Windows 11 with unknown build and Windows Server 2025, which are marked for REVIEW. FAIL when 0. When the value is absent: Windows 11 22H2+ clients are marked for REVIEW because Windows enables LSA protection by default on clean, enterprise-joined, HVCI-capable installs without writing RunAsPPL; all other hosts FAIL because protection is off by default. Other values cannot be evaluated (review).',
    parameters: {},
  },
  expectedState: 'RunAsPPL = 1 (or 2 on Windows 11 22H2+) on every host, and WinInit event 12 reports that LSASS started as a protected process.',
  remediation: {
    summary: 'Enable LSA protection through Group Policy or Intune after auditing LSA plug-ins.',
    steps: [
      'Audit first: enable LSASS audit mode (HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\LSASS.exe AuditLevel = 8) on a pilot group and review CodeIntegrity events 3065/3066 for plug-ins or drivers that would be blocked (for example old smart card, password filter or security products).',
      'Windows 11 22H2+: Group Policy Computer Configuration > Administrative Templates > System > Local Security Authority > "Configures LSASS to run as a protected process" = Enabled with UEFI Lock.',
      'Other versions: Group Policy Preferences registry item HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa RunAsPPL (REG_DWORD) = 1.',
      'Restart the host and confirm System event 12 from WinInit ("LSASS.exe was started as a protected process with level: 4").',
    ],
    scriptExample: '# Review, then run elevated on a single host (prefer Group Policy/Intune). Restart required.\nGet-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RunAsPPL -ErrorAction SilentlyContinue\n# Set-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RunAsPPL -Value 1 -Type DWord',
    effort: 'medium',
  },
  implementationConsiderations: [
    'Enabled with UEFI lock (value 1 on Secure Boot devices), the setting is stored in firmware and cannot be removed by editing the registry; disabling then requires the LSA Protected Process Opt-out tool.',
    'Unsigned or non-compliant LSA plug-ins and password filters will not load; test domain controllers carefully (password filters, auditing tools).',
    'Requires a restart to take effect.',
  ],
  impact: 'Processes without the required signature can no longer read LSASS memory or load into LSASS; some legacy security or authentication add-ins may stop working.',
  rollback: ['Set RunAsPPL = 0 (or the policy option Disabled) and restart; if a UEFI variable was set, also run the LSA Protected Process Opt-out tool.'],
  validation: [COLLECTOR_VALIDATION, 'System event log shows WinInit event 12 after restart.'],
  references: [WIN_REF.lsaProtection, WIN_REF.securityBaselines, WIN_REF.attackLsassMemory],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SI-16' },
    { framework: 'NIST-800-53r5', id: 'SC-39' },
    { framework: 'MCSB', id: 'IM-8' },
    { framework: 'MITRE-ATTACK', id: 'T1003.001' },
  ],
  tags: ['lsass', 'credential-protection', 'windows-hardening'],
  evaluate: (ctx) =>
    evaluateHosts(ctx, {
      requirement: 'LSASS runs as a protected process',
      reviewGuidance:
        'Hosts marked for review may already run LSASS as a protected process through Windows defaults; check System event 12 from WinInit, and configure the setting explicitly so the result does not depend on how the device was installed.',
      classify: lsaVerdict,
    }),
});

/** WDigest default (when UseLogonCredential is absent): disabled on Windows 8.1 / Server 2012 R2 and later. */
function wdigestDefaultDisabled(h: WindowsHost): boolean | null {
  const build = hostBuild(h);
  if (build !== null) return build >= WIN81_BUILD;
  const caption = h.osCaption ?? '';
  if (/windows (10|11)\b|windows 8\.1|server (2012 r2|2016|2019|2022|2025)/i.test(caption)) return true;
  if (/windows (xp|vista|7)\b|windows 8(?!\.1)|server (2003|2008|2012(?! r2))/i.test(caption)) return false;
  return null;
}

export const winWdigestDisabled = defineControl({
  id: 'WIN-CRED-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'WDigest does not store plaintext credentials',
  technology: 'windows',
  category: 'Credential protection',
  subcategory: 'WDigest',
  description: 'Checks that WDigest authentication is not configured to keep users\' plaintext passwords in LSASS memory (UseLogonCredential is not 1).',
  rationale:
    'When WDigest credential caching is on, anyone with administrator rights on the host can read the plaintext passwords of every user who signed in, with widely available tools. Attackers turn it on deliberately to harvest passwords, so a value of 1 on a modern system is also an indicator of compromise.',
  severity: 'high',
  confidence: 'high',
  applicability: HOST_APPLICABILITY,
  requiredEvidence: ['windows.hosts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each host (lsa.wdigestUseLogonCredential): FAIL when 1, PASS when 0. When the value is absent the operating system default applies: WDigest caching is disabled by default on Windows 8.1 / Windows Server 2012 R2 (build 9600) and later, so those hosts PASS, and it is enabled by default on earlier versions, so they FAIL. The version is taken from the OS build, falling back to the OS caption; when neither identifies the version the host cannot be evaluated (review). Other values cannot be evaluated (review).',
    parameters: {},
  },
  expectedState: 'UseLogonCredential is 0 (explicitly, as in the Microsoft security baselines) or absent on Windows 8.1 / Server 2012 R2 and later.',
  remediation: {
    summary: 'Set UseLogonCredential to 0 on affected hosts, investigate why it was enabled, and reset exposed passwords.',
    steps: [
      'Treat UseLogonCredential = 1 on a modern system as a possible indicator of compromise: check when and how it was set (Group Policy, script, attacker) before changing it.',
      'Set it explicitly to 0 domain-wide: Group Policy > Computer Configuration > Administrative Templates > MS Security Guide > "WDigest Authentication (disabling may require KB2871997)" = Disabled (import the MS Security Guide ADMX from the Security Compliance Toolkit), or a Group Policy Preferences registry item.',
      'Sign out users / restart affected hosts so cached plaintext passwords are cleared from memory.',
      'Reset passwords of privileged accounts that signed in to affected hosts while the setting was on.',
    ],
    scriptExample: '# Review, then run elevated on a single host\nGet-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest -Name UseLogonCredential -ErrorAction SilentlyContinue\n# Set-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest -Name UseLogonCredential -Value 0 -Type DWord',
    effort: 'low',
  },
  implementationConsiderations: [
    'Hosts older than Windows 8.1 / Server 2012 R2 are out of support; setting UseLogonCredential = 0 there requires the KB2871997 update and does not remove the other risks of unsupported systems (see WIN-OS-001).',
    'Applications that rely on HTTP Digest single sign-on with cached credentials may prompt for credentials.',
  ],
  impact: 'Windows no longer keeps WDigest plaintext passwords for new sign-ins.',
  rollback: ['Delete the UseLogonCredential value or set it to its previous value (not recommended).'],
  validation: [COLLECTOR_VALIDATION, 'The registry value UseLogonCredential is 0 or absent on the host.'],
  references: [WIN_REF.advisory2871997, WIN_REF.azurePolicyWindowsBaseline, WIN_REF.securityBaselines, WIN_REF.attackLsassMemory],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5(1)' },
    { framework: 'NIST-800-53r5', id: 'CM-6' },
    { framework: 'MCSB', id: 'IM-8' },
    { framework: 'MITRE-ATTACK', id: 'T1003.001' },
  ],
  tags: ['wdigest', 'credential-protection', 'lsass', 'windows-hardening'],
  evaluate: (ctx) =>
    evaluateHosts(ctx, {
      requirement: 'WDigest does not cache plaintext credentials (UseLogonCredential is not 1)',
      classify: (h) => {
        const value = h.lsa.wdigestUseLogonCredential;
        if (value === 1) return fail_(`UseLogonCredential = 1: plaintext passwords are kept in memory${dc(h)}.`);
        if (value === 0) return pass_('UseLogonCredential = 0.');
        if (value !== null) return unknown_(`Unrecognized UseLogonCredential value ${value}.`);
        const disabledByDefault = wdigestDefaultDisabled(h);
        if (disabledByDefault === true) return pass_(`Not configured; disabled by default on ${osLabel(h)}.`);
        if (disabledByDefault === false) return fail_(`Not configured; WDigest caching is enabled by default on ${osLabel(h)}.`);
        return unknown_('UseLogonCredential is not configured and the operating system version could not be determined.');
      },
    }),
});

export const winNtlmv2Only = defineControl({
  id: 'WIN-NTLM-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'LAN Manager authentication level is 5 (NTLMv2 only, refuse LM and NTLM)',
  technology: 'windows',
  category: 'Authentication',
  subcategory: 'NTLM',
  description: 'Checks that every host sets "Network security: LAN Manager authentication level" to "Send NTLMv2 response only. Refuse LM & NTLM" (LmCompatibilityLevel 5).',
  rationale:
    'At lower levels hosts send or accept LM and NTLMv1 responses, which can be cracked or relayed to recover passwords and impersonate users. The Windows default (level 3) still lets servers and domain controllers accept LM and NTLMv1 from clients that offer them. Level 5 is the Microsoft security baseline value.',
  severity: 'medium',
  confidence: 'high',
  applicability: HOST_APPLICABILITY,
  requiredEvidence: ['windows.hosts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      `For each host (lsa.lmCompatibilityLevel): PASS when 5, FAIL when 0-4. When the value is absent the Windows default of ${LM_LEVEL_OS_DEFAULT} applies (documented for Windows Vista / Server 2008 and later in the LocalPoliciesSecurityOptions policy CSP; earlier versions default lower), so the host FAILS. Other values cannot be evaluated (review).`,
    parameters: { requiredLevel: 5 },
  },
  expectedState: 'LmCompatibilityLevel = 5 on every host, enforced by a domain-wide GPO (see GPO-SEC-001).',
  remediation: {
    summary: 'Enforce LAN Manager authentication level 5 through Group Policy after auditing NTLMv1 use.',
    steps: [
      'Audit NTLMv1 use on domain controllers (event 4624 "Package Name (NTLM only): NTLM V1") and fix or retire systems that need it.',
      'Configure Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > "Network security: LAN Manager authentication level" = "Send NTLMv2 response only. Refuse LM & NTLM" in a GPO linked to the domain and the Domain Controllers OU.',
      'For hosts not managed by Group Policy use Intune (LocalPoliciesSecurityOptions policy) or local security policy.',
    ],
    scriptExample: '# Review, then run elevated on a single host (prefer Group Policy)\nGet-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name LmCompatibilityLevel -ErrorAction SilentlyContinue\n# Set-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name LmCompatibilityLevel -Value 5 -Type DWord',
    effort: 'medium',
  },
  implementationConsiderations: [
    'Legacy devices and MS-CHAPv2-based VPN/Wi-Fi authentication through NPS may fail at level 5; test them first.',
    'Domain controllers enforce what they accept for domain accounts, so prioritize them.',
  ],
  impact: 'LM and NTLMv1 responses are no longer sent or accepted by the host.',
  rollback: ['Set the policy back to level 3 or Not Defined and run gpupdate /force.'],
  validation: [COLLECTOR_VALIDATION],
  references: [WIN_REF.lanManagerAuthLevel, WIN_REF.azurePolicyWindowsBaseline, WIN_REF.securityBaselines, WIN_REF.attackAdversaryInTheMiddle],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-2(8)' },
    { framework: 'NIST-800-53r5', id: 'CM-6' },
    { framework: 'MCSB', id: 'NS-8' },
    { framework: 'MITRE-ATTACK', id: 'T1557' },
  ],
  tags: ['ntlm', 'authentication', 'legacy-protocols', 'windows-hardening'],
  evaluate: (ctx) =>
    evaluateHosts(ctx, {
      requirement: 'LmCompatibilityLevel is 5',
      classify: (h) => {
        const value = h.lsa.lmCompatibilityLevel;
        if (value === 5) return pass_('Level 5 (Send NTLMv2 response only. Refuse LM & NTLM).');
        if (value !== null && Number.isInteger(value) && value >= 0 && value < 5) return fail_(`Level ${value} (${LM_LEVEL_LABELS[value] ?? ''})${dc(h)}.`);
        if (value === null) return fail_(`Not configured; Windows default level ${LM_LEVEL_OS_DEFAULT} (${LM_LEVEL_LABELS[LM_LEVEL_OS_DEFAULT] ?? ''}) applies${dc(h)}.`);
        return unknown_(`Unrecognized LmCompatibilityLevel value ${value}.`);
      },
    }),
});

function credentialGuardVerdict(h: WindowsHost): Verdict {
  if (h.isDomainController) return na_('Domain controller: Microsoft does not recommend Credential Guard on domain controllers.');
  if (h.domainJoined === false) return na_('Not domain-joined: Credential Guard protects domain credentials.');
  const caption = h.osCaption ?? '';
  const build = hostBuild(h);
  if (!h.isServer && /\b(home|pro)\b/i.test(caption)) return na_(`${osLabel(h)} does not support Credential Guard (Enterprise or Education required).`);
  if (h.isServer && build !== null && build < WS2016_BUILD) return na_(`${osLabel(h)} does not support Credential Guard (Windows Server 2016 or later required).`);
  if (h.credentialGuard.running === true) return pass_('Credential Guard is running.');
  if (h.credentialGuard.running === false) {
    const vbs = h.credentialGuard.vbsStatus;
    const vbsText = vbs === 0 ? 'VBS is off' : vbs === 1 ? 'VBS is configured but not running (check hardware/firmware support)' : vbs === 2 ? 'VBS is running but Credential Guard is not' : 'VBS status not reported';
    return fail_(`Credential Guard is not running; ${vbsText}.`);
  }
  return unknown_('Credential Guard state was not collected.');
}

export const winCredentialGuard = defineControl({
  id: 'WIN-CG-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Credential Guard is running on supported hosts',
  technology: 'windows',
  category: 'Credential protection',
  subcategory: 'Credential Guard',
  description: 'Checks that Credential Guard (virtualization-based isolation of NTLM hashes and Kerberos tickets) is running on domain-joined Windows Enterprise/Education clients and Windows Server 2016+ member servers.',
  rationale:
    'Credential Guard moves domain credential secrets into an isolated process protected by virtualization-based security, so even an attacker with administrator or kernel-level code on the host cannot extract reusable NTLM hashes or Kerberos tickets. This blocks pass-the-hash and pass-the-ticket lateral movement from compromised workstations and servers.',
  severity: 'medium',
  confidence: 'medium',
  applicability: {
    description:
      'Domain-joined Windows Enterprise/Education clients and Windows Server 2016 or later member servers. Domain controllers, Pro/Home editions and non-domain-joined hosts are not applicable.',
  },
  requiredEvidence: ['windows.hosts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each host: NOT_APPLICABLE for domain controllers (Microsoft does not recommend Credential Guard there), hosts reported as not domain-joined, client Home/Pro editions (Credential Guard requires Enterprise or Education) and servers older than Windows Server 2016 (build 14393). Otherwise PASS when credentialGuard.running is true (SecurityServicesRunning contains 1), FAIL when false (the detail includes the VBS status), and review when the state is not reported. Hardware readiness (VBS, Secure Boot, TPM) is not evaluated, so a FAIL on hardware that cannot run VBS should be documented as an exception. Confidence is medium for that reason.',
    parameters: {},
  },
  expectedState: 'Credential Guard runs on every supported domain-joined non-DC host (Windows 11 22H2+ and Windows Server 2025 enable it by default on eligible hardware).',
  remediation: {
    summary: 'Enable virtualization-based security with Credential Guard through Group Policy or Intune on supported hosts.',
    steps: [
      'Check hardware readiness: 64-bit CPU with virtualization extensions and SLAT, UEFI with Secure Boot, TPM 2.0 recommended; virtual machines need nested virtualization / VBS support from the hypervisor.',
      'Test applications that need Kerberos unconstrained delegation, DES, NTLMv1, MS-CHAPv2 or CredSSP saved credentials: these break or prompt with Credential Guard.',
      'Group Policy: Computer Configuration > Administrative Templates > System > Device Guard > "Turn On Virtualization Based Security" = Enabled, Credential Guard Configuration = "Enabled with UEFI lock" (or "without lock" during pilot).',
      'Or Intune: Endpoint security > Account protection > Credential Guard.',
      'Restart and confirm with msinfo32 ("Virtualization-based security Services Running: Credential Guard").',
    ],
    scriptExample: '# Review only: show Credential Guard / VBS state on a host\nGet-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard |\n  Select-Object VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning',
    effort: 'medium',
  },
  implementationConsiderations: [
    'Enabling Credential Guard on Exchange Server is not supported; exclude Exchange servers and document the exception.',
    'Hyper-V live migration using CredSSP fails on hosts with Credential Guard; use Kerberos constrained delegation instead.',
    'With UEFI lock, disabling requires physical presence at boot; use "without lock" while piloting.',
    'Single sign-on for Wi-Fi/VPN using MS-CHAPv2 stops working; move to certificate-based authentication.',
  ],
  impact: 'Domain credentials are isolated; protocols that need the raw secret (NTLMv1, MS-CHAPv2 SSO, unconstrained delegation) no longer work with saved or single sign-on credentials.',
  rollback: ['Set the Group Policy / Intune setting to Disabled and restart (with UEFI lock, follow Microsoft\'s documented procedure to remove the UEFI variable).'],
  validation: [COLLECTOR_VALIDATION, 'msinfo32 lists Credential Guard under "Virtualization-based security Services Running".'],
  references: [WIN_REF.credentialGuard, WIN_REF.lsaProtection, WIN_REF.attackLsassMemory, WIN_REF.attackPassTheHash],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SC-39' },
    { framework: 'NIST-800-53r5', id: 'IA-5' },
    { framework: 'MCSB', id: 'IM-8' },
    { framework: 'MITRE-ATTACK', id: 'T1003.001' },
    { framework: 'MITRE-ATTACK', id: 'T1550.002' },
  ],
  tags: ['credential-guard', 'credential-protection', 'vbs', 'windows-hardening'],
  evaluate: (ctx) =>
    evaluateHosts(ctx, {
      requirement: 'Credential Guard is running on supported domain-joined non-DC hosts',
      classify: credentialGuardVerdict,
    }),
});
