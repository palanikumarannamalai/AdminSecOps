import { windowsOsSupportStatus } from '@adminsecops/inventory';
import { defineControl } from '../../define.js';
import { fact } from '../../helpers.js';
import { fail_, pass_, review_, unknown_, type Verdict } from '../shared/verdicts.js';
import { evaluateHosts, hostBuild, osLabel, type WindowsHost } from './hosts.js';
import { WIN_REF } from './references.js';

const HOST_APPLICABILITY = { description: 'Every Windows host included in the Windows host evidence.' };
const COLLECTOR_VALIDATION = 'Re-run the AdminSecOps Windows host collector on the affected hosts and confirm the control is PASS.';

export const winPowerShellScriptBlockLogging = defineControl({
  id: 'WIN-PS-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'PowerShell script block logging is enabled',
  technology: 'windows',
  category: 'Logging and monitoring',
  subcategory: 'PowerShell',
  description: 'Checks that PowerShell script block logging is turned on by policy, so the content of PowerShell code that runs on the host is recorded in the event log.',
  rationale:
    'Attackers use PowerShell extensively, often with obfuscated or in-memory scripts that leave no file on disk. Script block logging records the de-obfuscated code in event 4104, giving investigators and detection tools the evidence needed to understand and stop an attack.',
  severity: 'medium',
  confidence: 'high',
  applicability: HOST_APPLICABILITY,
  requiredEvidence: ['windows.hosts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each host: PASS when powershell.scriptBlockLoggingEnabled is true (EnableScriptBlockLogging policy = 1), FAIL when false. When the value was not collected the host cannot be evaluated and is reported for review (never PASS). Without the policy, Windows PowerShell 5.1 only logs script blocks it considers suspicious, which is not sufficient for investigations.',
    parameters: {},
  },
  expectedState: '"Turn on PowerShell Script Block Logging" is Enabled on every host, and the PowerShell Operational log is forwarded to central logging.',
  remediation: {
    summary: 'Enable PowerShell script block logging through Group Policy or Intune and forward the events.',
    steps: [
      'Group Policy: Computer Configuration > Policies > Administrative Templates > Windows Components > Windows PowerShell > "Turn on PowerShell Script Block Logging" = Enabled.',
      'For PowerShell 7 also configure the equivalent policy under the PowerShell Core administrative templates.',
      'Increase the size of the Microsoft-Windows-PowerShell/Operational log (for example to 100 MB or more) so events are not overwritten quickly.',
      'Forward the log to your SIEM or Microsoft Sentinel / Defender for Endpoint.',
    ],
    scriptExample: '# Review, then run elevated on a single host (prefer Group Policy)\nGet-ItemProperty HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -ErrorAction SilentlyContinue\n# New-Item -Path HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -Force | Out-Null\n# Set-ItemProperty -Path HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1 -Type DWord',
    effort: 'low',
  },
  implementationConsiderations: [
    'Script block logs can contain secrets that scripts handle in clear text; restrict access to the logs and consider Protected Event Logging.',
    'Logging increases event volume; size the event log and SIEM ingestion accordingly. Invocation logging (start/stop events) adds much more volume and is usually not needed.',
  ],
  impact: 'PowerShell writes event 4104 for executed script blocks; a small performance and storage overhead.',
  rollback: ['Set the policy to Disabled / Not Configured.'],
  validation: [COLLECTOR_VALIDATION, 'Run a PowerShell command and confirm event 4104 appears in Microsoft-Windows-PowerShell/Operational.'],
  references: [WIN_REF.powershellLogging, WIN_REF.securityBaselines, WIN_REF.attackPowerShell],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AU-2' },
    { framework: 'NIST-800-53r5', id: 'AU-12' },
    { framework: 'MCSB', id: 'LT-3' },
    { framework: 'MITRE-ATTACK', id: 'T1059.001' },
  ],
  tags: ['powershell', 'logging', 'detection'],
  evaluate: (ctx) =>
    evaluateHosts(ctx, {
      requirement: 'PowerShell script block logging is enabled',
      classify: (h) => {
        if (h.powershell.scriptBlockLoggingEnabled === true) return pass_('Script block logging enabled.');
        if (h.powershell.scriptBlockLoggingEnabled === false) return fail_('Script block logging is not enabled by policy.');
        return unknown_('Script block logging state was not collected.');
      },
    }),
});

function antivirusVerdict(h: WindowsHost): Verdict {
  const d = h.defender;
  const extras: string[] = [];
  if (d.isTamperProtected === false) extras.push('tamper protection off');
  if (d.antivirusSignatureAgeDays !== null && d.antivirusSignatureAgeDays > 7) extras.push(`signatures ${d.antivirusSignatureAgeDays} days old`);
  const suffix = extras.length > 0 ? ` Also: ${extras.join('; ')}.` : '';
  if (!d.available) {
    return review_('Microsoft Defender Antivirus is not available on this host; confirm that another antivirus product provides real-time protection.');
  }
  if (d.antivirusEnabled === false) {
    return review_(`Microsoft Defender Antivirus is disabled or in passive mode; confirm that another antivirus product provides real-time protection.${suffix}`);
  }
  if (d.realTimeProtectionEnabled === true) return pass_(`Real-time protection on.${suffix}`);
  if (d.realTimeProtectionEnabled === false) return fail_(`Microsoft Defender Antivirus is active but real-time protection is off.${suffix}`);
  return unknown_('Real-time protection state was not collected.');
}

export const winDefenderRealTime = defineControl({
  id: 'WIN-AV-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Antivirus real-time protection is enabled',
  technology: 'windows',
  category: 'Endpoint protection',
  subcategory: 'Antivirus',
  description: 'Checks that Microsoft Defender Antivirus real-time (always-on) protection is enabled on every host, or flags hosts where Defender is not the active antivirus so the administrator can confirm a third-party product protects them.',
  rationale:
    'Real-time protection scans files and processes as they are accessed and blocks known malware and ransomware before it runs. Turning it off - a common attacker and troubleshooting step that is then forgotten - leaves the host without on-access protection.',
  severity: 'high',
  confidence: 'high',
  applicability: HOST_APPLICABILITY,
  requiredEvidence: ['windows.hosts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each host: REVIEW when Microsoft Defender Antivirus is not available or reports antivirusEnabled = false (disabled or passive mode), because a third-party antivirus may be providing protection and AdminSecOps cannot confirm it. Otherwise PASS when realTimeProtectionEnabled is true and FAIL when it is false. When the value was not collected the host cannot be evaluated (review, never PASS). Tamper protection off and signatures older than 7 days are added to the detail as additional observations.',
    parameters: {},
  },
  expectedState: 'Microsoft Defender Antivirus is active with real-time protection and tamper protection on, or a documented third-party antivirus provides equivalent real-time protection.',
  remediation: {
    summary: 'Turn real-time protection back on, prevent it from being disabled, and confirm third-party antivirus where Defender is not active.',
    steps: [
      'Investigate why real-time protection was turned off (troubleshooting, performance exclusions, or malicious activity) before re-enabling it.',
      'Group Policy: Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Real-time Protection > "Turn off real-time protection" = Disabled. Or use Intune Endpoint security > Antivirus.',
      'Enable tamper protection (Microsoft Defender portal > Settings > Endpoints > Advanced features, or Intune) so local administrators and malware cannot turn protection off.',
      'For hosts marked for review, confirm in the third-party antivirus console that the host is protected and its real-time protection is on, and record the exception.',
    ],
    scriptExample: '# Review, then run elevated on a single host\nGet-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected, AntivirusSignatureAge\n# Set-MpPreference -DisableRealtimeMonitoring $false',
    effort: 'low',
  },
  implementationConsiderations: [
    'On Windows Server, Defender Antivirus does not switch to passive mode automatically when a third-party antivirus is installed; running two active products is unsupported.',
    'If performance was the reason for disabling it, use targeted exclusions instead of turning off real-time protection.',
    'With tamper protection on, local changes to real-time protection are blocked; manage settings centrally.',
  ],
  impact: 'Files and processes are scanned on access; minor performance overhead.',
  rollback: ['Not recommended. If required for troubleshooting, temporarily disable real-time protection through the management tool and re-enable it afterwards.'],
  validation: [COLLECTOR_VALIDATION, 'Get-MpComputerStatus shows RealTimeProtectionEnabled : True.'],
  references: [WIN_REF.defenderRealTimeProtection, WIN_REF.defenderCompatibility, WIN_REF.tamperProtection, WIN_REF.attackDisableTools],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SI-3' },
    { framework: 'MCSB', id: 'ES-2' },
    { framework: 'MITRE-ATTACK', id: 'T1562.001' },
  ],
  tags: ['antivirus', 'endpoint-protection', 'defender'],
  evaluate: (ctx) =>
    evaluateHosts(ctx, {
      requirement: 'antivirus real-time protection is enabled',
      reviewGuidance:
        'Hosts where Microsoft Defender Antivirus is unavailable, disabled or passive are listed for review because another antivirus product may protect them; AdminSecOps cannot verify third-party products, so confirm each one in its management console.',
      classify: antivirusVerdict,
    }),
});

export const winOsSupported = defineControl({
  id: 'WIN-OS-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Host operating system is within Microsoft support',
  technology: 'windows',
  category: 'Vulnerability management',
  subcategory: 'Operating system lifecycle',
  description: 'Checks that the operating system of every assessed host still receives security updates from Microsoft at the assessment date.',
  rationale:
    'Once an operating system reaches end of support it no longer receives security updates, so newly discovered vulnerabilities stay exploitable indefinitely. Unsupported systems are a frequent entry point and are often impossible to harden to current standards.',
  severity: 'high',
  confidence: 'high',
  applicability: HOST_APPLICABILITY,
  requiredEvidence: ['windows.hosts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each host the control determines the product from the OS caption and build: Windows 11 by release build and edition (Home/Pro vs Enterprise/Education end-of-updates dates from the Windows 11 release information), other versions from the AdminSecOps Windows lifecycle table (end of extended support). FAIL when the assessment date (evidence time, not the current time) is after the end-of-support date. PASS when it is on or before. When the product, release or edition cannot be identified (for example LTSC editions or unknown builds) the host is reported for review. Extended Security Updates (ESU) are not modelled; hosts covered by ESU still FAIL and should be documented as exceptions.',
    parameters: {},
  },
  expectedState: 'Every host runs a Windows version that receives security updates at the assessment date.',
  remediation: {
    summary: 'Upgrade or replace hosts running unsupported Windows versions, or isolate them and enrol in Extended Security Updates as a temporary measure.',
    steps: [
      'Plan an in-place upgrade or migration to a supported version (for example Windows 11 24H2/25H2, Windows Server 2022/2025).',
      'For Windows 11 feature versions, deploy the latest feature update through Windows Update for Business, Autopatch, Intune or Configuration Manager.',
      'Where an application blocks the upgrade, isolate the host (restricted network segment, no internet access, no privileged sign-ins) and purchase Extended Security Updates if available.',
      'Record hosts covered by ESU as documented exceptions with an end date.',
    ],
    effort: 'high',
  },
  implementationConsiderations: [
    'Check application and driver compatibility before upgrading; test on a pilot host.',
    'Extended Security Updates cover security fixes only and are time-limited.',
    'Support dates are maintained in AdminSecOps; confirm with the Microsoft Lifecycle site for your specific edition.',
  ],
  impact: 'Upgrades require downtime and testing; replacing unsupported systems removes a persistent source of unpatched vulnerabilities.',
  rollback: ['In-place upgrades can usually be rolled back within the rollback window (Windows client) or from backup; keep a backup before upgrading servers.'],
  validation: [COLLECTOR_VALIDATION],
  references: [WIN_REF.windows11ReleaseInformation, WIN_REF.windowsLifecycleFaq, WIN_REF.attackExploitRemoteServices],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SA-22' },
    { framework: 'NIST-800-53r5', id: 'SI-2' },
    { framework: 'MCSB', id: 'PV-6' },
    { framework: 'MITRE-ATTACK', id: 'T1210' },
  ],
  tags: ['lifecycle', 'end-of-support', 'patching'],
  evaluate: (ctx) => {
    const at = ctx.assessedAt;
    return evaluateHosts(ctx, {
      requirement: 'the operating system is within Microsoft support at the assessment date',
      extraFacts: [fact('Assessment date', at.toISOString().slice(0, 10))],
      notes: ['Extended Security Updates (ESU) are not modelled; document hosts covered by ESU as exceptions.'],
      classify: (h) => {
        const status = windowsOsSupportStatus(h.osCaption, hostBuild(h), at);
        if (status === undefined) {
          return unknown_(`Support status could not be determined for ${osLabel(h)}${h.osBuild !== null ? ` (build ${h.osBuild})` : ''}; confirm on the Microsoft Lifecycle site.`);
        }
        if (status.unsupported) return fail_(`${status.product} reached end of support on ${status.endOfSupport}.`);
        return pass_(`${status.product} supported until ${status.endOfSupport}.`);
      },
    });
  },
});
