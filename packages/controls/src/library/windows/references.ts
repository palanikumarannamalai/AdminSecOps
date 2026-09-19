import type { Reference } from '@adminsecops/schemas';

/**
 * Windows host references (also used by Group Policy controls). Every URL was checked on
 * Microsoft Learn / the publisher's site when added. Titles are paraphrased.
 */
const ms = (title: string, url: string): Reference => ({ title, url, publisher: 'Microsoft' });
const mitre = (title: string, url: string): Reference => ({ title, url, publisher: 'MITRE' });
const LEARN = 'https://learn.microsoft.com/en-us';

export const WIN_REF = {
  securityBaselines: ms(
    'Windows security baselines',
    `${LEARN}/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines`,
  ),
  azurePolicyWindowsBaseline: ms(
    'Windows security baseline (Azure Policy guest configuration reference)',
    `${LEARN}/azure/governance/policy/samples/guest-configuration-baseline-windows`,
  ),
  smb1: ms(
    'How to detect, enable and disable SMBv1, SMBv2 and SMBv3 in Windows',
    `${LEARN}/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3`,
  ),
  smbSigning: ms('Overview of Server Message Block signing', `${LEARN}/windows-server/storage/file-server/smb-signing-overview`),
  firewallRules: ms(
    'Windows Firewall rules',
    `${LEARN}/windows/security/operating-system-security/network-security/windows-firewall/rules`,
  ),
  firewallDefaultInboundAction: ms(
    'INetFwPolicy2::get_DefaultInboundAction (default inbound action is Block)',
    `${LEARN}/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_defaultinboundaction`,
  ),
  rdpAllowAccess: ms(
    'Enable Remote Desktop on your PC (why to allow connections only with NLA)',
    `${LEARN}/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access`,
  ),
  rdpNlaPolicy: ms(
    'Policy CSP - ADMX_TerminalServer (require user authentication by using NLA)',
    `${LEARN}/windows/client-management/mdm/policy-csp-admx-terminalserver`,
  ),
  lsaProtection: ms(
    'Configure added LSA protection',
    `${LEARN}/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection`,
  ),
  credentialGuard: ms('Credential Guard overview', `${LEARN}/windows/security/identity-protection/credential-guard/`),
  advisory2871997: ms(
    'Microsoft Security Advisory 2871997: update to improve credentials protection and management',
    `${LEARN}/security-updates/securityadvisories/2016/2871997`,
  ),
  lanManagerAuthLevel: ms(
    'Policy CSP - LocalPoliciesSecurityOptions: Network security LAN Manager authentication level',
    `${LEARN}/windows/client-management/mdm/policy-csp-localpoliciessecurityoptions`,
  ),
  powershellLogging: ms('about_Logging_Windows (PowerShell script block logging)', `${LEARN}/powershell/module/microsoft.powershell.core/about/about_logging_windows`),
  defenderRealTimeProtection: ms(
    'Enable and configure Microsoft Defender Antivirus always-on protection',
    `${LEARN}/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus`,
  ),
  defenderCompatibility: ms(
    'Microsoft Defender Antivirus compatibility with other security products',
    `${LEARN}/defender-endpoint/microsoft-defender-antivirus-compatibility`,
  ),
  tamperProtection: ms(
    'Protect security settings with tamper protection',
    `${LEARN}/defender-endpoint/tamper-protection-overview`,
  ),
  windows11ReleaseInformation: ms('Windows 11 release information', `${LEARN}/windows/release-health/windows11-release-information`),
  windowsLifecycleFaq: ms('Windows lifecycle FAQ', `${LEARN}/lifecycle/faq/windows`),

  attackLsassMemory: mitre('MITRE ATT&CK T1003.001: OS Credential Dumping: LSASS Memory', 'https://attack.mitre.org/techniques/T1003/001/'),
  attackPassTheHash: mitre('MITRE ATT&CK T1550.002: Pass the Hash', 'https://attack.mitre.org/techniques/T1550/002/'),
  attackAdversaryInTheMiddle: mitre('MITRE ATT&CK T1557: Adversary-in-the-Middle', 'https://attack.mitre.org/techniques/T1557/'),
  attackExploitRemoteServices: mitre(
    'MITRE ATT&CK T1210: Exploitation of Remote Services',
    'https://attack.mitre.org/techniques/T1210/',
  ),
  attackDisableFirewall: mitre(
    'MITRE ATT&CK T1562.004: Impair Defenses: Disable or Modify System Firewall',
    'https://attack.mitre.org/techniques/T1562/004/',
  ),
  attackDisableTools: mitre(
    'MITRE ATT&CK T1562.001: Impair Defenses: Disable or Modify Tools',
    'https://attack.mitre.org/techniques/T1562/001/',
  ),
  attackPowerShell: mitre('MITRE ATT&CK T1059.001: PowerShell', 'https://attack.mitre.org/techniques/T1059/001/'),
  attackRdp: mitre('MITRE ATT&CK T1021.001: Remote Desktop Protocol', 'https://attack.mitre.org/techniques/T1021/001/'),
} as const satisfies Record<string, Reference>;
