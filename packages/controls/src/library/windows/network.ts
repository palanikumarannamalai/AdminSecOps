import { defineControl } from '../../define.js';
import { eqi } from '../../helpers.js';
import { fail_, pass_, unknown_, type Verdict } from '../shared/verdicts.js';
import { evaluateHosts, type WindowsHost } from './hosts.js';
import { WIN_REF } from './references.js';

const HOST_APPLICABILITY = { description: 'Every Windows host included in the Windows host evidence.' };
const COLLECTOR_VALIDATION = 'Re-run the AdminSecOps Windows host collector on the affected hosts and confirm the control is PASS.';

export const winSmb1Disabled = defineControl({
  id: 'WIN-SMB-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'SMBv1 server is disabled',
  technology: 'windows',
  category: 'Network protocols',
  subcategory: 'SMB',
  description: 'Checks that the SMB 1.0 server protocol is disabled on every assessed Windows host.',
  rationale:
    'SMBv1 is a decades-old protocol without modern security protections (pre-authentication integrity, encryption, secure dialect negotiation). It was the vector for WannaCry and NotPetya and remains a target for wormable exploits. Microsoft has deprecated it and no longer installs it by default.',
  severity: 'high',
  confidence: 'high',
  applicability: HOST_APPLICABILITY,
  requiredEvidence: ['windows.hosts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each host: PASS when smb.smb1ServerEnabled is false (Get-SmbServerConfiguration EnableSMB1Protocol), FAIL when true. When the value is missing the host cannot be evaluated and is reported for review (never PASS).',
    parameters: {},
  },
  expectedState: 'EnableSMB1Protocol is False on every host, and the SMB 1.0/CIFS optional feature is removed where possible.',
  remediation: {
    summary: 'Disable the SMBv1 server on each affected host (and remove the SMB 1.0/CIFS feature) after confirming no client depends on it.',
    steps: [
      'Audit SMBv1 use first: run Set-SmbServerConfiguration -AuditSmb1Access $true and review the Microsoft-Windows-SMBServer/Audit event log for event 3000 over a few weeks.',
      'Replace or update devices that still require SMBv1 (old NAS appliances, scanners, legacy Windows versions).',
      'Disable the server protocol: Set-SmbServerConfiguration -EnableSMB1Protocol $false (or via Group Policy preferences registry item HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1 = 0 on older systems).',
      'Remove the feature: Windows Server "Remove Roles and Features" > SMB 1.0/CIFS File Sharing Support; Windows clients: "Turn Windows features on or off".',
    ],
    scriptExample:
      '# Review, then run elevated on the affected host\nGet-SmbServerConfiguration | Select-Object EnableSMB1Protocol\n# Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n# Windows Server: Uninstall-WindowsFeature -Name FS-SMB1\n# Windows client: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol',
    effort: 'low',
  },
  implementationConsiderations: [
    'Devices that only speak SMBv1 will no longer be able to access shares on the host.',
    'Removing the optional feature requires a restart.',
  ],
  impact: 'SMBv1 clients can no longer connect to the host; SMBv2/v3 clients are unaffected.',
  rollback: ['Set-SmbServerConfiguration -EnableSMB1Protocol $true (re-install the SMB 1.0/CIFS feature first if it was removed).'],
  validation: [COLLECTOR_VALIDATION, 'Get-SmbServerConfiguration shows EnableSMB1Protocol : False.'],
  references: [WIN_REF.smb1, WIN_REF.securityBaselines, WIN_REF.attackExploitRemoteServices],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'CM-7' },
    { framework: 'NIST-800-53r5', id: 'CM-6' },
    { framework: 'MCSB', id: 'NS-8' },
    { framework: 'MITRE-ATTACK', id: 'T1210' },
  ],
  tags: ['smb', 'legacy-protocols', 'windows-hardening'],
  evaluate: (ctx) =>
    evaluateHosts(ctx, {
      requirement: 'the SMBv1 server is disabled',
      classify: (h) => {
        if (h.smb.smb1ServerEnabled === false) return pass_('SMBv1 server disabled.');
        if (h.smb.smb1ServerEnabled === true) return fail_('SMBv1 server is enabled.');
        return unknown_('SMBv1 server state was not collected.');
      },
    }),
});

export const winSmbSigning = defineControl({
  id: 'WIN-SMB-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'SMB server signing is required',
  technology: 'windows',
  category: 'Network protocols',
  subcategory: 'SMB',
  description: 'Checks that every assessed host requires SMB signing for connections to its SMB server (RequireSecuritySignature = true).',
  rationale:
    'Without required signing, an attacker positioned on the network can relay captured NTLM authentication to the host\'s SMB server or tamper with SMB traffic, a common path to lateral movement and privilege escalation in Active Directory environments. Requiring signing prevents SMB relay and tampering.',
  severity: 'medium',
  confidence: 'high',
  applicability: HOST_APPLICABILITY,
  requiredEvidence: ['windows.hosts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each host: PASS when smb.serverRequireSecuritySignature is true, FAIL when false. When the value is missing the host cannot be evaluated and is reported for review (never PASS).',
    parameters: {},
  },
  expectedState: '"Microsoft network server: Digitally sign communications (always)" is Enabled on every host.',
  remediation: {
    summary: 'Require SMB server signing through Group Policy for all computers.',
    steps: [
      'In GPMC edit a GPO linked to the computers: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > "Microsoft network server: Digitally sign communications (always)" = Enabled.',
      'Also enable "Microsoft network client: Digitally sign communications (always)" once all servers support signing.',
      'Test file-server throughput on a pilot group; signing adds CPU overhead on older hardware.',
      'Run gpupdate /force on a pilot host and confirm with Get-SmbServerConfiguration.',
    ],
    scriptExample: '# Review, then run elevated on a single host (prefer Group Policy for fleets)\nGet-SmbServerConfiguration | Select-Object RequireSecuritySignature\n# Set-SmbServerConfiguration -RequireSecuritySignature $true -Force',
    effort: 'low',
  },
  implementationConsiderations: [
    'Windows 11 24H2 Enterprise, Pro and Education require inbound SMB signing by default, and domain controllers require it for their clients; Windows Server 2025 only requires outbound signing by default, so member servers (including 2025) usually need the policy.',
    'Third-party SMB clients (NAS devices, printers, Linux/macOS) must support signing; very old devices may fail to connect.',
    'Signing can reduce throughput on high-speed file servers with older CPUs; SMB encryption is an alternative that also provides integrity.',
  ],
  impact: 'SMB clients that cannot sign are refused; others negotiate signing automatically.',
  rollback: ['Set the policy to Disabled / Not Defined, or run Set-SmbServerConfiguration -RequireSecuritySignature $false.'],
  validation: [COLLECTOR_VALIDATION, 'Get-SmbServerConfiguration shows RequireSecuritySignature : True.'],
  references: [WIN_REF.smbSigning, WIN_REF.securityBaselines, WIN_REF.attackAdversaryInTheMiddle],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SC-8(1)' },
    { framework: 'NIST-800-53r5', id: 'SC-23' },
    { framework: 'MCSB', id: 'NS-8' },
    { framework: 'MITRE-ATTACK', id: 'T1557' },
  ],
  tags: ['smb', 'ntlm-relay', 'windows-hardening'],
  evaluate: (ctx) =>
    evaluateHosts(ctx, {
      requirement: 'SMB server signing is required',
      classify: (h) => {
        if (h.smb.serverRequireSecuritySignature === true) return pass_('SMB server signing required.');
        if (h.smb.serverRequireSecuritySignature === false) return fail_(`SMB server signing is not required${h.isDomainController ? ' (domain controller)' : ''}.`);
        return unknown_('SMB server signing requirement was not collected.');
      },
    }),
});

const FIREWALL_PROFILES = ['Domain', 'Private', 'Public'] as const;

/** Firewall profile verdict. NotConfigured inbound action resolves to the documented default (Block). */
function firewallVerdict(host: WindowsHost): Verdict {
  const problems: string[] = [];
  const unknown: string[] = [];
  const defaults: string[] = [];
  for (const name of FIREWALL_PROFILES) {
    const profile = host.firewallProfiles.find((p) => eqi(p.name, name));
    if (profile === undefined) {
      unknown.push(`${name} profile not reported`);
      continue;
    }
    if (profile.enabled === false) problems.push(`${name} profile disabled`);
    else if (profile.enabled === null) unknown.push(`${name} profile state not reported`);
    const action = (profile.defaultInboundAction ?? '').trim().toLowerCase();
    if (action === 'allow') problems.push(`${name} default inbound action Allow`);
    else if (action === 'notconfigured') defaults.push(name);
    else if (action !== 'block') unknown.push(`${name} default inbound action ${profile.defaultInboundAction ?? 'not reported'}`);
  }
  const defaultNote = defaults.length > 0 ? ` Default inbound action not configured for ${defaults.join(', ')} (Windows default: Block).` : '';
  if (problems.length > 0) return fail_(`${problems.join('; ')}.${unknown.length > 0 ? ` Also: ${unknown.join('; ')}.` : ''}`);
  if (unknown.length > 0) return unknown_(`${unknown.join('; ')}.`);
  return pass_(`All profiles enabled with inbound Block.${defaultNote}`);
}

export const winFirewallEnabled = defineControl({
  id: 'WIN-FW-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Windows Firewall is enabled for all profiles and blocks inbound by default',
  technology: 'windows',
  category: 'Network protection',
  subcategory: 'Windows Firewall',
  description: 'Checks that Windows Firewall is enabled for the Domain, Private and Public profiles and that each profile\'s default inbound action is Block.',
  rationale:
    'The host firewall limits which services an attacker can reach after gaining a foothold on the network, slowing lateral movement and ransomware propagation. A disabled profile or an "allow by default" inbound action exposes every listening service on the host.',
  severity: 'high',
  confidence: 'high',
  applicability: HOST_APPLICABILITY,
  requiredEvidence: ['windows.hosts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each host and each of the Domain, Private and Public profiles: FAIL when a profile is disabled or its default inbound action is Allow. A default inbound action of NotConfigured is treated as Block, the documented Windows default. A missing profile, an unreported enabled state or an unrecognized action cannot be evaluated and is reported for review (never PASS). PASS when all three profiles are enabled with Block.',
    parameters: {},
  },
  expectedState: 'Windows Firewall is On for Domain, Private and Public profiles with inbound connections blocked by default and only required inbound rules allowed.',
  remediation: {
    summary: 'Enable Windows Firewall for all profiles and set the default inbound action to Block through Group Policy or Intune.',
    steps: [
      'Before enabling, inventory required inbound traffic for the host role (for example RDP from admin networks, SMB for file servers, application ports) and create allow rules for it.',
      'In GPMC: Computer Configuration > Policies > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Properties; for each profile set Firewall state = On and Inbound connections = Block (default).',
      'Alternatively use Intune endpoint security > Firewall policies for managed devices.',
      'Run gpupdate /force on a pilot host and verify the application still works.',
    ],
    scriptExample: '# Review, then run elevated on a single host (prefer Group Policy/Intune for fleets)\nGet-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction\n# Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block',
    effort: 'medium',
  },
  implementationConsiderations: [
    'If a third-party firewall manages the host, Windows Firewall may be intentionally off; confirm the third-party product enforces equivalent inbound blocking and document the exception.',
    'Enabling the firewall without the required allow rules breaks inbound application traffic; start with the Domain profile rules the host role needs.',
    'Local rule merging can be disabled in Group Policy so users or applications cannot add their own allow rules.',
  ],
  impact: 'Inbound connections not matched by an allow rule are blocked.',
  rollback: ['Set the profile state back to the previous value in the GPO, or Set-NetFirewallProfile -Profile <name> -Enabled False on the host.'],
  validation: [COLLECTOR_VALIDATION, 'Get-NetFirewallProfile shows Enabled True and DefaultInboundAction Block (or NotConfigured) for all profiles.'],
  references: [WIN_REF.firewallRules, WIN_REF.firewallDefaultInboundAction, WIN_REF.securityBaselines, WIN_REF.attackDisableFirewall],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SC-7' },
    { framework: 'NIST-800-53r5', id: 'SC-7(12)' },
    { framework: 'MCSB', id: 'NS-1' },
    { framework: 'MITRE-ATTACK', id: 'T1562.004' },
  ],
  tags: ['firewall', 'network', 'windows-hardening'],
  evaluate: (ctx) =>
    evaluateHosts(ctx, {
      requirement: 'Windows Firewall is enabled for Domain, Private and Public profiles with default inbound action Block',
      classify: firewallVerdict,
    }),
});

export const winRdpNla = defineControl({
  id: 'WIN-RDP-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Remote Desktop requires Network Level Authentication',
  technology: 'windows',
  category: 'Remote access',
  subcategory: 'Remote Desktop',
  description: 'Checks that every host with Remote Desktop enabled requires Network Level Authentication (NLA), so users must authenticate before a remote session is created.',
  rationale:
    'Without NLA, an unauthenticated attacker reaches the full Remote Desktop session and logon screen, which consumes server resources and exposes pre-authentication vulnerabilities (several critical RDP vulnerabilities could only be exploited without NLA). NLA also reduces denial-of-service risk and exposure of the logon screen.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Windows hosts in the evidence that have Remote Desktop enabled; hosts with Remote Desktop disabled are compliant.' },
  requiredEvidence: ['windows.hosts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each host: PASS when Remote Desktop is disabled (fDenyTSConnections = 1) or NLA is required (UserAuthentication = 1). FAIL when Remote Desktop is enabled and NLA is not required. When NLA state is unknown and Remote Desktop is enabled or its state is unknown, the host cannot be evaluated and is reported for review (never PASS).',
    parameters: {},
  },
  expectedState: 'Remote Desktop is disabled where not needed; where enabled, "Require user authentication for remote connections by using Network Level Authentication" is Enabled.',
  remediation: {
    summary: 'Require Network Level Authentication for Remote Desktop through Group Policy.',
    steps: [
      'Confirm all RDP clients support NLA (every supported Windows version and current Microsoft Remote Desktop clients do).',
      'In GPMC: Computer Configuration > Policies > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security > "Require user authentication for remote connections by using Network Level Authentication" = Enabled.',
      'For a single host: System Properties > Remote > select "Allow connections only from computers running Remote Desktop with Network Level Authentication".',
      'Disable Remote Desktop on hosts that do not need it.',
    ],
    scriptExample:
      '# Review, then run elevated on a single host (prefer Group Policy for fleets)\n(Get-CimInstance -Namespace root\\cimv2\\TerminalServices -ClassName Win32_TSGeneralSetting -Filter "TerminalName=\'RDP-Tcp\'").UserAuthenticationRequired\n# Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -Name UserAuthentication -Value 1',
    effort: 'low',
  },
  implementationConsiderations: [
    'Users whose password has expired cannot change it through an NLA-protected RDP connection; provide another password change path.',
    'Clients that are not domain-joined must be able to reach a domain controller (or use Remote Desktop Gateway / KDC proxy) for Kerberos, otherwise NTLM is used.',
  ],
  impact: 'Clients must authenticate before the session starts; very old RDP clients without CredSSP cannot connect.',
  rollback: ['Set the Group Policy setting to Disabled / Not Configured, or clear the NLA option in System Properties > Remote.'],
  validation: [COLLECTOR_VALIDATION, 'Connecting with a client shows the credential prompt before the remote logon screen.'],
  references: [WIN_REF.rdpAllowAccess, WIN_REF.rdpNlaPolicy, WIN_REF.securityBaselines, WIN_REF.attackRdp],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-17' },
    { framework: 'NIST-800-53r5', id: 'IA-2' },
    { framework: 'MCSB', id: 'PV-3' },
    { framework: 'MITRE-ATTACK', id: 'T1021.001' },
  ],
  tags: ['rdp', 'remote-access', 'windows-hardening'],
  evaluate: (ctx) =>
    evaluateHosts(ctx, {
      requirement: 'Remote Desktop requires Network Level Authentication when enabled',
      classify: (h) => {
        if (h.rdp.enabled === false) return pass_('Remote Desktop is disabled.');
        if (h.rdp.nlaRequired === true) return pass_(`NLA required${h.rdp.enabled === null ? ' (Remote Desktop state not reported)' : ''}.`);
        if (h.rdp.enabled === true && h.rdp.nlaRequired === false) return fail_('Remote Desktop is enabled without Network Level Authentication.');
        if (h.rdp.enabled === null && h.rdp.nlaRequired === false) return unknown_('NLA is not required; Remote Desktop enabled state was not reported.');
        return unknown_('Network Level Authentication state was not collected.');
      },
    }),
});
