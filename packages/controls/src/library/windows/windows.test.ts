import { describe, expect, it } from 'vitest';
import { firewallProfile, host, WIN11_ENTERPRISE_24H2, type HostInput } from '../../../test/builders/windows.js';
import { run } from '../../../test/run.js';
import type { ControlDefinition } from '../../define.js';
import { winCredentialGuard, winLsaProtection, winNtlmv2Only, winWdigestDisabled } from './credentials.js';
import { winFirewallEnabled, winRdpNla, winSmb1Disabled, winSmbSigning } from './network.js';
import { winDefenderRealTime, winOsSupported, winPowerShellScriptBlockLogging } from './protection.js';

const hosts = (...inputs: HostInput[]) => ({ 'windows.hosts': inputs.map((i, n) => host({ hostName: `HOST${n + 1}`, ...i })) });
const status = (control: ControlDefinition, ...inputs: HostInput[]) => run(control, hosts(...inputs)).status;

describe('shared host evaluation semantics', () => {
  it('is NOT_ASSESSED when the evidence contains no hosts', () => {
    expect(run(winSmb1Disabled, { 'windows.hosts': [] }).status).toBe('NOT_ASSESSED');
  });

  it('downgrades PASS to REVIEW on partial host evidence', () => {
    expect(run(winSmb1Disabled, hosts({}), { partial: ['windows.hosts'] }).status).toBe('REVIEW');
  });

  it('lists non-compliant and unknown hosts together on FAIL, with a note', () => {
    const result = run(winSmb1Disabled, hosts({}, { smb: { smb1ServerEnabled: true } }, { smb: { smb1ServerEnabled: null } }));
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.id)).toEqual(['HOST2', 'HOST3']);
    expect(result.notes.join(' ')).toContain('could not be evaluated');
  });
});

describe('WIN-SMB-001 SMBv1 server', () => {
  it('passes when disabled on all hosts', () => expect(status(winSmb1Disabled, {}, {})).toBe('PASS'));
  it('fails when enabled on a host', () => expect(status(winSmb1Disabled, {}, { smb: { smb1ServerEnabled: true } })).toBe('FAIL'));
  it('requires review when one host is unknown', () => expect(status(winSmb1Disabled, {}, { smb: { smb1ServerEnabled: null } })).toBe('REVIEW'));
  it('is NOT_ASSESSED when every host is unknown', () => expect(status(winSmb1Disabled, { smb: { smb1ServerEnabled: null } })).toBe('NOT_ASSESSED'));
});

describe('WIN-SMB-002 SMB signing', () => {
  it('passes when required', () => expect(status(winSmbSigning, {})).toBe('PASS'));
  it('fails when not required', () => {
    const result = run(winSmbSigning, hosts({ isDomainController: true, smb: { serverRequireSecuritySignature: false } }));
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('domain controller');
  });
  it('does not pass an unknown value', () => expect(status(winSmbSigning, { smb: { serverRequireSecuritySignature: null } })).toBe('NOT_ASSESSED'));
});

describe('WIN-FW-001 Windows Firewall', () => {
  const profiles = (...p: Record<string, unknown>[]) => ({ firewallProfiles: p });

  it('passes with all profiles enabled and Block', () => expect(status(winFirewallEnabled, {})).toBe('PASS'));

  it('treats NotConfigured inbound action as the Block default', () => {
    const result = run(winFirewallEnabled, hosts(profiles(firewallProfile('Domain', true, 'NotConfigured'), firewallProfile('Private'), firewallProfile('Public'))));
    expect(result.status).toBe('PASS');
  });

  it('fails when a profile is disabled', () => {
    const result = run(winFirewallEnabled, hosts(profiles(firewallProfile('Domain'), firewallProfile('Private'), firewallProfile('Public', false))));
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('Public profile disabled');
  });

  it('fails when the default inbound action is Allow', () => {
    expect(status(winFirewallEnabled, profiles(firewallProfile('domain', true, 'Allow'), firewallProfile('private'), firewallProfile('public')))).toBe('FAIL');
  });

  it('does not pass when a profile is missing or its state unknown', () => {
    expect(status(winFirewallEnabled, profiles(firewallProfile('Domain'), firewallProfile('Private')))).toBe('NOT_ASSESSED');
    expect(status(winFirewallEnabled, {}, profiles(firewallProfile('Domain', null), firewallProfile('Private'), firewallProfile('Public')))).toBe('REVIEW');
  });
});

describe('WIN-RDP-001 Network Level Authentication', () => {
  it('passes when NLA is required', () => expect(status(winRdpNla, {})).toBe('PASS'));
  it('passes when RDP is disabled even without NLA', () => expect(status(winRdpNla, { rdp: { enabled: false, nlaRequired: false } })).toBe('PASS'));
  it('fails when RDP is enabled without NLA', () => expect(status(winRdpNla, { rdp: { enabled: true, nlaRequired: false } })).toBe('FAIL'));
  it('does not pass when NLA state is unknown and RDP is enabled', () => expect(status(winRdpNla, { rdp: { enabled: true, nlaRequired: null } })).toBe('NOT_ASSESSED'));
  it('does not pass when RDP state is unknown and NLA is off', () => expect(status(winRdpNla, {}, { rdp: { enabled: null, nlaRequired: false } })).toBe('REVIEW'));
});

describe('WIN-LSA-001 LSA protection', () => {
  it('passes with RunAsPPL = 1', () => expect(status(winLsaProtection, {})).toBe('PASS'));
  it('passes with RunAsPPL = 2 on Windows 11 24H2', () => expect(status(winLsaProtection, { ...WIN11_ENTERPRISE_24H2, lsa: { runAsPPL: 2 } })).toBe('PASS'));
  it('fails with RunAsPPL = 2 on Windows Server 2022 (not enforced there)', () => expect(status(winLsaProtection, { lsa: { runAsPPL: 2 } })).toBe('FAIL'));
  it('requires review with RunAsPPL = 2 on Windows Server 2025', () =>
    expect(status(winLsaProtection, { osCaption: 'Microsoft Windows Server 2025 Datacenter', osBuild: '26100', osVersion: '10.0.26100', lsa: { runAsPPL: 2 } })).toBe('REVIEW'));
  it('fails with RunAsPPL = 0', () => expect(status(winLsaProtection, { lsa: { runAsPPL: 0 } })).toBe('FAIL'));
  it('fails when not configured on a server (off by default)', () => expect(status(winLsaProtection, { lsa: { runAsPPL: null } })).toBe('FAIL'));
  it('requires review when not configured on Windows 11 22H2+ (may be on by default)', () => {
    const result = run(winLsaProtection, hosts({ ...WIN11_ENTERPRISE_24H2, lsa: { runAsPPL: null } }));
    expect(result.status).toBe('REVIEW');
    expect(result.notes.join(' ')).toContain('event 12');
  });
});

describe('WIN-CRED-001 WDigest', () => {
  it('passes with UseLogonCredential = 0', () => expect(status(winWdigestDisabled, {})).toBe('PASS'));
  it('fails with UseLogonCredential = 1', () => expect(status(winWdigestDisabled, {}, { lsa: { wdigestUseLogonCredential: 1 } })).toBe('FAIL'));
  it('passes when absent on a supported OS (disabled by default since 8.1 / 2012 R2)', () =>
    expect(status(winWdigestDisabled, { lsa: { wdigestUseLogonCredential: null } })).toBe('PASS'));
  it('fails when absent on Windows Server 2008 R2 (enabled by default)', () =>
    expect(status(winWdigestDisabled, { osCaption: 'Microsoft Windows Server 2008 R2 Standard', osBuild: '7601', osVersion: '6.1.7601', lsa: { wdigestUseLogonCredential: null } })).toBe('FAIL'));
  it('uses the caption when the build is unknown', () =>
    expect(status(winWdigestDisabled, { osCaption: 'Microsoft Windows Server 2012 R2 Standard', osBuild: null, osVersion: null, lsa: { wdigestUseLogonCredential: null } })).toBe('PASS'));
  it('cannot evaluate an absent value when the OS is unknown', () =>
    expect(status(winWdigestDisabled, { osCaption: null, osBuild: null, osVersion: null, lsa: { wdigestUseLogonCredential: null } })).toBe('NOT_ASSESSED'));
});

describe('WIN-NTLM-001 LAN Manager authentication level', () => {
  it('passes at level 5', () => expect(status(winNtlmv2Only, {})).toBe('PASS'));
  it('fails at level 3', () => expect(status(winNtlmv2Only, { lsa: { lmCompatibilityLevel: 3 } })).toBe('FAIL'));
  it('fails when not configured (OS default 3)', () => {
    const result = run(winNtlmv2Only, hosts({ isDomainController: true, lsa: { lmCompatibilityLevel: null } }));
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('default level 3');
  });
  it('does not pass an unexpected value', () => expect(status(winNtlmv2Only, { lsa: { lmCompatibilityLevel: 9 } })).toBe('NOT_ASSESSED'));
});

describe('WIN-PS-001 script block logging', () => {
  it('passes when enabled', () => expect(status(winPowerShellScriptBlockLogging, {})).toBe('PASS'));
  it('fails when disabled', () => expect(status(winPowerShellScriptBlockLogging, { powershell: { scriptBlockLoggingEnabled: false } })).toBe('FAIL'));
  it('does not pass when unknown', () => expect(status(winPowerShellScriptBlockLogging, { powershell: { scriptBlockLoggingEnabled: null } })).toBe('NOT_ASSESSED'));
});

describe('WIN-AV-001 antivirus real-time protection', () => {
  it('passes when Defender real-time protection is on', () => expect(status(winDefenderRealTime, {})).toBe('PASS'));

  it('fails when Defender is active but real-time protection is off', () => {
    const result = run(winDefenderRealTime, hosts({ defender: { realTimeProtectionEnabled: false, isTamperProtected: false, antivirusSignatureAgeDays: 30 } }));
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('tamper protection off');
    expect(result.affectedObjects[0]?.detail).toContain('30 days');
  });

  it('requires review when Defender is not available (third-party antivirus must be confirmed)', () => {
    const result = run(winDefenderRealTime, hosts({ defender: { available: false, antivirusEnabled: null, realTimeProtectionEnabled: null } }));
    expect(result.status).toBe('REVIEW');
    expect(result.notes.join(' ')).toContain('third-party');
  });

  it('requires review when Defender is in passive mode or disabled', () =>
    expect(status(winDefenderRealTime, { defender: { antivirusEnabled: false, realTimeProtectionEnabled: false } })).toBe('REVIEW'));

  it('does not pass when real-time protection state is unknown', () =>
    expect(status(winDefenderRealTime, { defender: { realTimeProtectionEnabled: null } })).toBe('NOT_ASSESSED'));
});

describe('WIN-CG-001 Credential Guard', () => {
  it('passes when running on a member server', () => expect(status(winCredentialGuard, {})).toBe('PASS'));

  it('fails when not running and reports VBS state', () => {
    const result = run(winCredentialGuard, hosts({ credentialGuard: { running: false, vbsStatus: 1 } }));
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('configured but not running');
  });

  it('is NOT_APPLICABLE on domain controllers', () => {
    const result = run(winCredentialGuard, hosts({ isDomainController: true, credentialGuard: { running: false, vbsStatus: 0 } }));
    expect(result.status).toBe('NOT_APPLICABLE');
  });

  it('is NOT_APPLICABLE on Windows Pro and non-domain-joined hosts', () => {
    expect(status(winCredentialGuard, { osCaption: 'Microsoft Windows 11 Pro', isServer: false, credentialGuard: { running: false } })).toBe('NOT_APPLICABLE');
    expect(status(winCredentialGuard, { domainJoined: false, credentialGuard: { running: false } })).toBe('NOT_APPLICABLE');
  });

  it('is NOT_APPLICABLE on Windows Server 2012 R2', () =>
    expect(status(winCredentialGuard, { osCaption: 'Microsoft Windows Server 2012 R2 Standard', osBuild: '9600', credentialGuard: { running: false } })).toBe('NOT_APPLICABLE'));

  it('evaluates only supported hosts in a mixed fleet', () => {
    const result = run(winCredentialGuard, hosts({ isDomainController: true, credentialGuard: { running: false } }, { ...WIN11_ENTERPRISE_24H2, credentialGuard: { running: false } }));
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.id)).toEqual(['HOST2']);
  });

  it('does not pass when state is unknown', () => expect(status(winCredentialGuard, { credentialGuard: { running: null } })).toBe('NOT_ASSESSED'));
});

describe('WIN-OS-001 operating system support', () => {
  const at = (date: string) => ({ assessedAt: `${date}T12:00:00Z` });

  it('passes for Windows Server 2022 in 2026', () => expect(run(winOsSupported, hosts({}), at('2026-09-01')).status).toBe('PASS'));

  it('fails for Windows Server 2012 R2 after October 2023', () => {
    const result = run(winOsSupported, hosts({ osCaption: 'Microsoft Windows Server 2012 R2 Datacenter', osBuild: '9600' }), at('2026-09-01'));
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('2023-10-10');
  });

  it('uses the assessment date, not the current date', () => {
    const input = hosts({ osCaption: 'Microsoft Windows 10 Enterprise', osBuild: '19045', isServer: false });
    expect(run(winOsSupported, input, at('2025-10-14')).status).toBe('PASS');
    expect(run(winOsSupported, input, at('2025-10-15')).status).toBe('FAIL');
  });

  it('applies Windows 11 edition-specific dates by build', () => {
    const pro23h2 = hosts({ osCaption: 'Microsoft Windows 11 Pro', osBuild: '22631', isServer: false });
    const ent23h2 = hosts({ osCaption: 'Microsoft Windows 11 Enterprise', osBuild: '22631', isServer: false });
    expect(run(winOsSupported, pro23h2, at('2026-09-01')).status).toBe('FAIL');
    expect(run(winOsSupported, ent23h2, at('2026-09-01')).status).toBe('PASS');
    expect(run(winOsSupported, ent23h2, at('2026-11-11')).status).toBe('FAIL');
  });

  it('requires review for an unknown product (for example LTSC)', () => {
    const result = run(winOsSupported, hosts({}, { osCaption: 'Microsoft Windows 11 Enterprise LTSC', osBuild: '26100', isServer: false }), at('2026-09-01'));
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects.map((o) => o.id)).toEqual(['HOST2']);
  });
});
