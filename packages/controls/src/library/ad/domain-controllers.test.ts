import { describe, expect, it } from 'vitest';
import { CHILD, dcSetting, domainController } from '../../../test/builders/ad.js';
import { run } from '../../../test/run.js';
import { adDcSmbSigning, adLdapChannelBinding, adLdapSigning } from './domain-controllers.js';

const DC1 = 'dc01.contoso.com';
const DC2 = 'dc02.contoso.com';

describe('AD-DC-001 LDAP signing', () => {
  it('passes when every DC requires signing', () => {
    const result = run(adLdapSigning, {
      'ad.domainControllerSettings': [dcSetting(DC1), dcSetting(DC2)],
      'ad.domainControllers': [domainController(DC1), domainController(DC2)],
    });
    expect(result.status).toBe('PASS');
  });

  it('fails for a DC that only negotiates signing', () => {
    const result = run(adLdapSigning, { 'ad.domainControllerSettings': [dcSetting(DC1), dcSetting(DC2, { ldapServerIntegrity: 1 })] });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.id).toBe(DC2);
  });

  it('never counts a failed registry read as passing', () => {
    const result = run(adLdapSigning, { 'ad.domainControllerSettings': [dcSetting(DC1), dcSetting(DC2, { readStatus: 'Failed' })] });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.detail).toContain('could not be read');
  });

  it('is NOT_ASSESSED when no DC could be read', () => {
    expect(run(adLdapSigning, { 'ad.domainControllerSettings': [dcSetting(DC1, { readStatus: 'Failed' })] }).status).toBe('NOT_ASSESSED');
  });

  it('requires review when a known DC is missing from the settings (short/FQDN names matched)', () => {
    const result = run(adLdapSigning, {
      'ad.domainControllerSettings': [dcSetting('DC01')],
      'ad.domainControllers': [domainController(DC1), domainController('dc03.emea.contoso.com', 'Windows Server 2022 Standard', CHILD)],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjectCount).toBe(1);
    expect(result.affectedObjects[0]?.name).toBe(`${CHILD}\\dc03.emea.contoso.com`);
  });

  it('fails for an unset value on a pre-2025 DC and requires review on 2025 or unknown OS', () => {
    const unset = { 'ad.domainControllerSettings': [dcSetting(DC1, { ldapServerIntegrity: null })] };
    expect(run(adLdapSigning, { ...unset, 'ad.domainControllers': [domainController(DC1, 'Windows Server 2019 Standard')] }).status).toBe('FAIL');
    expect(run(adLdapSigning, { ...unset, 'ad.domainControllers': [domainController(DC1, 'Windows Server 2025 Standard')] }).status).toBe('REVIEW');
    expect(run(adLdapSigning, unset).status).toBe('REVIEW');
  });

  it('is NOT_APPLICABLE when the optional collection was not run and reported NotApplicable', () => {
    expect(run(adLdapSigning, {}, { unavailable: { 'ad.domainControllerSettings': 'NotApplicable' } }).status).toBe('NOT_APPLICABLE');
  });

  it('is NOT_ASSESSED when the optional collection was skipped', () => {
    expect(run(adLdapSigning, { 'ad.domainControllers': [domainController(DC1)] }).status).toBe('NOT_ASSESSED');
  });
});

describe('AD-DC-002 LDAP channel binding', () => {
  it('requires review when both the registry value and OS version are unknown', () => {
    expect(run(adLdapChannelBinding, { 'ad.domainControllerSettings': [dcSetting(DC1, { ldapEnforceChannelBinding: null })] }).status).toBe('REVIEW');
  });
  it('passes when always enforced', () => {
    expect(run(adLdapChannelBinding, { 'ad.domainControllerSettings': [dcSetting(DC1)] }).status).toBe('PASS');
  });

  it('requires review for "when supported"', () => {
    expect(run(adLdapChannelBinding, { 'ad.domainControllerSettings': [dcSetting(DC1, { ldapEnforceChannelBinding: 1 })] }).status).toBe('REVIEW');
  });

  it('fails for "never" and for an unset value on older DCs', () => {
    expect(run(adLdapChannelBinding, { 'ad.domainControllerSettings': [dcSetting(DC1, { ldapEnforceChannelBinding: 0 })] }).status).toBe('FAIL');
    expect(
      run(adLdapChannelBinding, {
        'ad.domainControllerSettings': [dcSetting(DC1, { ldapEnforceChannelBinding: null })],
        'ad.domainControllers': [domainController(DC1, 'Windows Server 2022 Datacenter')],
      }).status,
    ).toBe('FAIL');
  });

  it('requires review for an unset value on Windows Server 2025 (default "when supported")', () => {
    const result = run(adLdapChannelBinding, {
      'ad.domainControllerSettings': [dcSetting(DC1, { ldapEnforceChannelBinding: null })],
      'ad.domainControllers': [domainController(DC1, 'Windows Server 2025 Datacenter')],
    });
    expect(result.status).toBe('REVIEW');
  });
});

describe('AD-DC-003 SMB signing on domain controllers', () => {
  it('passes when required', () => {
    expect(run(adDcSmbSigning, { 'ad.domainControllerSettings': [dcSetting(DC1)] }).status).toBe('PASS');
  });

  it('fails when not required', () => {
    expect(run(adDcSmbSigning, { 'ad.domainControllerSettings': [dcSetting(DC1, { smbRequireSecuritySignature: 0 })] }).status).toBe('FAIL');
  });

  it('requires review when the value is not set', () => {
    expect(run(adDcSmbSigning, { 'ad.domainControllerSettings': [dcSetting(DC1, { smbRequireSecuritySignature: null })] }).status).toBe('REVIEW');
  });

  it('notes SMBv1', () => {
    const result = run(adDcSmbSigning, { 'ad.domainControllerSettings': [dcSetting(DC1, { smb1Enabled: 1 })] });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('SMBv1');
  });

  it('downgrades PASS to REVIEW with partial settings evidence', () => {
    expect(run(adDcSmbSigning, { 'ad.domainControllerSettings': [dcSetting(DC1)] }, { partial: ['ad.domainControllerSettings'] }).status).toBe('REVIEW');
  });
});
