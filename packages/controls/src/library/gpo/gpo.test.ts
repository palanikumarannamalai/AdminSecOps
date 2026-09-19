import { describe, expect, it } from 'vitest';
import { gpo, gppArtifact, LMCOMPAT_KEY, setting, sysvolScan, WDIGEST_KEY } from '../../../test/builders/gpo.js';
import { run } from '../../../test/run.js';
import { gpoUnusedObjects } from './hygiene.js';
import { gpoNoPreferencePasswords } from './passwords.js';
import { gpoLanManagerAuthLevel, gpoNoWdigest } from './security-options.js';

describe('GPO-PWD-001 Group Policy Preferences passwords', () => {
  it('passes when no cpassword artifact was found', () => {
    const result = run(gpoNoPreferencePasswords, { 'gpo.sysvolPasswordArtifacts': sysvolScan([], 40) });
    expect(result.status).toBe('PASS');
    expect(result.notes).toEqual([]);
  });

  it('fails and lists each file, resolving the GPO name when available', () => {
    const gpoId = '{31B2F340-016D-11D2-945F-00C04FB984F9}';
    const result = run(gpoNoPreferencePasswords, {
      'gpo.sysvolPasswordArtifacts': sysvolScan([gppArtifact({ gpoId }), gppArtifact({ fileName: 'ScheduledTasks.xml', relativePath: 'x\\ScheduledTasks.xml' })]),
      'gpo.groupPolicyObjects': [gpo({ id: '31b2f340-016d-11d2-945f-00c04fb984f9', displayName: 'Default Domain Policy' })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(2);
    expect(result.affectedObjects[0]?.detail).toContain('Default Domain Policy');
    expect(JSON.stringify(result)).not.toContain('cpassword=');
  });

  it('still evaluates when the optional GPO list is unavailable', () => {
    const result = run(
      gpoNoPreferencePasswords,
      { 'gpo.sysvolPasswordArtifacts': sysvolScan([gppArtifact({ gpoId: '{ABC}' })]) },
      { unavailable: { 'gpo.groupPolicyObjects': 'Failed' } },
    );
    expect(result.status).toBe('FAIL');
  });

  it('adds a note when no preference files were scanned', () => {
    const result = run(gpoNoPreferencePasswords, { 'gpo.sysvolPasswordArtifacts': sysvolScan([], 0) });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('SYSVOL');
  });

  it('downgrades PASS to REVIEW when the scan was partial', () => {
    const result = run(gpoNoPreferencePasswords, { 'gpo.sysvolPasswordArtifacts': sysvolScan() }, { partial: ['gpo.sysvolPasswordArtifacts'] });
    expect(result.status).toBe('REVIEW');
  });

  it('is NOT_ASSESSED when SYSVOL could not be scanned', () => {
    expect(run(gpoNoPreferencePasswords, {}, { unavailable: { 'gpo.sysvolPasswordArtifacts': 'Unauthorized' } }).status).toBe('NOT_ASSESSED');
  });
});

describe('GPO-HYG-001 unlinked or disabled GPOs', () => {
  it('passes when every GPO is linked and enabled', () => {
    expect(run(gpoUnusedObjects, { 'gpo.groupPolicyObjects': [gpo(), gpo()] }).status).toBe('PASS');
  });

  it('requires review for unlinked, disabled-link and all-settings-disabled GPOs', () => {
    const result = run(gpoUnusedObjects, {
      'gpo.groupPolicyObjects': [
        gpo({ displayName: 'Active' }),
        gpo({ displayName: 'Orphan', links: [] }),
        gpo({ displayName: 'Disabled links', links: [{ somPath: 'corp/Servers', enabled: false }] }),
        gpo({ displayName: 'Switched off', gpoStatus: 'AllSettingsDisabled' }),
      ],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects.map((o) => o.name)).toEqual(['Orphan', 'Disabled links', 'Switched off']);
    expect(result.notes.join(' ')).toContain('intentionally');
  });

  it('does not flag a GPO with at least one enabled link', () => {
    const result = run(gpoUnusedObjects, {
      'gpo.groupPolicyObjects': [gpo({ links: [{ somPath: 'a', enabled: false }, { somPath: 'b', enabled: true }] })],
    });
    expect(result.status).toBe('PASS');
  });

  it('is NOT_ASSESSED for an empty GPO list', () => {
    expect(run(gpoUnusedObjects, { 'gpo.groupPolicyObjects': [] }).status).toBe('NOT_ASSESSED');
  });
});

describe('GPO-SEC-001 LAN Manager authentication level', () => {
  const lm = (value: unknown, name = LMCOMPAT_KEY) => setting('SecurityOptions', name, value);

  it('passes when a linked GPO sets level 5', () => {
    const result = run(gpoLanManagerAuthLevel, { 'gpo.groupPolicyObjects': [gpo({ displayName: 'Baseline', settings: [lm(5)] }), gpo()] });
    expect(result.status).toBe('PASS');
    expect(result.statusReason).toContain('Baseline');
  });

  it('fails when a linked GPO sets a lower level, even if another sets 5', () => {
    const result = run(gpoLanManagerAuthLevel, {
      'gpo.groupPolicyObjects': [gpo({ settings: [lm(5)] }), gpo({ displayName: 'Legacy', settings: [lm(2)] })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.name)).toEqual(['Legacy']);
    expect(result.affectedObjects[0]?.detail).toContain('Send NTLM response only');
  });

  it('fails when no linked GPO configures the setting (Windows default 3)', () => {
    const result = run(gpoLanManagerAuthLevel, { 'gpo.groupPolicyObjects': [gpo()] });
    expect(result.status).toBe('FAIL');
    expect(result.statusReason).toContain('level 3');
  });

  it('matches registry paths case-insensitively with either hive prefix and numeric strings', () => {
    const result = run(gpoLanManagerAuthLevel, {
      'gpo.groupPolicyObjects': [gpo({ settings: [setting('RegistryValue', 'hkey_local_machine\\system\\currentcontrolset\\control\\LSA\\lmcompatibilitylevel', '5')] })],
    });
    expect(result.status).toBe('PASS');
  });

  it('ignores GPOs that do not apply to computers and mentions them in notes', () => {
    const result = run(gpoLanManagerAuthLevel, {
      'gpo.groupPolicyObjects': [
        gpo({ settings: [lm(5)] }),
        gpo({ displayName: 'Unlinked weak', links: [], settings: [lm(0)] }),
        gpo({ displayName: 'Computer off', gpoStatus: 'ComputerSettingsDisabled', settings: [lm(1)] }),
        gpo({ displayName: 'User scope', settings: [setting('SecurityOptions', LMCOMPAT_KEY, 0, 'User')] }),
      ],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('Unlinked weak');
    expect(result.notes.join(' ')).toContain('Computer off');
  });

  it('requires review for a value that is not a number', () => {
    const result = run(gpoLanManagerAuthLevel, { 'gpo.groupPolicyObjects': [gpo({ settings: [lm('Send NTLMv2')] })] });
    expect(result.status).toBe('REVIEW');
  });

  it('is NOT_ASSESSED for an empty GPO list', () => {
    expect(run(gpoLanManagerAuthLevel, { 'gpo.groupPolicyObjects': [] }).status).toBe('NOT_ASSESSED');
  });
});

describe('GPO-SEC-002 WDigest', () => {
  it('passes when no GPO configures WDigest, noting the OS default', () => {
    const result = run(gpoNoWdigest, { 'gpo.groupPolicyObjects': [gpo()] });
    expect(result.status).toBe('PASS');
    expect(result.statusReason).toContain('default');
  });

  it('passes when a GPO explicitly disables WDigest', () => {
    const result = run(gpoNoWdigest, {
      'gpo.groupPolicyObjects': [gpo({ displayName: 'Baseline', settings: [setting('RegistryPolicy', 'WDigest Authentication (disabling may require KB2871997)', 'Disabled')] })],
    });
    expect(result.status).toBe('PASS');
    expect(result.statusReason).toContain('Baseline');
  });

  it('fails when a linked GPO sets UseLogonCredential = 1 (registry path with MACHINE prefix)', () => {
    const result = run(gpoNoWdigest, {
      'gpo.groupPolicyObjects': [
        gpo({ displayName: 'Bad', settings: [setting('RegistryValue', 'MACHINE\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential', 1)] }),
      ],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.name)).toEqual(['Bad']);
  });

  it('fails when the administrative template enables WDigest', () => {
    const result = run(gpoNoWdigest, {
      'gpo.groupPolicyObjects': [gpo({ settings: [setting('RegistryPolicy', 'WDigest Authentication (disabling may require KB2871997)', 'Enabled')] })],
    });
    expect(result.status).toBe('FAIL');
  });

  it('does not fail for an unlinked GPO but reports it in notes', () => {
    const result = run(gpoNoWdigest, {
      'gpo.groupPolicyObjects': [gpo({ displayName: 'Dormant', links: [{ somPath: 'corp/Old', enabled: false }], settings: [setting('RegistryValue', WDIGEST_KEY, 1)] })],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('Dormant');
  });

  it('is NOT_ASSESSED when GPOs were not collected', () => {
    expect(run(gpoNoWdigest, {}, { unavailable: { 'gpo.groupPolicyObjects': 'Failed' } }).status).toBe('NOT_ASSESSED');
  });
});
