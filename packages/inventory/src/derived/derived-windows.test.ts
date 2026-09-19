import { describe, expect, it } from 'vitest';
import { normalizeRegistryPath, registryPathEquals, settingEnabledState, settingNumber } from './group-policy.js';
import { windows11ServicingStatus, windowsBuildNumber, windowsOsSupportStatus } from './windows-servicing.js';

describe('group policy helpers', () => {
  it('normalizes hive prefixes, case and separators', () => {
    const expected = 'hklm\\system\\currentcontrolset\\control\\lsa\\lmcompatibilitylevel';
    expect(normalizeRegistryPath('MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel')).toBe(expected);
    expect(normalizeRegistryPath('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel')).toBe(expected);
    expect(normalizeRegistryPath('HKLM:\\SYSTEM/CurrentControlSet\\\\Control\\Lsa\\LmCompatibilityLevel\\')).toBe(expected);
    expect(registryPathEquals('USER\\Software\\X', 'HKEY_CURRENT_USER\\software\\x')).toBe(true);
  });

  it('interprets setting values', () => {
    expect(settingNumber(5)).toBe(5);
    expect(settingNumber(' 3 ')).toBe(3);
    expect(settingNumber('Enabled')).toBeNull();
    expect(settingNumber(true)).toBeNull();
    expect(settingEnabledState('enabled')).toBe('Enabled');
    expect(settingEnabledState(false)).toBe('Disabled');
    expect(settingEnabledState(1)).toBeNull();
  });
});

describe('windows servicing helpers', () => {
  it('parses build numbers from osBuild or osVersion', () => {
    expect(windowsBuildNumber('22631', null)).toBe(22631);
    expect(windowsBuildNumber(null, '10.0.20348')).toBe(20348);
    expect(windowsBuildNumber('n/a', null)).toBeNull();
  });

  it('computes Windows 11 support by edition and build', () => {
    const at = new Date('2026-09-01T00:00:00Z');
    expect(windows11ServicingStatus('Microsoft Windows 11 Pro', 26100, at)).toMatchObject({ endOfSupport: '2026-10-13', unsupported: false });
    expect(windows11ServicingStatus('Microsoft Windows 11 Pro Education', 22631, at)?.unsupported).toBe(true);
    expect(windows11ServicingStatus('Microsoft Windows 11 Education', 22631, at)?.unsupported).toBe(false);
    expect(windows11ServicingStatus('Microsoft Windows 11 Enterprise', 99999, at)).toBeUndefined();
    expect(windows11ServicingStatus('Microsoft Windows 11 Enterprise LTSC', 26100, at)).toBeUndefined();
  });

  it('does not treat Windows Server 2025 (build 26100) as Windows 11', () => {
    const status = windowsOsSupportStatus('Microsoft Windows Server 2025 Datacenter', 26100, new Date('2026-09-01T00:00:00Z'));
    expect(status?.product).toBe('Windows Server 2025');
  });
});
