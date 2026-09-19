import { describe, expect, it } from 'vitest';
import { adComputer, CHILD, daysAgo, domainController } from '../../../test/builders/ad.js';
import { run } from '../../../test/run.js';
import { adLapsCoverage, adUnsupportedComputers, adUnsupportedDomainControllers } from './computers.js';

describe('AD-CMP-001 LAPS coverage', () => {
  it('passes when every Windows computer has a current Windows LAPS expiration', () => {
    expect(run(adLapsCoverage, { 'ad.computers': [adComputer(), adComputer()] }).status).toBe('PASS');
  });

  it('accepts legacy LAPS and notes migration', () => {
    const result = run(adLapsCoverage, { 'ad.computers': [adComputer({ windowsLapsExpiration: null, legacyLapsExpiration: daysAgo(-10) })] });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('legacy Microsoft LAPS');
  });

  it('fails for computers without any LAPS expiration', () => {
    const result = run(adLapsCoverage, {
      'ad.computers': [adComputer(), adComputer({ name: 'SRV01', domain: CHILD, operatingSystem: 'Windows Server 2022 Standard', windowsLapsExpiration: null })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.id).toBe(`${CHILD}\\SRV01`);
    expect(result.statusReason).toContain('50%');
  });

  it('excludes domain controllers, disabled computers and non-Windows systems', () => {
    const result = run(adLapsCoverage, {
      'ad.computers': [
        adComputer(),
        adComputer({ isDomainController: true, windowsLapsExpiration: null, operatingSystem: 'Windows Server 2022 Datacenter' }),
        adComputer({ enabled: false, windowsLapsExpiration: null }),
        adComputer({ operatingSystem: 'Ubuntu 24.04', windowsLapsExpiration: null }),
        adComputer({ operatingSystem: null, windowsLapsExpiration: null }),
      ],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('no operating system value');
  });

  it('requires review when LAPS passwords expired long ago and were not rotated', () => {
    const result = run(adLapsCoverage, { 'ad.computers': [adComputer({ windowsLapsExpiration: daysAgo(120), lastLogonTimestamp: daysAgo(150) })] });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.detail).toContain('120 days');
  });

  it('uses the most recent of the two expiration attributes', () => {
    const result = run(adLapsCoverage, { 'ad.computers': [adComputer({ windowsLapsExpiration: daysAgo(-5), legacyLapsExpiration: daysAgo(400) })] });
    expect(result.status).toBe('PASS');
  });

  it('is NOT_APPLICABLE when only domain controllers exist', () => {
    expect(run(adLapsCoverage, { 'ad.computers': [adComputer({ isDomainController: true })] }).status).toBe('NOT_APPLICABLE');
  });
});

describe('AD-CMP-002 unsupported Windows on computers', () => {
  it('passes for supported versions and notes untracked ones', () => {
    const result = run(adUnsupportedComputers, {
      'ad.computers': [adComputer({ operatingSystem: 'Windows Server 2022 Standard' }), adComputer({ operatingSystem: 'Windows 11 Enterprise' })],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('does not track');
  });

  it('fails for Windows 10 and Server 2012 R2 at the assessment date', () => {
    const result = run(adUnsupportedComputers, {
      'ad.computers': [
        adComputer({ operatingSystem: 'Windows 10 Enterprise' }),
        adComputer({ operatingSystem: 'Windows Server 2012 R2 Standard', lastLogonTimestamp: daysAgo(400) }),
      ],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(2);
    expect(result.observed.summary).toContain('Windows 10');
    expect(result.notes.join(' ')).toContain('Extended Security Updates');
  });

  it('uses the assessment date, not the current date', () => {
    const data = { 'ad.computers': [adComputer({ operatingSystem: 'Windows 10 Pro' })] };
    expect(run(adUnsupportedComputers, data, { assessedAt: '2025-06-01T00:00:00Z' }).status).toBe('PASS');
    expect(run(adUnsupportedComputers, data, { assessedAt: '2025-10-15T12:00:00Z' }).status).toBe('FAIL');
  });

  it('ignores disabled computers and domain controllers', () => {
    const result = run(adUnsupportedComputers, {
      'ad.computers': [
        adComputer({ enabled: false, operatingSystem: 'Windows 7 Professional' }),
        adComputer({ isDomainController: true, operatingSystem: 'Windows Server 2012 R2 Standard' }),
        adComputer(),
      ],
    });
    expect(result.status).toBe('PASS');
  });
});

describe('AD-DC-004 domain controller OS support', () => {
  it('passes for supported domain controllers', () => {
    expect(run(adUnsupportedDomainControllers, { 'ad.domainControllers': [domainController('dc01.contoso.com')] }).status).toBe('PASS');
  });

  it('warns about domain controllers approaching end of support', () => {
    const result = run(adUnsupportedDomainControllers, { 'ad.domainControllers': [domainController('dc01.contoso.com', 'Windows Server 2016 Standard')] });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('2027-01-12');
  });

  it('fails for an unsupported domain controller in a child domain', () => {
    const result = run(adUnsupportedDomainControllers, {
      'ad.domainControllers': [domainController('dc01.contoso.com'), domainController('dc9.emea.contoso.com', 'Windows Server 2012 R2 Datacenter', CHILD)],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.name).toBe(`${CHILD}\\dc9.emea.contoso.com`);
  });

  it('requires review when the OS is unknown', () => {
    expect(run(adUnsupportedDomainControllers, { 'ad.domainControllers': [domainController('dc01.contoso.com', null)] }).status).toBe('REVIEW');
  });

  it('is NOT_ASSESSED for an empty list', () => {
    expect(run(adUnsupportedDomainControllers, { 'ad.domainControllers': [] }).status).toBe('NOT_ASSESSED');
  });
});
