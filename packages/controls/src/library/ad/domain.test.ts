import { describe, expect, it } from 'vitest';
import { adDomain, adForest, adTrust, CHILD, CONTOSO } from '../../../test/builders/ad.js';
import { run } from '../../../test/run.js';
import { adDomainFunctionalLevel, adExternalTrustSidFiltering, adMachineAccountQuota, adRecycleBin } from './domain.js';

describe('AD-DOM-001 machine account quota', () => {
  it('passes when every domain has a quota of 0', () => {
    expect(run(adMachineAccountQuota, { 'ad.domains': [adDomain(CONTOSO), adDomain(CHILD)] }).status).toBe('PASS');
  });

  it('fails for the domain that keeps the default of 10', () => {
    const result = run(adMachineAccountQuota, { 'ad.domains': [adDomain(CONTOSO), adDomain(CHILD, { machineAccountQuota: 10 })] });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.name).toBe(CHILD);
  });

  it('requires review when the quota could not be read (null is not assumed to be 0)', () => {
    expect(run(adMachineAccountQuota, { 'ad.domains': [adDomain(CONTOSO, { machineAccountQuota: null })] }).status).toBe('REVIEW');
  });

  it('is NOT_ASSESSED for an empty domain list', () => {
    expect(run(adMachineAccountQuota, { 'ad.domains': [] }).status).toBe('NOT_ASSESSED');
  });
});

describe('AD-DOM-002 Recycle Bin', () => {
  it('passes when enabled', () => {
    expect(run(adRecycleBin, { 'ad.forest': adForest() }).status).toBe('PASS');
  });

  it('fails when disabled', () => {
    const result = run(adRecycleBin, { 'ad.forest': adForest({ recycleBinEnabled: false }) });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(1);
  });

  it('is NOT_APPLICABLE when the collector reported AD as not applicable', () => {
    expect(run(adRecycleBin, {}, { unavailable: { 'ad.forest': 'NotApplicable' } }).status).toBe('NOT_APPLICABLE');
  });
});

describe('AD-DOM-003 domain functional level', () => {
  it('passes at Windows2016Domain and Windows2025Domain', () => {
    const result = run(adDomainFunctionalLevel, { 'ad.domains': [adDomain(CONTOSO), adDomain(CHILD, { domainMode: 'Windows2025Domain' })] });
    expect(result.status).toBe('PASS');
  });

  it('fails for a domain below 2016', () => {
    const result = run(adDomainFunctionalLevel, { 'ad.domains': [adDomain(CONTOSO), adDomain(CHILD, { domainMode: 'Windows2012R2Domain' })] });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('Windows2012R2Domain');
  });

  it('requires review for an unrecognised level', () => {
    expect(run(adDomainFunctionalLevel, { 'ad.domains': [adDomain(CONTOSO, { domainMode: 'UnknownMode' })] }).status).toBe('REVIEW');
  });
});

describe('AD-TRU-001 SID filtering on external trusts', () => {
  it('passes when external trusts are quarantined', () => {
    expect(run(adExternalTrustSidFiltering, { 'ad.trusts': [adTrust('partner.example')] }).status).toBe('PASS');
  });

  it('fails for an outbound external trust without SID filtering', () => {
    const result = run(adExternalTrustSidFiltering, {
      'ad.trusts': [adTrust('partner.example', { direction: 'Outbound', sidFilteringQuarantined: false })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.id).toBe(`${CONTOSO}->partner.example`);
  });

  it('is NOT_APPLICABLE with only intra-forest, forest and MIT trusts', () => {
    const result = run(adExternalTrustSidFiltering, {
      'ad.trusts': [
        adTrust(CHILD, { intraForest: true, sidFilteringQuarantined: false }),
        adTrust('fabrikam.com', { forestTransitive: true, sidFilteringQuarantined: false }),
        adTrust('REALM.EXAMPLE', { trustType: 'MIT', sidFilteringQuarantined: false }),
      ],
    });
    expect(result.status).toBe('NOT_APPLICABLE');
  });

  it('notes inbound-only external trusts without failing', () => {
    const result = run(adExternalTrustSidFiltering, {
      'ad.trusts': [adTrust('partner.example'), adTrust('vendor.example', { direction: 'Inbound', sidFilteringQuarantined: false })],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('vendor.example');
  });

  it('is NOT_APPLICABLE when there are no trusts at all', () => {
    expect(run(adExternalTrustSidFiltering, { 'ad.trusts': [] }).status).toBe('NOT_APPLICABLE');
  });
});
