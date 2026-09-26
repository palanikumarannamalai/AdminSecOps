import { describe, expect, it } from 'vitest';
import {
  compliancePolicy,
  deviceOverview,
  EXCLUDE_GROUP,
  GROUP,
  ALL_USERS,
  intuneSettings,
} from '../../../test/builders/intune.js';
import { run } from '../../../test/run.js';
import {
  intuneNoPolicyNoncompliant,
  intunePlatformCoverage,
  intuneWindowsBitLocker,
} from './compliance.js';

describe('INTUNE-CMP-001 devices without a compliance policy are not compliant', () => {
  it('passes when secureByDefault is true', () => {
    expect(run(intuneNoPolicyNoncompliant, { 'intune.settings': intuneSettings() }).status).toBe(
      'PASS',
    );
  });

  it('fails with the default (Compliant)', () => {
    const result = run(intuneNoPolicyNoncompliant, {
      'intune.settings': intuneSettings({ secureByDefault: false }),
    });
    expect(result.status).toBe('FAIL');
  });

  it('is NOT_APPLICABLE when Intune is not available', () => {
    expect(
      run(intuneNoPolicyNoncompliant, {}, { unavailable: { 'intune.settings': 'NotApplicable' } })
        .status,
    ).toBe('NOT_APPLICABLE');
  });
});

describe('INTUNE-CMP-002 compliance policy per platform', () => {
  it('does not pass enrolled devices with no supported platform counts', () => {
    expect(run(intunePlatformCoverage, { 'intune.deviceOverview': deviceOverview({ linux: 2 }), 'intune.compliancePolicies': [] }).status).toBe('NOT_ASSESSED');
  });
  it('does not count an unknown assignment target as an include assignment', () => {
    expect(run(intunePlatformCoverage, { 'intune.deviceOverview': deviceOverview({ windows: 2 }), 'intune.compliancePolicies': [compliancePolicy({ targets: ['#microsoft.graph.futureAssignmentTarget'] })] }).status).toBe('FAIL');
  });
  it('passes when every platform in use has an assigned policy (with prefixed and unprefixed OData types)', () => {
    const result = run(intunePlatformCoverage, {
      'intune.deviceOverview': deviceOverview({ windows: 40, ios: 10, android: 5 }),
      'intune.compliancePolicies': [
        compliancePolicy({ type: 'windows10CompliancePolicy' }),
        compliancePolicy({ type: '#microsoft.graph.iosCompliancePolicy', targets: [ALL_USERS] }),
        compliancePolicy({ type: 'androidWorkProfileCompliancePolicy' }),
      ],
    });
    expect(result.status).toBe('PASS');
  });

  it('fails and lists platforms with devices but no assigned policy', () => {
    const result = run(intunePlatformCoverage, {
      'intune.deviceOverview': deviceOverview({ windows: 40, macOS: 3, android: 2 }),
      'intune.compliancePolicies': [
        compliancePolicy({ type: 'windows10CompliancePolicy' }),
        compliancePolicy({ type: 'macOSCompliancePolicy', targets: [] }),
        compliancePolicy({ type: 'androidDeviceOwnerCompliancePolicy', targets: [EXCLUDE_GROUP] }),
      ],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.name)).toEqual(['macOS', 'Android']);
    expect(result.affectedObjects[0]?.detail).toContain('3 enrolled devices');
    expect(result.notes.join(' ')).toContain('have no assignments');
  });

  it('ignores platforms without devices', () => {
    const result = run(intunePlatformCoverage, {
      'intune.deviceOverview': deviceOverview({ windows: 1 }),
      'intune.compliancePolicies': [compliancePolicy({ type: 'windows10CompliancePolicy' })],
    });
    expect(result.status).toBe('PASS');
  });

  it('fails when devices exist but there are no policies at all', () => {
    const result = run(intunePlatformCoverage, {
      'intune.deviceOverview': deviceOverview({ ios: 2 }),
      'intune.compliancePolicies': [],
    });
    expect(result.status).toBe('FAIL');
  });

  it('notes group-only coverage and enrolled Linux devices', () => {
    const result = run(intunePlatformCoverage, {
      'intune.deviceOverview': deviceOverview({ windows: 5, linux: 2 }),
      'intune.compliancePolicies': [
        compliancePolicy({ type: 'windows10CompliancePolicy', targets: [GROUP] }),
      ],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('group-assigned');
    expect(result.notes.join(' ')).toContain('Linux');
  });

  it('is NOT_APPLICABLE when no devices are enrolled', () => {
    const result = run(intunePlatformCoverage, {
      'intune.deviceOverview': deviceOverview(),
      'intune.compliancePolicies': [],
    });
    expect(result.status).toBe('NOT_APPLICABLE');
  });

  it('downgrades PASS to REVIEW when policies were partially collected', () => {
    const result = run(
      intunePlatformCoverage,
      {
        'intune.deviceOverview': deviceOverview({ windows: 1 }),
        'intune.compliancePolicies': [compliancePolicy()],
      },
      { partial: ['intune.compliancePolicies'] },
    );
    expect(result.status).toBe('REVIEW');
  });
});

describe('INTUNE-CMP-003 Windows compliance requires BitLocker', () => {
  const overview = deviceOverview({ windows: 10 });

  it('passes when an assigned Windows policy requires BitLocker', () => {
    const result = run(intuneWindowsBitLocker, {
      'intune.deviceOverview': overview,
      'intune.compliancePolicies': [
        compliancePolicy({ displayName: 'Win baseline', settings: { bitLockerEnabled: true } }),
      ],
    });
    expect(result.status).toBe('PASS');
    expect(result.statusReason).toContain('Win baseline');
  });

  it('notes when the BitLocker policy is only group-assigned', () => {
    const result = run(intuneWindowsBitLocker, {
      'intune.compliancePolicies': [
        compliancePolicy({ targets: [GROUP], settings: { bitLockerEnabled: true } }),
      ],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('specific groups');
  });

  it('requires review when only storage encryption is required', () => {
    const result = run(intuneWindowsBitLocker, {
      'intune.deviceOverview': overview,
      'intune.compliancePolicies': [
        compliancePolicy({
          displayName: 'Encryption',
          settings: { storageRequireEncryption: true },
        }),
      ],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.name).toBe('Encryption');
  });

  it('fails when the BitLocker policy is not assigned', () => {
    const result = run(intuneWindowsBitLocker, {
      'intune.deviceOverview': overview,
      'intune.compliancePolicies': [
        compliancePolicy({
          displayName: 'Unassigned',
          targets: [],
          settings: { bitLockerEnabled: true },
        }),
      ],
    });
    expect(result.status).toBe('FAIL');
    expect(result.statusReason).toContain('No Windows 10/11 compliance policy is assigned');
  });

  it('fails when assigned Windows policies do not require BitLocker', () => {
    const result = run(intuneWindowsBitLocker, {
      'intune.deviceOverview': overview,
      'intune.compliancePolicies': [
        compliancePolicy({ displayName: 'Win', settings: { bitLockerEnabled: false } }),
        compliancePolicy({
          type: 'iosCompliancePolicy',
          settings: { storageRequireEncryption: true },
        }),
      ],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.name)).toEqual(['Win']);
  });

  it('is NOT_APPLICABLE when no Windows devices are enrolled', () => {
    const result = run(intuneWindowsBitLocker, {
      'intune.deviceOverview': deviceOverview({ ios: 3 }),
      'intune.compliancePolicies': [],
    });
    expect(result.status).toBe('NOT_APPLICABLE');
  });

  it('evaluates when the optional device overview is unavailable', () => {
    const result = run(
      intuneWindowsBitLocker,
      { 'intune.compliancePolicies': [] },
      { unavailable: { 'intune.deviceOverview': 'Failed' } },
    );
    expect(result.status).toBe('FAIL');
  });
});
