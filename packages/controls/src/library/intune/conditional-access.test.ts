import { describe, expect, it } from 'vitest';
import { caPolicy } from '../../../test/builders/entra.js';
import { deviceOverview, intuneSettings } from '../../../test/builders/intune.js';
import { run } from '../../../test/run.js';
import { intuneCaRequireCompliantDevice } from './conditional-access.js';

const enrolled = deviceOverview({ windows: 20, ios: 5 });
const compliant = (overrides: Parameters<typeof caPolicy>[0] = {}) =>
  caPolicy({
    displayName: 'Require compliant device',
    builtInControls: ['compliantDevice'],
    ...overrides,
  });

describe('INTUNE-CA-001 Conditional Access requires a compliant device', () => {
  it('does not pass an Office 365 policy with excluded resources', () => {
    const result = run(intuneCaRequireCompliantDevice, {
      'intune.deviceOverview': enrolled,
      'entra.conditionalAccessPolicies': [compliant({ includeApplications: ['Office365'], excludeApplications: ['excluded-resource'] })],
    });
    expect(result.status).toBe('REVIEW');
  });
  it('passes with an enabled all-users compliant-device policy', () => {
    const result = run(intuneCaRequireCompliantDevice, {
      'intune.deviceOverview': enrolled,
      'entra.conditionalAccessPolicies': [compliant()],
    });
    expect(result.status).toBe('PASS');
    expect(result.statusReason).toContain('Require compliant device');
  });

  it('passes with compliant OR hybrid joined device targeting Office 365', () => {
    const result = run(intuneCaRequireCompliantDevice, {
      'intune.deviceOverview': enrolled,
      'entra.conditionalAccessPolicies': [
        compliant({
          builtInControls: ['compliantDevice', 'domainJoinedDevice'],
          includeApplications: ['Office365'],
        }),
      ],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('Hybrid joined status does not prove Intune compliance');
  });

  it('passes with MFA AND compliant device and notes exclusions', () => {
    const result = run(intuneCaRequireCompliantDevice, {
      'intune.deviceOverview': enrolled,
      'entra.conditionalAccessPolicies': [
        compliant({
          operator: 'AND',
          builtInControls: ['mfa', 'compliantDevice'],
          excludeUsers: ['breakglass'],
        }),
      ],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('excludes 1 user');
  });

  it('requires review when MFA is an alternative to a compliant device', () => {
    const result = run(intuneCaRequireCompliantDevice, {
      'intune.deviceOverview': enrolled,
      'entra.conditionalAccessPolicies': [
        compliant({ builtInControls: ['compliantDevice', 'domainJoinedDevice', 'mfa'] }),
      ],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.detail).toContain('device requirement=alternative');
  });

  it('requires review when the policy is report-only or scoped', () => {
    const result = run(intuneCaRequireCompliantDevice, {
      'intune.deviceOverview': enrolled,
      'entra.conditionalAccessPolicies': [
        compliant({ state: 'enabledForReportingButNotEnforced' }),
        compliant({ includeUsers: ['someone'] }),
        compliant({ includeApplications: ['00000003-0000-0ff1-ce00-000000000000'] }),
        compliant({ excludeLocations: ['AllTrusted'] }),
      ],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjectCount).toBe(4);
  });

  it('requires review (not FAIL) when no policy uses device compliance, and explains why', () => {
    const result = run(intuneCaRequireCompliantDevice, {
      'intune.deviceOverview': enrolled,
      'entra.conditionalAccessPolicies': [caPolicy()],
      'intune.settings': intuneSettings({ secureByDefault: false }),
    });
    expect(result.status).toBe('REVIEW');
    expect(result.statusReason).toContain('design decision');
    expect(result.notes.join(' ')).toContain('INTUNE-CMP-001');
  });

  it('requires review when Conditional Access is not licensed', () => {
    const result = run(
      intuneCaRequireCompliantDevice,
      { 'intune.deviceOverview': enrolled },
      { unavailable: { 'entra.conditionalAccessPolicies': 'NotApplicable' } },
    );
    expect(result.status).toBe('REVIEW');
    expect(result.statusReason).toContain('P1');
  });

  it('is NOT_ASSESSED when Conditional Access policies could not be read', () => {
    const result = run(
      intuneCaRequireCompliantDevice,
      { 'intune.deviceOverview': enrolled },
      { unavailable: { 'entra.conditionalAccessPolicies': 'Unauthorized' } },
    );
    expect(result.status).toBe('NOT_ASSESSED');
  });

  it('is NOT_ASSESSED when Conditional Access policies were not collected at all', () => {
    expect(run(intuneCaRequireCompliantDevice, { 'intune.deviceOverview': enrolled }).status).toBe(
      'NOT_ASSESSED',
    );
  });

  it('is NOT_APPLICABLE when no devices are enrolled', () => {
    const result = run(intuneCaRequireCompliantDevice, {
      'intune.deviceOverview': deviceOverview(),
      'entra.conditionalAccessPolicies': [],
    });
    expect(result.status).toBe('NOT_APPLICABLE');
  });

  it('downgrades PASS to REVIEW when CA policies were partially collected', () => {
    const result = run(
      intuneCaRequireCompliantDevice,
      { 'intune.deviceOverview': enrolled, 'entra.conditionalAccessPolicies': [compliant()] },
      { partial: ['entra.conditionalAccessPolicies'] },
    );
    expect(result.status).toBe('REVIEW');
  });
});
