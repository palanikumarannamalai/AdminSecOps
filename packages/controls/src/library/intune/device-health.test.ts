import { describe, expect, it } from 'vitest';
import { run } from '../../../test/run.js';
import { compliancePolicy, deviceOverview, GROUP, ALL_DEVICES, EXCLUDE_GROUP } from '../../../test/builders/intune.js';
import { intuneWindowsSecureBoot, intuneWindowsCodeIntegrity } from './device-health.js';

for (const [id, control, field] of [['INTUNE-CMP-004', intuneWindowsSecureBoot, 'secureBootEnabled'], ['INTUNE-CMP-005', intuneWindowsCodeIntegrity, 'codeIntegrityEnabled']] as const) {
  describe(id, () => {
    const assess = (setting: boolean | null, targets = [ALL_DEVICES], windows = 2) => run(control, {
      'intune.deviceOverview': deviceOverview({ windows }),
      'intune.compliancePolicies': [compliancePolicy({ targets, settings: { [field]: setting } })],
    });
    it('passes a broad configured requirement and fails an explicit false value', () => {
      expect(assess(true).status).toBe('PASS');
      expect(assess(false).status).toBe('FAIL');
    });
    it('does not turn an omitted property into a failure or pass', () => { expect(assess(null).status).toBe('NOT_ASSESSED'); });
    it('requires review for group-only assignments and exclusions', () => {
      expect(assess(true, [GROUP]).status).toBe('REVIEW');
      expect(assess(true, [ALL_DEVICES, EXCLUDE_GROUP]).status).toBe('REVIEW');
    });
    it('does not apply without enrolled Windows devices', () => { expect(assess(false, [ALL_DEVICES], 0).status).toBe('NOT_APPLICABLE'); });
  });
}
