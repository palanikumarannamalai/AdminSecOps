import { describe, expect, it } from 'vitest';
import { ConditionalAccessPolicySchema } from '@adminsecops/schemas';
import {
  hasNoNarrowingConditions,
  includesAllApps,
  mfaRequirement,
  MFA_STRENGTH_ID,
} from './conditional-access.js';

function policy(
  conditions = {},
  grantControls: unknown = { operator: 'OR', builtInControls: ['mfa'] },
) {
  return ConditionalAccessPolicySchema.parse({
    id: '11111111-1111-4111-8111-111111111111',
    displayName: 'Test policy',
    state: 'enabled',
    conditions: { applications: { includeApplications: ['All'] }, ...conditions },
    grantControls,
  });
}

describe('Conditional Access scope', () => {
  it('requires no application exclusions for all-app coverage', () => {
    expect(includesAllApps(policy())).toBe(true);
    expect(
      includesAllApps(
        policy({
          applications: { includeApplications: ['All'], excludeApplications: ['excluded-app'] },
        }),
      ),
    ).toBe(false);
  });

  it('accepts unrestricted conditions', () => {
    expect(hasNoNarrowingConditions(policy())).toBe(true);
    expect(hasNoNarrowingConditions(policy({ platforms: { includePlatforms: ['all'] } }))).toBe(
      true,
    );
  });

  it.each([
    { platforms: { includePlatforms: ['all'], excludePlatforms: ['windows'] } },
    { devices: { deviceFilter: { mode: 'exclude', rule: 'device.isCompliant -eq True' } } },
    { devices: { deviceFilter: { mode: 'include', rule: 'device.isCompliant -eq True' } } },
    { devices: { includeDevices: ['Compliant'] } },
    { devices: { excludeDevices: ['Compliant'] } },
    { authenticationFlows: { transferMethods: 'deviceCodeFlow' } },
    { signInRiskLevels: ['high'] },
    { userRiskLevels: ['high'] },
  ])('does not consider a scoped policy universal: %j', (conditions) => {
    expect(hasNoNarrowingConditions(policy(conditions))).toBe(false);
  });
});

describe('Conditional Access authentication strength', () => {
  function strength(
    id: string,
    requirementsSatisfied?: string,
    builtInControls: string[] = [],
    operator = 'OR',
  ) {
    return policy(
      {},
      { operator, builtInControls, authenticationStrength: { id, requirementsSatisfied } },
    );
  }

  it('recognizes the built-in MFA strength when older evidence lacks requirement metadata', () => {
    expect(mfaRequirement(strength(MFA_STRENGTH_ID))).toBe('required');
  });

  it('requires explicit MFA evidence for custom strengths', () => {
    expect(mfaRequirement(strength('custom', 'mfa'))).toBe('required');
    expect(mfaRequirement(strength('custom', 'singleFactorAuthentication'))).toBe('none');
    expect(mfaRequirement(strength('custom'))).toBe('none');
  });

  it('does not ignore a single-factor or unknown strength as an OR alternative', () => {
    expect(mfaRequirement(strength('custom', 'singleFactorAuthentication', ['mfa']))).toBe(
      'alternative',
    );
    expect(mfaRequirement(strength('custom', undefined, ['mfa']))).toBe('alternative');
    expect(mfaRequirement(strength('custom', 'singleFactorAuthentication', ['mfa'], 'AND'))).toBe(
      'required',
    );
  });

  it('keeps an MFA strength OR compliant device as an alternative', () => {
    expect(mfaRequirement(strength('custom', 'mfa', ['compliantDevice']))).toBe('alternative');
  });
});
