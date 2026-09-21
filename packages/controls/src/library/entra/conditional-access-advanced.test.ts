import { describe, expect, it } from 'vitest';
import { ENTRA_ROLE_TEMPLATES, HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS } from '@adminsecops/inventory';
import { caPolicy, sku } from '../../../test/builders/entra.js';
import { run } from '../../../test/run.js';
import { entraCaBlockDeviceCode, entraCaPhishingResistantAdmins, entraCaSignInRisk, entraCaUserRisk } from './conditional-access-advanced.js';

const PHISH = '00000000-0000-0000-0000-000000000004';
const allAdminRoles = [...HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS];

describe('ENTRA-CA-004 phishing-resistant MFA for privileged roles', () => {
  it('passes when all highly privileged roles require the phishing-resistant strength', () => {
    const result = run(entraCaPhishingResistantAdmins, {
      'entra.conditionalAccessPolicies': [caPolicy({ includeUsers: [], includeRoles: allAdminRoles, builtInControls: [], authenticationStrengthId: PHISH })],
    });
    expect(result.status).toBe('PASS');
  });

  it('fails and lists uncovered roles when only MFA is required', () => {
    const result = run(entraCaPhishingResistantAdmins, {
      'entra.conditionalAccessPolicies': [caPolicy({ includeUsers: [], includeRoles: allAdminRoles })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(allAdminRoles.length);
  });

  it('requires review when roles rely on a custom authentication strength', () => {
    const result = run(entraCaPhishingResistantAdmins, {
      'entra.conditionalAccessPolicies': [
        caPolicy({ includeUsers: [], includeRoles: allAdminRoles, builtInControls: [], authenticationStrengthId: '11111111-2222-4333-8444-555555555555' }),
      ],
    });
    expect(result.status).toBe('REVIEW');
  });

  it('ignores report-only and location-narrowed policies', () => {
    const result = run(entraCaPhishingResistantAdmins, {
      'entra.conditionalAccessPolicies': [
        caPolicy({ state: 'enabledForReportingButNotEnforced', authenticationStrengthId: PHISH }),
        caPolicy({ authenticationStrengthId: PHISH, excludeLocations: ['AllTrusted'] }),
      ],
    });
    expect(result.status).toBe('FAIL');
  });

  it('fails only for the excluded role', () => {
    const result = run(entraCaPhishingResistantAdmins, {
      'entra.conditionalAccessPolicies': [caPolicy({ builtInControls: [], authenticationStrengthId: PHISH, excludeRoles: [ENTRA_ROLE_TEMPLATES.exchangeAdministrator] })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.name)).toEqual(['Exchange Administrator']);
  });

  it('is NOT_APPLICABLE when Conditional Access is not licensed', () => {
    const result = run(entraCaPhishingResistantAdmins, {}, { unavailable: { 'entra.conditionalAccessPolicies': 'NotApplicable' } });
    expect(result.status).toBe('NOT_APPLICABLE');
  });
});

describe('ENTRA-CA-005 device code flow blocked', () => {
  const block = (overrides = {}) => caPolicy({ transferMethods: 'deviceCodeFlow,authenticationTransfer', builtInControls: ['block'], ...overrides });

  it('passes with an enabled tenant-wide block', () => {
    expect(run(entraCaBlockDeviceCode, { 'entra.securityDefaults': { isEnabled: false }, 'entra.conditionalAccessPolicies': [block()] }).status).toBe('PASS');
  });

  it('requires review for a report-only or partial block', () => {
    expect(run(entraCaBlockDeviceCode, { 'entra.securityDefaults': { isEnabled: false }, 'entra.conditionalAccessPolicies': [block({ state: 'enabledForReportingButNotEnforced' })] }).status).toBe('REVIEW');
    expect(run(entraCaBlockDeviceCode, { 'entra.securityDefaults': { isEnabled: false }, 'entra.conditionalAccessPolicies': [block({ includeUsers: ['someone'] })] }).status).toBe('REVIEW');
  });

  it('fails when only authentication transfer is blocked', () => {
    expect(
      run(entraCaBlockDeviceCode, { 'entra.securityDefaults': { isEnabled: false }, 'entra.conditionalAccessPolicies': [caPolicy({ transferMethods: 'authenticationTransfer', builtInControls: ['block'] })] }).status,
    ).toBe('FAIL');
  });

  it('fails with no policies', () => {
    expect(run(entraCaBlockDeviceCode, { 'entra.securityDefaults': { isEnabled: false }, 'entra.conditionalAccessPolicies': [] }).status).toBe('FAIL');
  });
});

describe('ENTRA-CA-006 / ENTRA-CA-007 risk-based policies', () => {
  const p2 = [sku(['AAD_PREMIUM', 'AAD_PREMIUM_P2'])];
  const p1 = [sku(['AAD_PREMIUM'])];

  it('is NOT_APPLICABLE without Entra ID P2', () => {
    const result = run(entraCaSignInRisk, { 'entra.conditionalAccessPolicies': [], 'entra.subscribedSkus': p1 });
    expect(result.status).toBe('NOT_APPLICABLE');
    expect(result.statusReason).toContain('P2');
  });

  it('does not count a suspended P2 licence', () => {
    const suspended = [sku(['AAD_PREMIUM_P2'], { capabilityStatus: 'Suspended' })];
    expect(run(entraCaUserRisk, { 'entra.conditionalAccessPolicies': [], 'entra.subscribedSkus': suspended }).status).toBe('NOT_APPLICABLE');
  });

  it('ENTRA-CA-006 passes with an enabled high sign-in risk MFA policy', () => {
    const result = run(entraCaSignInRisk, {
      'entra.conditionalAccessPolicies': [{ ...caPolicy({ signInRiskLevels: ['high', 'medium'] }), sessionControls: { signInFrequency: { isEnabled: true, frequencyInterval: 'everyTime' } } }],
      'entra.subscribedSkus': p2,
    });
    expect(result.status).toBe('PASS');
  });

  it('ENTRA-CA-006 fails when only medium risk is covered', () => {
    const result = run(entraCaSignInRisk, {
      'entra.conditionalAccessPolicies': [caPolicy({ signInRiskLevels: ['medium'] })],
      'entra.subscribedSkus': p2,
    });
    expect(result.status).toBe('FAIL');
  });

  it('ENTRA-CA-007 passes with MFA and password change for high user risk', () => {
    const result = run(entraCaUserRisk, {
      'entra.conditionalAccessPolicies': [caPolicy({ userRiskLevels: ['high'], operator: 'AND', builtInControls: ['mfa', 'passwordChange'] })],
      'entra.subscribedSkus': p2,
    });
    expect(result.status).toBe('PASS');
  });

  it('ENTRA-CA-007 requires review for report-only and fails for MFA-only', () => {
    const reportOnly = run(entraCaUserRisk, {
      'entra.conditionalAccessPolicies': [caPolicy({ state: 'enabledForReportingButNotEnforced', userRiskLevels: ['high'], builtInControls: ['block'] })],
      'entra.subscribedSkus': p2,
    });
    expect(reportOnly.status).toBe('REVIEW');
    const mfaOnly = run(entraCaUserRisk, {
      'entra.conditionalAccessPolicies': [caPolicy({ userRiskLevels: ['high'], builtInControls: ['mfa'] })],
      'entra.subscribedSkus': p2,
    });
    expect(mfaOnly.status).toBe('FAIL');
  });

  it('is NOT_ASSESSED when licences were not collected', () => {
    expect(run(entraCaSignInRisk, { 'entra.conditionalAccessPolicies': [] }).status).toBe('NOT_ASSESSED');
  });
});


describe('Conditional Access advanced coverage regressions', () => {
  it.each([
    { builtInControls: ['compliantDevice'], operator: 'OR' as const },
    { builtInControls: ['mfa'], operator: 'OR' as const },
    { builtInControls: [], clientAppTypes: ['browser'] },
    { builtInControls: [], signInRiskLevels: ['high'] },
    { builtInControls: [], excludeApplications: ['some-app'] },
  ])('rejects phishing-resistant coverage with alternate grants or narrowed scope: %j', (input) => {
    expect(run(entraCaPhishingResistantAdmins, { 'entra.conditionalAccessPolicies': [caPolicy({ authenticationStrengthId: PHISH, ...input })] }).status).toBe('FAIL');
  });
  it('reviews identity exclusions and accepts independent complete coverage', () => {
    const excluded = caPolicy({ authenticationStrengthId: PHISH, builtInControls: [], excludeUsers: ['emergency'] });
    expect(run(entraCaPhishingResistantAdmins, { 'entra.conditionalAccessPolicies': [excluded] }).status).toBe('REVIEW');
    expect(run(entraCaPhishingResistantAdmins, { 'entra.conditionalAccessPolicies': [excluded, caPolicy({ authenticationStrengthId: PHISH, builtInControls: [] })] }).status).toBe('PASS');
  });
  it('accepts an AND strength grant but not an OR fallback', () => {
    expect(run(entraCaPhishingResistantAdmins, { 'entra.conditionalAccessPolicies': [caPolicy({ authenticationStrengthId: PHISH, operator: 'AND', builtInControls: ['compliantDevice'] })] }).status).toBe('PASS');
  });
  it('reviews device flow restrictions beyond the intended flow condition', () => {
    expect(run(entraCaBlockDeviceCode, { 'entra.securityDefaults': { isEnabled: false }, 'entra.conditionalAccessPolicies': [caPolicy({ transferMethods: 'deviceCodeFlow', builtInControls: ['block'], excludePlatforms: ['iOS'] })] }).status).toBe('REVIEW');
  });
  it('reviews a risk policy restricted by the other risk dimension', () => {
    expect(run(entraCaSignInRisk, { 'entra.subscribedSkus': [sku(['AAD_PREMIUM_P2'])], 'entra.conditionalAccessPolicies': [caPolicy({ signInRiskLevels: ['high'], userRiskLevels: ['high'] })] }).status).toBe('REVIEW');
  });
});


describe('ENTRA-CA-007 password change must be mandatory', () => {
  it.each([
    { builtInControls: ['passwordChange', 'compliantDevice'] },
    { builtInControls: ['passwordChange', 'mfa'] },
    { builtInControls: ['passwordChange'], authenticationStrengthId: PHISH },
  ])('rejects OR fallback to another grant: %j', (grants) => {
    expect(run(entraCaUserRisk, {
      'entra.subscribedSkus': [sku(['AAD_PREMIUM_P2'])],
      'entra.conditionalAccessPolicies': [caPolicy({ userRiskLevels: ['high'], operator: 'OR', ...grants })],
    }).status).toBe('FAIL');
  });
});
