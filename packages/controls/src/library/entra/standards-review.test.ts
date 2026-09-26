import { describe, expect, it } from 'vitest';
import { ENTRA_ROLE_TEMPLATES } from '@adminsecops/inventory';
import { caPolicy, roleAssignment, sku } from '../../../test/builders/entra.js';
import { run } from '../../../test/run.js';
import { entraCaMfaAdmins, entraCaMfaAllUsers, entraCaBlockLegacyAuth } from './conditional-access.js';
import { entraCaBlockDeviceCode, entraCaPhishingResistantAdmins, entraCaSignInRisk, entraCaUserRisk } from './conditional-access-advanced.js';
import { entraGlobalAdminMaximum, entraGlobalAdminMinimum, entraPrivilegedCloudOnly } from './privileged-roles.js';

describe('2026-09-21 standards and scope regressions', () => {
  const p2 = { 'entra.subscribedSkus': [sku(['AAD_PREMIUM_P2'])] };
  const defaults = { 'entra.securityDefaults': { isEnabled: false } };
  const everyTime = { signInFrequency: { isEnabled: true, frequencyInterval: 'everyTime' } };
  it('names discovered group-targeted admin MFA policy and lowers confidence', () => {
    const policy = caPolicy({ displayName: 'Privileged people', includeUsers: [] });
    (policy['conditions'] as { users: Record<string, unknown> }).users['includeGroups'] = ['admins-group'];
    const result = run(entraCaMfaAdmins, { ...defaults, 'entra.conditionalAccessPolicies': [policy] });
    expect(result.status).toBe('REVIEW');
    expect(result.confidence).toBe('medium');
    expect(result.statusReason).toContain('Privileged people');
    expect(result.notes.join(' ')).toContain('not a finding');
  });
  it('retains FAIL when no qualifying MFA configuration exists at all', () => {
    expect(run(entraCaMfaAllUsers, { ...defaults, 'entra.conditionalAccessPolicies': [] }).status).toBe('FAIL');
  });
  it('accepts block-all client scope as blocking legacy too', () => {
    expect(run(entraCaBlockLegacyAuth, { ...defaults, 'entra.conditionalAccessPolicies': [caPolicy({ builtInControls: ['block'], clientAppTypes: ['all'] })] }).status).toBe('PASS');
  });
  it('reviews phishing-resistant explicit-user scope without assuming missing protection', () => {
    expect(run(entraCaPhishingResistantAdmins, { 'entra.conditionalAccessPolicies': [caPolicy({ includeUsers: ['admin'], builtInControls: [], authenticationStrengthId: '00000000-0000-0000-0000-000000000004' })] }).status).toBe('REVIEW');
  });
  it('recognizes current risk remediation with strength and a fresh challenge', () => {
    const policy = { ...caPolicy({ userRiskLevels: ['high'], operator: 'AND', builtInControls: ['riskRemediation'], authenticationStrengthId: '00000000-0000-0000-0000-000000000002' }), sessionControls: everyTime };
    expect(run(entraCaUserRisk, { ...p2, 'entra.conditionalAccessPolicies': [policy] }).status).toBe('PASS');
    expect(run(entraCaUserRisk, { ...p2, 'entra.conditionalAccessPolicies': [{ ...policy, sessionControls: null }] }).status).toBe('REVIEW');
  });
  it('reviews unknown risk grants and unproven fresh sign-in challenges', () => {
    expect(run(entraCaUserRisk, { ...p2, 'entra.conditionalAccessPolicies': [caPolicy({ userRiskLevels: ['high'], builtInControls: ['unknownFutureValue'] })] }).status).toBe('REVIEW');
    expect(run(entraCaSignInRisk, { ...p2, 'entra.conditionalAccessPolicies': [caPolicy({ signInRiskLevels: ['high'] })] }).status).toBe('REVIEW');
  });
  it('accepts unconditional MFA with fresh challenge as covering high risk too', () => {
    expect(run(entraCaSignInRisk, { ...p2, 'entra.conditionalAccessPolicies': [{ ...caPolicy(), sessionControls: everyTime }] }).status).toBe('PASS');
  });
  it('does not recommend a duplicate flow policy when security defaults might cover it', () => {
    expect(run(entraCaBlockDeviceCode, { 'entra.securityDefaults': { isEnabled: true } }).status).toBe('REVIEW');
  });
  it('does not certify human administrator counts from unexpanded groups', () => {
    const group = roleAssignment(ENTRA_ROLE_TEMPLATES.globalAdministrator, { principalType: 'group' });
    const data = { 'entra.roleAssignments': [group, roleAssignment(ENTRA_ROLE_TEMPLATES.globalAdministrator)], 'entra.roleEligibilitySchedules': [] };
    expect(run(entraGlobalAdminMaximum, data).status).toBe('REVIEW');
    expect(run(entraGlobalAdminMinimum, data).status).toBe('REVIEW');
    expect(run(entraPrivilegedCloudOnly, data).status).toBe('REVIEW');
  });
});
