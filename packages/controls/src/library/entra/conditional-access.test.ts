import { describe, expect, it } from 'vitest';
import { ENTRA_ROLE_TEMPLATES, MFA_ADMIN_ROLE_TEMPLATE_IDS } from '@adminsecops/inventory';
import { caPolicy } from '../../../test/builders/entra.js';
import { run } from '../../../test/run.js';
import { entraCaBlockLegacyAuth, entraCaMfaAdmins, entraCaMfaAllUsers } from './conditional-access.js';

const sdOff = { isEnabled: false };
const sdOn = { isEnabled: true };

describe('ENTRA-CA-001 MFA for all users', () => {
  it('passes when security defaults are enabled', () => {
    const result = run(entraCaMfaAllUsers, { 'entra.securityDefaults': sdOn });
    expect(result.status).toBe('PASS');
  });

  it('passes with an enabled all-users MFA policy', () => {
    const result = run(entraCaMfaAllUsers, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ displayName: 'Require MFA all users' })],
    });
    expect(result.status).toBe('PASS');
    expect(result.statusReason).toContain('Require MFA all users');
  });

  it('passes with an authentication strength grant', () => {
    const result = run(entraCaMfaAllUsers, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ builtInControls: [], authenticationStrengthId: '00000000-0000-0000-0000-000000000002' })],
    });
    expect(result.status).toBe('PASS');
  });

  it('notes exclusions on a passing policy', () => {
    const result = run(entraCaMfaAllUsers, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ excludeUsers: ['a', 'b'] })],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('excludes 2 users');
  });

  it('requires review when the only policy is report-only', () => {
    const result = run(entraCaMfaAllUsers, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ state: 'enabledForReportingButNotEnforced' })],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjectCount).toBe(1);
  });

  it('requires review when MFA is only an OR alternative to a compliant device', () => {
    const result = run(entraCaMfaAllUsers, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ operator: 'OR', builtInControls: ['mfa', 'compliantDevice'] })],
    });
    expect(result.status).toBe('REVIEW');
  });

  it('treats MFA AND compliant device as required MFA', () => {
    const result = run(entraCaMfaAllUsers, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ operator: 'AND', builtInControls: ['mfa', 'compliantDevice'] })],
    });
    expect(result.status).toBe('PASS');
  });

  it('requires review when trusted locations are excluded', () => {
    const result = run(entraCaMfaAllUsers, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ excludeLocations: ['AllTrusted'] })],
    });
    expect(result.status).toBe('REVIEW');
  });

  it('fails when no policy requires MFA', () => {
    const result = run(entraCaMfaAllUsers, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ includeUsers: ['someone'] }), caPolicy({ builtInControls: ['compliantDevice'] })],
    });
    expect(result.status).toBe('FAIL');
  });

  it('fails when security defaults are off and Conditional Access is not licensed', () => {
    const result = run(
      entraCaMfaAllUsers,
      { 'entra.securityDefaults': sdOff },
      { unavailable: { 'entra.conditionalAccessPolicies': 'NotApplicable' } },
    );
    expect(result.status).toBe('FAIL');
  });

  it('is NOT_ASSESSED when security defaults are off and CA policies were not collected', () => {
    const result = run(
      entraCaMfaAllUsers,
      { 'entra.securityDefaults': sdOff },
      { unavailable: { 'entra.conditionalAccessPolicies': 'Unauthorized' } },
    );
    expect(result.status).toBe('NOT_ASSESSED');
  });

  it('is NOT_ASSESSED without security defaults evidence', () => {
    expect(run(entraCaMfaAllUsers, {}).status).toBe('NOT_ASSESSED');
  });

  it('downgrades PASS to REVIEW when CA policies were partially collected', () => {
    const result = run(
      entraCaMfaAllUsers,
      { 'entra.securityDefaults': sdOff, 'entra.conditionalAccessPolicies': [caPolicy()] },
      { partial: ['entra.conditionalAccessPolicies'] },
    );
    expect(result.status).toBe('REVIEW');
  });
});

describe('ENTRA-CA-002 MFA for administrators', () => {
  it('passes with security defaults', () => {
    expect(run(entraCaMfaAdmins, { 'entra.securityDefaults': sdOn }).status).toBe('PASS');
  });

  it('passes when a role-based policy covers all admin roles', () => {
    const result = run(entraCaMfaAdmins, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ includeUsers: [], includeRoles: [...MFA_ADMIN_ROLE_TEMPLATE_IDS] })],
    });
    expect(result.status).toBe('PASS');
  });

  it('passes when an all-users MFA policy exists', () => {
    const result = run(entraCaMfaAdmins, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy()],
    });
    expect(result.status).toBe('PASS');
  });

  it('fails and lists roles that are missing from the policy', () => {
    const result = run(entraCaMfaAdmins, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ includeUsers: [], includeRoles: [ENTRA_ROLE_TEMPLATES.globalAdministrator] })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(MFA_ADMIN_ROLE_TEMPLATE_IDS.length - 1);
    expect(result.affectedObjects.map((o) => o.id)).not.toContain(ENTRA_ROLE_TEMPLATES.globalAdministrator);
  });

  it('fails when a role is explicitly excluded', () => {
    const result = run(entraCaMfaAdmins, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ excludeRoles: [ENTRA_ROLE_TEMPLATES.globalAdministrator] })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.name)).toEqual(['Global Administrator']);
  });

  it('does not count report-only policies', () => {
    const result = run(entraCaMfaAdmins, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ state: 'enabledForReportingButNotEnforced' })],
    });
    expect(result.status).toBe('FAIL');
  });
});

describe('ENTRA-CA-003 legacy authentication blocked', () => {
  const legacyBlock = (state: 'enabled' | 'enabledForReportingButNotEnforced' = 'enabled') =>
    caPolicy({ state, clientAppTypes: ['exchangeActiveSync', 'other'], builtInControls: ['block'], displayName: 'Block legacy auth' });

  it('passes with security defaults', () => {
    expect(run(entraCaBlockLegacyAuth, { 'entra.securityDefaults': sdOn }).status).toBe('PASS');
  });

  it('passes with an enabled blocking policy', () => {
    const result = run(entraCaBlockLegacyAuth, { 'entra.securityDefaults': sdOff, 'entra.conditionalAccessPolicies': [legacyBlock()] });
    expect(result.status).toBe('PASS');
  });

  it('requires review when the blocking policy is report-only', () => {
    const result = run(entraCaBlockLegacyAuth, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [legacyBlock('enabledForReportingButNotEnforced')],
    });
    expect(result.status).toBe('REVIEW');
  });

  it('fails when only one legacy client type is blocked', () => {
    const result = run(entraCaBlockLegacyAuth, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ clientAppTypes: ['other'], builtInControls: ['block'] })],
    });
    expect(result.status).toBe('FAIL');
  });

  it('fails when no policy blocks legacy authentication', () => {
    const result = run(entraCaBlockLegacyAuth, { 'entra.securityDefaults': sdOff, 'entra.conditionalAccessPolicies': [] });
    expect(result.status).toBe('FAIL');
  });
});
