import { describe, expect, it } from 'vitest';
import { ENTRA_ROLE_TEMPLATES, MFA_ADMIN_ROLE_TEMPLATE_IDS } from '@adminsecops/inventory';
import { caPolicy, roleAssignment } from '../../../test/builders/entra.js';
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

  it('requires review for unverified emergency account exclusions', () => {
    const result = run(entraCaMfaAllUsers, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ excludeUsers: ['a', 'b'] })],
    });
    expect(result.status).toBe('REVIEW');
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

  it('reviews unresolved individual-user targeting', () => {
    const result = run(entraCaMfaAllUsers, {
      'entra.securityDefaults': sdOff,
      'entra.conditionalAccessPolicies': [caPolicy({ includeUsers: ['someone'] }), caPolicy({ builtInControls: ['compliantDevice'] })],
    });
    expect(result.status).toBe('REVIEW');
  });

  it('reviews unlicensed CA without claiming no other MFA mechanism exists', () => {
    const result = run(
      entraCaMfaAllUsers,
      { 'entra.securityDefaults': sdOff },
      { unavailable: { 'entra.conditionalAccessPolicies': 'NotApplicable' } },
    );
    expect(result.status).toBe('REVIEW');
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
    expect(result.status).toBe('REVIEW');
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


describe('combined MFA policy exclusions', () => {
  const a = 'aaaaaaaa-0000-4000-8000-000000000001';
  const b = 'bbbbbbbb-0000-4000-8000-000000000002';
  it('uses complete collected role-group exclusions, but does not trust incomplete membership', () => {
    const group = 'cccccccc-0000-4000-8000-000000000003';
    const assignment = { ...roleAssignment(ENTRA_ROLE_TEMPLATES.globalAdministrator, { id: group, principalType: 'group' }), groupMembersComplete: true, groupMembers: [{ id: a, principalType: 'user', accountEnabled: true }] };
    const evidence = { 'entra.securityDefaults': sdOff, 'entra.conditionalAccessPolicies': [caPolicy({ excludeGroups: [group] }), caPolicy({ excludeUsers: [b] })], 'entra.roleAssignments': [assignment] };
    expect(run(entraCaMfaAdmins, evidence).status).toBe('PASS');
    expect(run(entraCaMfaAdmins, { ...evidence, 'entra.roleAssignments': [{ ...assignment, groupMembersComplete: false }] }).status).toBe('REVIEW');
  });
  it.each([entraCaMfaAllUsers, entraCaMfaAdmins])('recognises complementary policies but not a common exclusion: $id', (control) => {
    const assessPolicies = (policies: ReturnType<typeof caPolicy>[]) => run(control, { 'entra.securityDefaults': sdOff, 'entra.conditionalAccessPolicies': policies });
    expect(assessPolicies([caPolicy({ excludeUsers: [a] }), caPolicy({ excludeUsers: [b] })]).status).toBe('PASS');
    expect(assessPolicies([caPolicy({ excludeUsers: [a] }), caPolicy({ excludeUsers: [a, b] })]).status).toBe('REVIEW');
    expect(assessPolicies([caPolicy({ excludeUsers: [a] }), caPolicy({ excludeUsers: [b], state: 'enabledForReportingButNotEnforced' })]).status).toBe('REVIEW');
    expect(assessPolicies([caPolicy({ excludeGroups: [a] }), caPolicy({ excludeGroups: [b] })]).status).toBe('REVIEW');
  });
});

describe('Conditional Access coverage regressions', () => {
  it.each([entraCaMfaAllUsers, entraCaMfaAdmins])('reviews exclusions without rejecting emergency access outright: $id', (control) => {
    expect(run(control, { 'entra.securityDefaults': sdOff, 'entra.conditionalAccessPolicies': [caPolicy({ excludeGroups: ['emergency'] })] }).status).toBe('REVIEW');
    expect(run(control, { 'entra.securityDefaults': sdOff, 'entra.conditionalAccessPolicies': [caPolicy({ excludeGroups: ['emergency'] }), caPolicy()] }).status).toBe('PASS');
  });
  it('does not treat a narrowed legacy block as tenant-wide enforcement', () => {
    expect(run(entraCaBlockLegacyAuth, { 'entra.securityDefaults': sdOff, 'entra.conditionalAccessPolicies': [caPolicy({ builtInControls: ['block'], clientAppTypes: ['exchangeActiveSync', 'other'], excludePlatforms: ['iOS'] })] }).status).toBe('REVIEW');
  });
});
