import { describe, expect, it } from 'vitest';
import { ENTRA_ROLE_TEMPLATES } from '@adminsecops/inventory';
import { nextGuid, roleAssignment } from '../../../test/builders/entra.js';
import { run } from '../../../test/run.js';
import {
  entraGlobalAdminMaximum,
  entraGlobalAdminMinimum,
  entraPrivilegedCloudOnly,
  entraPrivilegedMfaRegistered,
  entraPrivilegedNoPermanent,
} from './privileged-roles.js';

const GA = ENTRA_ROLE_TEMPLATES.globalAdministrator;
const gas = (n: number) => Array.from({ length: n }, () => roleAssignment(GA));

describe('ENTRA-PRIV-001 / ENTRA-PRIV-002 Global Administrator count', () => {
  it('passes with between two and four Global Administrators', () => {
    expect(run(entraGlobalAdminMaximum, { 'entra.roleAssignments': gas(4) }).status).toBe('PASS');
    expect(run(entraGlobalAdminMinimum, { 'entra.roleAssignments': gas(2) }).status).toBe('PASS');
  });

  it('fails with five or more and lists them', () => {
    const result = run(entraGlobalAdminMaximum, { 'entra.roleAssignments': gas(5) });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(5);
    expect(result.notes.join(' ')).toContain('eligible assignments were not available');
  });

  it('counts distinct principals and includes PIM eligible assignments', () => {
    const shared = roleAssignment(GA, { id: 'aaaaaaaa-0000-4000-8000-000000000001' });
    const eligible = Array.from({ length: 2 }, () => ({ id: nextGuid(), roleDefinitionId: GA, principalId: nextGuid(), directoryScopeId: '/' }));
    const result = run(entraGlobalAdminMaximum, {
      'entra.roleAssignments': [shared, { ...shared, id: nextGuid() }, ...gas(2)],
      'entra.roleEligibilitySchedules': eligible,
    });
    expect(result.observed.facts.find((f) => f.label === 'Global Administrator principals')?.value).toBe(5);
    expect(result.status).toBe('FAIL');
  });

  it('ignores other roles and non-tenant scopes', () => {
    const scoped = { ...roleAssignment(GA), directoryScopeId: '/administrativeUnits/x' };
    const result = run(entraGlobalAdminMaximum, { 'entra.roleAssignments': [...gas(1), scoped, roleAssignment(ENTRA_ROLE_TEMPLATES.userAdministrator)] });
    expect(result.observed.facts[0]?.value).toBe(1);
  });

  it('notes role-assignable groups', () => {
    const result = run(entraGlobalAdminMaximum, { 'entra.roleAssignments': [roleAssignment(GA, { principalType: 'group', displayName: 'GA group' })] });
    expect(result.notes.join(' ')).toContain('GA group');
  });

  it('fails the minimum with a single Global Administrator', () => {
    expect(run(entraGlobalAdminMinimum, { 'entra.roleAssignments': gas(1) }).status).toBe('FAIL');
  });
});

describe('ENTRA-PRIV-003 cloud-only privileged accounts', () => {
  it('fails when a synchronized account holds a highly privileged role', () => {
    const result = run(entraPrivilegedCloudOnly, {
      'entra.roleAssignments': [roleAssignment(GA, { onPremisesSyncEnabled: true, userPrincipalName: 'synced@contoso.example' }), roleAssignment(GA)],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.name).toBe('synced@contoso.example');
  });

  it('passes when only non-privileged roles are synchronized', () => {
    const result = run(entraPrivilegedCloudOnly, {
      'entra.roleAssignments': [roleAssignment(ENTRA_ROLE_TEMPLATES.globalReader, { onPremisesSyncEnabled: true }), roleAssignment(GA, { onPremisesSyncEnabled: false })],
    });
    expect(result.status).toBe('PASS');
  });

  it('requires review when a privileged account synchronization state is unknown', () => {
    const result = run(entraPrivilegedCloudOnly, {
      'entra.roleAssignments': [roleAssignment(GA, { onPremisesSyncEnabled: null })],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjectCount).toBe(1);
  });

  it('preserves failure when synchronized and unknown states coexist', () => {
    const result = run(entraPrivilegedCloudOnly, {
      'entra.roleAssignments': [roleAssignment(GA, { onPremisesSyncEnabled: true }), roleAssignment(GA, { onPremisesSyncEnabled: null })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.notes.join(' ')).toContain('cannot be confirmed');
  });

  it('uses role definitions to resolve custom role names', () => {
    const result = run(entraPrivilegedCloudOnly, {
      'entra.roleAssignments': [roleAssignment(GA, { onPremisesSyncEnabled: true })],
      'entra.roleDefinitions': [{ id: GA, displayName: 'Global Administrator', templateId: GA, isBuiltIn: true }],
    });
    expect(result.affectedObjects[0]?.detail).toContain('Global Administrator');
  });
});

describe('ENTRA-PRIV-004 no permanent privileged assignments', () => {
  const instance = (roleId: string, type: 'Assigned' | 'Activated', end: string | null = null) => ({
    id: nextGuid(),
    roleDefinitionId: roleId,
    principalId: nextGuid(),
    directoryScopeId: '/',
    assignmentType: type,
    memberType: 'Direct',
    startDateTime: '2026-01-01T00:00:00Z',
    endDateTime: end,
  });

  it('passes when only activations and time-bound assignments exist', () => {
    const result = run(entraPrivilegedNoPermanent, {
      'entra.roleAssignmentScheduleInstances': [instance(GA, 'Activated', '2026-09-01T20:00:00Z'), instance(GA, 'Assigned', '2026-12-01T00:00:00Z')],
    });
    expect(result.status).toBe('PASS');
  });

  it('requires review for up to two permanent Global Administrators (emergency access)', () => {
    const result = run(entraPrivilegedNoPermanent, { 'entra.roleAssignmentScheduleInstances': [instance(GA, 'Assigned'), instance(GA, 'Assigned')] });
    expect(result.status).toBe('REVIEW');
  });

  it('fails with permanent assignments of other privileged roles', () => {
    const result = run(entraPrivilegedNoPermanent, {
      'entra.roleAssignmentScheduleInstances': [instance(GA, 'Assigned'), instance(ENTRA_ROLE_TEMPLATES.exchangeAdministrator, 'Assigned')],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(2);
  });

  it('fails with three permanent Global Administrators', () => {
    const result = run(entraPrivilegedNoPermanent, { 'entra.roleAssignmentScheduleInstances': [instance(GA, 'Assigned'), instance(GA, 'Assigned'), instance(GA, 'Assigned')] });
    expect(result.status).toBe('FAIL');
  });

  it('is NOT_APPLICABLE without PIM licensing', () => {
    expect(run(entraPrivilegedNoPermanent, {}, { unavailable: { 'entra.roleAssignmentScheduleInstances': 'NotApplicable' } }).status).toBe('NOT_APPLICABLE');
  });
});

describe('ENTRA-PRIV-005 administrators registered for MFA', () => {
  const adminId = 'bbbbbbbb-0000-4000-8000-000000000001';
  const reg = (id: string, registered: boolean) => ({ id, userPrincipalName: `${id}@contoso.example`, userType: 'member', isAdmin: true, isMfaRegistered: registered, methodsRegistered: [] });

  it('passes when every assessed administrator is registered and eligibility is empty', () => {
    const result = run(entraPrivilegedMfaRegistered, {
      'entra.roleAssignments': [roleAssignment(GA, { id: adminId })],
      'entra.userRegistrationDetails': [reg(adminId, true)],
      'entra.roleEligibilitySchedules': [],
    });
    expect(result.status).toBe('PASS');
  });

  it('fails when an administrator is not registered', () => {
    const result = run(entraPrivilegedMfaRegistered, {
      'entra.roleAssignments': [roleAssignment(GA, { id: adminId, userPrincipalName: 'admin@contoso.example' })],
      'entra.userRegistrationDetails': [reg(adminId, false)],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.name).toBe('admin@contoso.example');
  });

  it('requires review when an administrator is missing from the report', () => {
    const result = run(entraPrivilegedMfaRegistered, { 'entra.roleAssignments': [roleAssignment(GA, { id: adminId })], 'entra.userRegistrationDetails': [] });
    expect(result.status).toBe('REVIEW');
  });

  it('does not pass when disabled accounts, service principals and out-of-scope roles leave no user checked', () => {
    const result = run(entraPrivilegedMfaRegistered, {
      'entra.roleAssignments': [
        roleAssignment(GA, { id: adminId, accountEnabled: false }),
        roleAssignment(GA, { principalType: 'servicePrincipal' }),
        roleAssignment(ENTRA_ROLE_TEMPLATES.globalReader),
      ],
      'entra.userRegistrationDetails': [reg(adminId, false)],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.observed.facts.find((f) => f.label === 'Administrators checked')?.value).toBe(0);
  });

  it('requires review when eligible administrator evidence was not collected', () => {
    const result = run(entraPrivilegedMfaRegistered, {
      'entra.roleAssignments': [roleAssignment(GA, { id: adminId })],
      'entra.userRegistrationDetails': [reg(adminId, true)],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.notes.join(' ')).toContain('PIM eligibility evidence was not available');
  });

  it('requires review for unexpanded group assignments even with a registered direct user', () => {
    const result = run(entraPrivilegedMfaRegistered, {
      'entra.roleAssignments': [roleAssignment(GA, { id: adminId }), roleAssignment(GA, { principalType: 'group' })],
      'entra.userRegistrationDetails': [reg(adminId, true)],
      'entra.roleEligibilitySchedules': [],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.observed.facts.find((f) => f.label === 'Unresolved group or principal assignments')?.value).toBe(1);
  });

  it('requires review for selected PIM-eligible assignments with tenant-specific role definition IDs', () => {
    const roleId = nextGuid();
    const result = run(entraPrivilegedMfaRegistered, {
      'entra.roleAssignments': [roleAssignment(GA, { id: adminId })],
      'entra.userRegistrationDetails': [reg(adminId, true)],
      'entra.roleDefinitions': [{ id: roleId, templateId: GA, displayName: 'Global Administrator', isBuiltIn: true }],
      'entra.roleEligibilitySchedules': [{ id: nextGuid(), roleDefinitionId: roleId, principalId: nextGuid(), directoryScopeId: '/' }],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.observed.facts.find((f) => f.label === 'Selected PIM-eligible assignments not assessed')?.value).toBe(1);
  });

  it('preserves known registration failures when group and eligibility coverage are incomplete', () => {
    const result = run(entraPrivilegedMfaRegistered, {
      'entra.roleAssignments': [roleAssignment(GA, { id: adminId }), roleAssignment(GA, { principalType: 'group' })],
      'entra.userRegistrationDetails': [reg(adminId, false)],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(1);
    expect(result.notes.join(' ')).toContain('groups or unidentified principals');
  });

  it('is NOT_ASSESSED without the registration report', () => {
    expect(run(entraPrivilegedMfaRegistered, { 'entra.roleAssignments': [] }).status).toBe('NOT_ASSESSED');
  });
});
