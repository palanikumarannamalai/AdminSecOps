import { describe, expect, it } from 'vitest';
import { azRoleAssignment, SUB_A, SUB_B, subscription } from '../../../test/builders/azure.js';
import { run } from '../../../test/run.js';
import { AZURE_ROLE_IDS, azRbacGuestPrivileged, azRbacOwnerCount } from './rbac.js';

const owners = (n: number, subscriptionId = SUB_A) => Array.from({ length: n }, () => azRoleAssignment({ subscriptionId }));

describe('AZ-RBAC-001 Owner assignments per subscription', () => {
  it('passes with three Owners', () => {
    const result = run(azRbacOwnerCount, { 'azure.roleAssignments': owners(3) });
    expect(result.status).toBe('PASS');
  });

  it('fails with four Owners and lists the subscription', () => {
    const result = run(azRbacOwnerCount, { 'azure.roleAssignments': owners(4) });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects).toHaveLength(1);
    expect(result.affectedObjects[0]?.id).toBe(`/subscriptions/${SUB_A}`);
    expect(result.affectedObjects[0]?.detail).toContain('4 Owner principals');
  });

  it('evaluates each subscription separately', () => {
    const result = run(azRbacOwnerCount, {
      'azure.roleAssignments': [...owners(2, SUB_A), ...owners(5, SUB_B)],
      'azure.subscriptions': [subscription(SUB_A, { displayName: 'Prod' }), subscription(SUB_B, { displayName: 'Dev' })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.name)).toEqual(['Dev']);
  });

  it('counts inherited management-group Owners and de-duplicates principals', () => {
    const principalId = '00000000-0000-4000-8000-00000000abcd';
    const result = run(azRbacOwnerCount, {
      'azure.roleAssignments': [
        ...owners(2),
        azRoleAssignment({ principalId }),
        azRoleAssignment({ principalId, scope: '/providers/Microsoft.Management/managementGroups/root' }),
        azRoleAssignment({ scope: '/providers/Microsoft.Management/managementGroups/corp' }),
      ],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('4 Owner principals');
  });

  it('ignores Owner at resource group scope and matches the Owner role by ID', () => {
    const result = run(azRbacOwnerCount, {
      'azure.roleAssignments': [
        ...owners(2),
        azRoleAssignment({ role: 'Custom Owner name', roleDefinitionId: `/subscriptions/${SUB_A}/providers/Microsoft.Authorization/roleDefinitions/${AZURE_ROLE_IDS.owner}` }),
        azRoleAssignment({ scope: `/subscriptions/${SUB_A}/resourceGroups/app` }),
        azRoleAssignment({ role: 'Contributor' }),
      ],
    });
    expect(result.status).toBe('PASS');
    expect(result.statusReason).toContain('1 subscription');
  });

  it('counts a group as one assignment and adds a note', () => {
    const result = run(azRbacOwnerCount, {
      'azure.roleAssignments': [...owners(1), azRoleAssignment({ principalType: 'Group', principalDisplayName: 'Cloud Admins', principalSignInName: null })],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('Group "Cloud Admins" holds Owner');
  });

  it('respects the case-insensitive subscription scope with a trailing slash', () => {
    const result = run(azRbacOwnerCount, {
      'azure.roleAssignments': [...owners(3), azRoleAssignment({ scope: `/SUBSCRIPTIONS/${SUB_A.toUpperCase()}/` })],
    });
    expect(result.status).toBe('FAIL');
  });

  it('requires review when a listed subscription has no role assignments', () => {
    const result = run(azRbacOwnerCount, {
      'azure.roleAssignments': owners(2),
      'azure.subscriptions': [subscription(SUB_A), subscription(SUB_B)],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects.map((o) => o.id)).toEqual([`/subscriptions/${SUB_B}`]);
  });

  it('skips disabled subscriptions from the subscription list', () => {
    const result = run(azRbacOwnerCount, {
      'azure.roleAssignments': owners(2),
      'azure.subscriptions': [subscription(SUB_A), subscription(SUB_B, { state: 'Disabled' })],
    });
    expect(result.status).toBe('PASS');
  });

  it('is NOT_ASSESSED when no assignments or subscriptions are in evidence', () => {
    expect(run(azRbacOwnerCount, { 'azure.roleAssignments': [] }).status).toBe('NOT_ASSESSED');
  });

  it('downgrades PASS to REVIEW on partial evidence', () => {
    const result = run(azRbacOwnerCount, { 'azure.roleAssignments': owners(2) }, { partial: ['azure.roleAssignments'] });
    expect(result.status).toBe('REVIEW');
  });
});

describe('AZ-RBAC-002 guests with privileged Azure roles', () => {
  const guest = (role: string, scope?: string) =>
    azRoleAssignment({ role, principalSignInName: 'partner_fabrikam.example#EXT#@contoso.onmicrosoft.com', ...(scope ? { scope } : {}) });

  it('passes when no guest holds a privileged role', () => {
    const result = run(azRbacGuestPrivileged, {
      'azure.roleAssignments': [azRoleAssignment(), guest('Reader')],
    });
    expect(result.status).toBe('PASS');
  });

  it.each(['Owner', 'Contributor', 'User Access Administrator', 'Role Based Access Control Administrator'])('fails for a guest with %s', (role) => {
    const result = run(azRbacGuestPrivileged, { 'azure.roleAssignments': [azRoleAssignment(), guest(role)] });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(1);
  });

  it('detects guests at resource group scope and case-insensitively', () => {
    const result = run(azRbacGuestPrivileged, {
      'azure.roleAssignments': [
        azRoleAssignment({ role: 'Contributor', scope: `/subscriptions/${SUB_A}/resourceGroups/app`, principalSignInName: 'x_y.example#ext#@contoso.onmicrosoft.com' }),
      ],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('resourceGroups/app');
  });

  it('matches privileged roles by built-in role ID', () => {
    const result = run(azRbacGuestPrivileged, {
      'azure.roleAssignments': [
        azRoleAssignment({
          role: 'Renamed',
          roleDefinitionId: `/providers/Microsoft.Authorization/roleDefinitions/${AZURE_ROLE_IDS.userAccessAdministrator}`,
          principalSignInName: 'a_b.example#EXT#@contoso.onmicrosoft.com',
        }),
      ],
    });
    expect(result.status).toBe('FAIL');
  });

  it('requires review when a privileged user has no resolved sign-in name', () => {
    const result = run(azRbacGuestPrivileged, {
      'azure.roleAssignments': [azRoleAssignment({ principalSignInName: null })],
    });
    expect(result.status).toBe('REVIEW');
  });

  it('does not treat service principals without sign-in names as unresolved users', () => {
    const result = run(azRbacGuestPrivileged, {
      'azure.roleAssignments': [azRoleAssignment({ principalType: 'ServicePrincipal', principalSignInName: null })],
    });
    expect(result.status).toBe('PASS');
  });

  it('is NOT_ASSESSED when the evidence has no role assignments', () => {
    expect(run(azRbacGuestPrivileged, { 'azure.roleAssignments': [] }).status).toBe('NOT_ASSESSED');
  });

  it('is NOT_ASSESSED when role assignments were not collected', () => {
    expect(run(azRbacGuestPrivileged, {}, { unavailable: { 'azure.roleAssignments': 'Unauthorized' } }).status).toBe('NOT_ASSESSED');
  });
});
