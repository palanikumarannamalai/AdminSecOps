import { describe, expect, it } from 'vitest';
import { run } from '../../../test/run.js';
import { entraAppSecretLifetime, entraControlPlaneAppPermissions, entraDataAccessAppPermissions } from './applications.js';

const GRAPH = '00000003-0000-0000-c000-000000000000';
const EXO = '00000002-0000-0ff1-ce00-000000000000';

function grants(resourceAppId: string, roles: Record<string, string>, assignments: Array<[string, string]>) {
  return {
    resourceAppId,
    resourceDisplayName: resourceAppId === GRAPH ? 'Microsoft Graph' : 'Office 365 Exchange Online',
    appRoles: Object.entries(roles).map(([id, value]) => ({ id, value })),
    assignments: assignments.map(([principal, role], i) => ({
      id: `a${i}`,
      principalId: principal,
      principalType: 'ServicePrincipal',
      principalDisplayName: `App ${principal}`,
      appRoleId: role,
    })),
  };
}

describe('ENTRA-APP-004 / 005 high-impact application permissions', () => {
  const graph = grants(
    GRAPH,
    { r1: 'RoleManagement.ReadWrite.Directory', r2: 'User.Read.All', r3: 'Mail.Read', r4: 'Application.ReadWrite.All' },
    [
      ['sp1', 'r1'],
      ['sp1', 'r4'],
      ['sp2', 'r2'],
      ['sp3', 'r3'],
    ],
  );
  const exo = grants(EXO, { e1: 'full_access_as_app' }, [['sp4', 'e1']]);

  it('ENTRA-APP-004 requires review and groups permissions per application', () => {
    const result = run(entraControlPlaneAppPermissions, { 'entra.apiPermissionGrants': [graph, exo] });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects).toHaveLength(1);
    expect(result.affectedObjects[0]?.detail).toContain('RoleManagement.ReadWrite.Directory');
    expect(result.affectedObjects[0]?.detail).toContain('Application.ReadWrite.All');
  });

  it('ENTRA-APP-005 finds data access permissions on Graph and Exchange Online', () => {
    const result = run(entraDataAccessAppPermissions, { 'entra.apiPermissionGrants': [graph, exo] });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects.map((o) => o.id).sort()).toEqual(['sp3', 'sp4']);
  });

  it('passes when only low-impact permissions are granted', () => {
    const low = grants(GRAPH, { r2: 'User.Read.All' }, [['sp2', 'r2']]);
    expect(run(entraControlPlaneAppPermissions, { 'entra.apiPermissionGrants': [low] }).status).toBe('PASS');
    expect(run(entraDataAccessAppPermissions, { 'entra.apiPermissionGrants': [low] }).status).toBe('PASS');
  });

  it('ignores other resource applications', () => {
    const other = grants('11111111-1111-4111-8111-111111111111', { x: 'Directory.ReadWrite.All' }, [['sp9', 'x']]);
    expect(run(entraControlPlaneAppPermissions, { 'entra.apiPermissionGrants': [other] }).status).toBe('PASS');
  });
});

describe('ENTRA-APP-003 client secret lifetime', () => {
  const app = (secrets: Array<{ start: string | null; end: string | null }>) => ({
    id: 'obj1',
    appId: '22222222-2222-4222-8222-222222222222',
    displayName: 'Payroll connector',
    passwordCredentials: secrets.map((s, i) => ({ keyId: `k${i}`, displayName: `secret${i}`, startDateTime: s.start, endDateTime: s.end })),
    keyCredentials: [],
  });
  const at = { assessedAt: '2026-09-01T00:00:00Z' };

  it('fails for an active secret valid for two years', () => {
    const result = run(entraAppSecretLifetime, { 'entra.applications': [app([{ start: '2026-01-01T00:00:00Z', end: '2028-01-01T00:00:00Z' }])] }, at);
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('730 days');
  });

  it('passes for short-lived secrets and ignores expired long-lived ones', () => {
    const result = run(
      entraAppSecretLifetime,
      {
        'entra.applications': [
          app([
            { start: '2026-06-01T00:00:00Z', end: '2026-12-01T00:00:00Z' },
            { start: '2020-01-01T00:00:00Z', end: '2025-01-01T00:00:00Z' },
          ]),
        ],
      },
      at,
    );
    expect(result.status).toBe('PASS');
  });

  it('notes secrets without dates', () => {
    const result = run(entraAppSecretLifetime, { 'entra.applications': [app([{ start: null, end: null }])] }, at);
    expect(result.status).toBe('PASS');
    expect(result.notes[0]).toContain('no validity dates');
  });
});
