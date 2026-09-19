import { describe, expect, it } from 'vitest';
import { run } from '../../../test/run.js';
import { hybridBlockHardMatch, hybridBlockSoftMatch, hybridPasswordProtectionEnforced, hybridSyncRecent } from './directory-sync.js';

const org = (syncEnabled: boolean | null, lastSync: string | null = '2026-09-01T11:30:00Z') => ({
  id: '11111111-2222-4333-8444-555555555555',
  displayName: 'Contoso',
  onPremisesSyncEnabled: syncEnabled,
  onPremisesLastSyncDateTime: lastSync,
  verifiedDomains: [],
});
const sync = (features: Record<string, boolean | null>) => [{ id: 'sync1', features }];
const at = { assessedAt: '2026-09-01T12:00:00Z' };

describe('HYB-SYNC-001 / HYB-SYNC-002 match blocking', () => {
  it('is NOT_APPLICABLE for cloud-only tenants', () => {
    expect(run(hybridBlockHardMatch, { 'entra.organization': org(null), 'entra.onPremisesSynchronization': [] }).status).toBe('NOT_APPLICABLE');
  });

  it('passes and fails on the feature flags', () => {
    const data = (f: Record<string, boolean | null>) => ({ 'entra.organization': org(true), 'entra.onPremisesSynchronization': sync(f) });
    expect(run(hybridBlockHardMatch, data({ blockCloudObjectTakeoverThroughHardMatchEnabled: true })).status).toBe('PASS');
    expect(run(hybridBlockHardMatch, data({ blockCloudObjectTakeoverThroughHardMatchEnabled: false })).status).toBe('FAIL');
    expect(run(hybridBlockSoftMatch, data({ blockSoftMatchEnabled: true })).status).toBe('PASS');
    expect(run(hybridBlockSoftMatch, data({ blockSoftMatchEnabled: false })).status).toBe('FAIL');
    expect(run(hybridBlockSoftMatch, data({})).status).toBe('REVIEW');
  });

  it('is NOT_ASSESSED when the sync settings could not be read', () => {
    const result = run(hybridBlockHardMatch, { 'entra.organization': org(true) }, { unavailable: { 'entra.onPremisesSynchronization': 'Unauthorized' } });
    expect(result.status).toBe('NOT_ASSESSED');
  });
});

describe('HYB-SYNC-003 recent synchronization', () => {
  it('passes for a sync 30 minutes before the assessment', () => {
    expect(run(hybridSyncRecent, { 'entra.organization': org(true) }, at).status).toBe('PASS');
  });
  it('fails for a stale or missing sync', () => {
    expect(run(hybridSyncRecent, { 'entra.organization': org(true, '2026-08-25T00:00:00Z') }, at).status).toBe('FAIL');
    expect(run(hybridSyncRecent, { 'entra.organization': org(true, null) }, at).status).toBe('FAIL');
  });
  it('is NOT_APPLICABLE without sync', () => {
    expect(run(hybridSyncRecent, { 'entra.organization': org(false) }, at).status).toBe('NOT_APPLICABLE');
  });
});

describe('HYB-PWD-001 password protection', () => {
  const settings = (values: Array<[string, string]>) => [
    { id: 's1', displayName: 'Password Rule Settings', templateId: '5cf42378-d67d-4f36-ba46-e8b86229381d', values: values.map(([name, value]) => ({ name, value })) },
  ];

  it('passes in Enforce mode', () => {
    const result = run(hybridPasswordProtectionEnforced, {
      'entra.organization': org(true),
      'entra.groupSettings': settings([
        ['EnableBannedPasswordCheckOnPremises', 'True'],
        ['BannedPasswordCheckOnPremisesMode', 'Enforce'],
      ]),
    });
    expect(result.status).toBe('PASS');
  });

  it('fails in Audit mode or when disabled', () => {
    expect(
      run(hybridPasswordProtectionEnforced, {
        'entra.organization': org(true),
        'entra.groupSettings': settings([['BannedPasswordCheckOnPremisesMode', 'Audit']]),
      }).status,
    ).toBe('FAIL');
    expect(
      run(hybridPasswordProtectionEnforced, {
        'entra.organization': org(true),
        'entra.groupSettings': settings([
          ['EnableBannedPasswordCheckOnPremises', 'False'],
          ['BannedPasswordCheckOnPremisesMode', 'Enforce'],
        ]),
      }).status,
    ).toBe('FAIL');
  });

  it('applies Microsoft defaults (Audit) when no settings object exists', () => {
    const result = run(hybridPasswordProtectionEnforced, { 'entra.organization': org(true), 'entra.groupSettings': [] });
    expect(result.status).toBe('FAIL');
    expect(result.notes[0]).toContain('defaults');
  });

  it('is NOT_APPLICABLE for cloud-only tenants', () => {
    expect(run(hybridPasswordProtectionEnforced, { 'entra.organization': org(false), 'entra.groupSettings': [] }).status).toBe('NOT_APPLICABLE');
  });
});
