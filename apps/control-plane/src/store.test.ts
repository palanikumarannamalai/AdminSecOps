import { describe, expect, it, vi } from 'vitest';
import type { Pool } from 'pg';
import type { AssessmentResult } from '@adminsecops/schemas';
import { PostgresStore } from './store.js';

describe('Postgres tenant boundary', () => {
  it('rejects a result for another tenant before accessing the database', async () => {
    const connect = vi.fn();
    const store = new PostgresStore({ connect } as unknown as Pool);
    const result = { collection: { environment: { tenantId: 'tenant-b' } } } as AssessmentResult;
    await expect(store.complete({ id: 'job-a', tenantId: 'tenant-a', userId: 'admin-a', encryptedTokens: 'encrypted' }, result)).rejects.toThrow('Assessment tenant mismatch');
    expect(connect).not.toHaveBeenCalled();
  });

  it('binds tenant identity separately from a supplied report ID in database reads', async () => {
    const query = vi.fn().mockResolvedValue({ rows: [] });
    const store = new PostgresStore({ query } as unknown as Pool);
    expect(await store.getAssessment('tenant-a', 'report-b')).toBeNull();
    expect(query).toHaveBeenCalledWith(expect.stringContaining('WHERE tenant_id=$1 AND id=$2'), ['tenant-a', 'report-b']);
    await store.listAssessments('tenant-a');
    expect(query).toHaveBeenLastCalledWith(expect.stringContaining('WHERE tenant_id=$1'), ['tenant-a']);
    await store.listJobs('tenant-a');
    expect(query).toHaveBeenLastCalledWith(expect.stringContaining('WHERE tenant_id=$1'), ['tenant-a']);
  });
});
