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

  it('adds the connector column only when it is missing and clears connector tokens with the job', async () => {
    const present = vi.fn().mockResolvedValue({ rows: [{ table_name: 'aso_sessions',column_name:'modules' }, { table_name: 'aso_jobs',column_name:'progress' }] });
    await new PostgresStore({ query: present } as unknown as Pool).initialize();
    expect(present.mock.calls.some(([sql]) => String(sql).startsWith('ALTER TABLE'))).toBe(false);
    const missing = vi.fn().mockResolvedValue({ rows: [{ table_name: 'aso_sessions',column_name:'modules' },{column_name:'progress'}] });
    await new PostgresStore({ query: missing } as unknown as Pool).initialize();
    expect(missing.mock.calls.filter(([sql]) => String(sql).startsWith('ALTER TABLE')).map(([sql]) => String(sql))).toEqual(['ALTER TABLE aso_jobs ADD COLUMN IF NOT EXISTS encrypted_connectors text']);
    const query = vi.fn().mockResolvedValue({ rows: [] });
    await new PostgresStore({ query } as unknown as Pool).fail({ id: 'job', tenantId: 'tenant-a', userId: 'u', encryptedTokens: 'e' }, 'failed');
    expect(query).toHaveBeenCalledWith(expect.stringContaining('encrypted_tokens=NULL,encrypted_connectors=NULL'), ['job', 'tenant-a', 'failed']);
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

it('scopes remediation reads and progress writes to the tenant',async()=>{
 const query=vi.fn().mockResolvedValue({rows:[]});const store=new PostgresStore({query} as unknown as Pool);
 expect(await store.getRemediation('tenant-a','CONTROL')).toBeNull();expect(query).toHaveBeenLastCalledWith(expect.stringContaining('tenant_id=$1 AND control_id=$2'),['tenant-a','CONTROL']);
 await store.progress({id:'job',tenantId:'tenant-a',userId:'u',encryptedTokens:'x'},'entra.organization','Success');expect(query).toHaveBeenLastCalledWith(expect.stringContaining("tenant_id=$2 AND status='running'"),['job','tenant-a','entra.organization','Success']);
});
