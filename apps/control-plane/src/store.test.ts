import { describe, expect, it, vi } from 'vitest';
import type { Pool } from 'pg';
import type { AssessmentResult } from '@adminsecops/schemas';
import { PostgresStore, utcDay } from './store.js';

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

  it('creates the usage tables in the idempotent startup migration', async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ table_name: 'aso_sessions' }, { table_name: 'aso_jobs' }] });
    await new PostgresStore({ query } as unknown as Pool).initialize();
    const sql = String(query.mock.calls[0]?.[0]).replace(/\s+/g, ' ');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS aso_usage_daily ( day date NOT NULL, counter text NOT NULL, value bigint NOT NULL DEFAULT 0, PRIMARY KEY(day,counter))');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS aso_usage_orgs ( day date NOT NULL, org_hash text NOT NULL, PRIMARY KEY(day,org_hash))');
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS aso_usage_consent');
  });

  it('stores the tenant analytics choice and writes a matching audit event transactionally', async () => {
    const client = { query: vi.fn().mockResolvedValue({ rows: [] }), release: vi.fn() };
    const pool = { query: vi.fn().mockResolvedValue({ rows: [{ consented: true }] }), connect: vi.fn().mockResolvedValue(client) };
    const store = new PostgresStore(pool as unknown as Pool);
    expect(await store.hasUsageConsent('tenant-a')).toBe(true);
    expect(pool.query).toHaveBeenCalledWith('SELECT consented FROM aso_usage_consent WHERE tenant_id=$1', ['tenant-a']);
    await store.setUsageConsent('tenant-a', 'user-a', false);
    expect(client.query.mock.calls.map(([sql]) => String(sql))).toEqual([
      'BEGIN',
      expect.stringContaining('INSERT INTO aso_usage_consent'),
      expect.stringContaining('INSERT INTO aso_audit'),
      'COMMIT',
    ]);
    expect(client.query).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO aso_usage_consent'), ['tenant-a', false, 'user-a']);
    expect(client.query).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO aso_audit'), ['tenant-a', 'user-a', 'usage.consent.withdrawn']);
    expect(client.release).toHaveBeenCalled();
  });

  it('upserts allowlisted daily counters and the organisation hash only', async () => {
    const query = vi.fn().mockResolvedValue({ rows: [] });
    const store = new PostgresStore({ query } as unknown as Pool);
    await store.recordUsage({ assessments_completed: 1, controls_evaluated: 40 }, 'f'.repeat(64));
    expect(query).toHaveBeenCalledWith(expect.stringContaining('ON CONFLICT(day,counter) DO UPDATE SET value=aso_usage_daily.value+EXCLUDED.value'), [utcDay(), ['assessments_completed', 'controls_evaluated'], [1, 40]]);
    expect(query).toHaveBeenLastCalledWith(expect.stringContaining('INSERT INTO aso_usage_orgs(day,org_hash)'), [utcDay(), 'f'.repeat(64)]);
    query.mockClear();
    await expect(store.recordUsage({ 'aaaaaaaa-0000-4000-8000-000000000001': 1 })).rejects.toThrow('Unknown usage counter');
    expect(query).not.toHaveBeenCalled();
  });

  it('summarises usage per day with totals for every counter and distinct organisations', async () => {
    const query = vi.fn()
      .mockResolvedValueOnce({ rows: [{ day: '2026-09-25', counter: 'assessments_started', value: '2' }, { day: '2026-09-26', counter: 'assessments_started', value: '3' }, { day: '2026-09-26', counter: 'exports_html', value: '1' }] })
      .mockResolvedValueOnce({ rows: [{ n: '2' }] });
    const summary = await new PostgresStore({ query } as unknown as Pool).usageSummary(7);
    expect(query.mock.calls[0]?.[1]).toEqual([utcDay(-6)]);
    expect(summary.from).toBe(utcDay(-6));
    expect(summary.to).toBe(utcDay());
    expect(summary.totals).toMatchObject({ assessments_started: 5, exports_html: 1, assessments_failed: 0, failed_TIMEOUT: 0 });
    expect(summary.distinctOrganisations).toBe(2);
    // One distinct count across the whole window, not a sum of daily counts.
    expect(String(query.mock.calls[1]?.[0])).toContain('count(DISTINCT org_hash)');
    expect(String(query.mock.calls[1]?.[0])).not.toContain('GROUP BY');
    expect(query.mock.calls[1]?.[1]).toEqual([utcDay(-6)]);
    expect(summary.days).toEqual([{ day: '2026-09-25', counters: { assessments_started: 2 } }, { day: '2026-09-26', counters: { assessments_started: 3, exports_html: 1 } }]);
    const all = vi.fn().mockResolvedValue({ rows: [] });
    expect((await new PostgresStore({ query: all } as unknown as Pool).usageSummary(0)).from).toBeNull();
    expect(all.mock.calls[0]?.[1]).toEqual([null]);
    await new PostgresStore({ query: all } as unknown as Pool).usageSummary(26);
    expect(all.mock.calls[2]?.[1]).toEqual([utcDay(-25)]);
  });

  it('keeps 30-day results and 90-day audit retention, deletes old usage rows and reports expired jobs', async () => {
    const query = vi.fn((sql: string) => Promise.resolve({ rows: [], rowCount: sql.includes("status='running' AND") ? 2 : sql.includes("status='queued' AND") ? 1 : 0 }));
    const store = new PostgresStore({ query } as unknown as Pool);
    expect(await store.cleanup()).toEqual({ timedOut: 2, queueExpired: 1 });
    const statements = query.mock.calls.map(([sql]) => String(sql));
    expect(statements).toContain("DELETE FROM aso_assessments WHERE created_at<now()-interval '30 days'");
    expect(statements).toContain("DELETE FROM aso_audit WHERE created_at<now()-interval '90 days'");
    expect(query).toHaveBeenCalledWith('DELETE FROM aso_usage_daily WHERE day<$1::date', [utcDay(-400)]);
    expect(query).toHaveBeenCalledWith('DELETE FROM aso_usage_orgs WHERE day<$1::date', [utcDay(-400)]);
    await store.cleanup(30);
    expect(query).toHaveBeenLastCalledWith('DELETE FROM aso_usage_orgs WHERE day<$1::date', [utcDay(-30)]);
  });

  it('computes UTC days', () => {
    expect(utcDay(0, Date.UTC(2026, 8, 26, 23, 59))).toBe('2026-09-26');
    expect(utcDay(-400, Date.UTC(2026, 8, 26))).toBe('2025-08-22');
  });
});

it('scopes remediation reads and progress writes to the tenant',async()=>{
 const query=vi.fn().mockResolvedValue({rows:[]});const store=new PostgresStore({query} as unknown as Pool);
 expect(await store.getRemediation('tenant-a','CONTROL')).toBeNull();expect(query).toHaveBeenLastCalledWith(expect.stringContaining('tenant_id=$1 AND control_id=$2'),['tenant-a','CONTROL']);
 await store.progress({id:'job',tenantId:'tenant-a',userId:'u',encryptedTokens:'x'},'entra.organization','Success');expect(query).toHaveBeenLastCalledWith(expect.stringContaining("tenant_id=$2 AND status='running'"),['job','tenant-a','entra.organization','Success']);
});
