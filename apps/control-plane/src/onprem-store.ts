import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import type { AssessmentResult } from '@adminsecops/schemas';

export interface OnPremAgent {
  id: string;
  name: string;
  tenantId: string;
  expiresAt: string;
  revoked: boolean;
}
export interface OnPremStore {
  enroll(tenantId: string, userId: string, name: string, tokenHash: string): Promise<OnPremAgent>;
  agents(tenantId: string): Promise<OnPremAgent[]>;
  revoke(tenantId: string, id: string): Promise<void>;
  authenticate(tokenHash: string): Promise<OnPremAgent | null>;
  save(
    tenantId: string,
    userId: string | null,
    result: AssessmentResult,
    agentId?: string,
  ): Promise<void>;
}
export class PostgresOnPremStore implements OnPremStore {
  constructor(private readonly pool: Pool) {}
  async initialize(): Promise<void> {
    await this.pool.query(`CREATE TABLE IF NOT EXISTS aso_onprem_agents (
      id uuid PRIMARY KEY, tenant_id uuid NOT NULL, user_id uuid NOT NULL, name text NOT NULL,
      token_hash text NOT NULL UNIQUE, expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false);
      CREATE INDEX IF NOT EXISTS aso_onprem_agents_tenant ON aso_onprem_agents(tenant_id);`);
  }
  async enroll(
    tenantId: string,
    userId: string,
    name: string,
    tokenHash: string,
  ): Promise<OnPremAgent> {
    const id = randomUUID();
    const expiresAt = new Date(Date.now() + 30 * 86400_000).toISOString();
    const c = await this.pool.connect();
    try {
      await c.query('BEGIN');
      await c.query('SELECT pg_advisory_xact_lock(hashtext($1))', [tenantId]);
      const count = await c.query<{ count: string }>(
        'SELECT count(*) FROM aso_onprem_agents WHERE tenant_id=$1 AND NOT revoked AND expires_at>now()',
        [tenantId],
      );
      if (Number(count.rows[0]?.count) >= 5)
        throw Object.assign(
          new Error('Five active agents are already enrolled. Revoke an unused agent first.'),
          { statusCode: 409 },
        );
      await c.query(
        'INSERT INTO aso_onprem_agents(id,tenant_id,user_id,name,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6)',
        [id, tenantId, userId, name, tokenHash, expiresAt],
      );
      await c.query(
        "INSERT INTO aso_audit(tenant_id,user_id,action,target_id) VALUES($1,$2,'onprem.agent.enrolled',$3)",
        [tenantId, userId, id],
      );
      await c.query('COMMIT');
    } catch (error) {
      await c.query('ROLLBACK');
      throw error;
    } finally {
      c.release();
    }
    return { id, tenantId, name, expiresAt, revoked: false };
  }
  async agents(tenantId: string): Promise<OnPremAgent[]> {
    const r = await this.pool.query<{
      id: string;
      tenantId: string;
      name: string;
      expiresAt: Date;
      revoked: boolean;
    }>(
      'SELECT id,tenant_id AS "tenantId",name,expires_at AS "expiresAt",revoked FROM aso_onprem_agents WHERE tenant_id=$1 ORDER BY expires_at DESC LIMIT 100',
      [tenantId],
    );
    return r.rows.map((a) => ({ ...a, expiresAt: a.expiresAt.toISOString() }));
  }
  async revoke(tenantId: string, id: string): Promise<void> {
    await this.pool.query(
      `WITH revoked AS (
        UPDATE aso_onprem_agents SET revoked=true WHERE tenant_id=$1 AND id=$2 AND NOT revoked RETURNING id
      ) INSERT INTO aso_audit(tenant_id,action,target_id)
        SELECT $1,'onprem.agent.revoked',id::text FROM revoked`,
      [tenantId, id],
    );
  }
  async authenticate(tokenHash: string): Promise<OnPremAgent | null> {
    const r = await this.pool.query<{
      id: string;
      tenantId: string;
      name: string;
      expiresAt: Date;
      revoked: boolean;
    }>(
      'SELECT id,tenant_id AS "tenantId",name,expires_at AS "expiresAt",revoked FROM aso_onprem_agents WHERE token_hash=$1 AND NOT revoked AND expires_at>now()',
      [tokenHash],
    );
    const a = r.rows[0];
    return a ? { ...a, expiresAt: a.expiresAt.toISOString() } : null;
  }
  async save(
    tenantId: string,
    userId: string | null,
    result: AssessmentResult,
    agentId?: string,
  ): Promise<void> {
    if (result.collection.environment.tenantId?.toLowerCase() !== tenantId.toLowerCase())
      throw new Error('Tenant mismatch');
    const c = await this.pool.connect();
    try {
      await c.query('BEGIN');
      if (agentId) {
        const active = await c.query(
          'SELECT id FROM aso_onprem_agents WHERE tenant_id=$1 AND id=$2 AND NOT revoked AND expires_at>now() FOR UPDATE',
          [tenantId, agentId],
        );
        if (active.rowCount !== 1) throw new Error('Agent expired or revoked');
      }
      await c.query('INSERT INTO aso_assessments(tenant_id,id,result) VALUES($1,$2,$3)', [
        tenantId,
        result.assessmentId,
        JSON.stringify(result),
      ]);
      await c.query(
        'INSERT INTO aso_audit(tenant_id,user_id,action,target_id) VALUES($1,$2,$3,$4)',
        [
          tenantId,
          userId,
          agentId ? 'onprem.agent.upload' : 'onprem.browser.upload',
          result.assessmentId,
        ],
      );
      await c.query('COMMIT');
    } catch (error) {
      await c.query('ROLLBACK');
      throw error;
    } finally {
      c.release();
    }
  }
}
