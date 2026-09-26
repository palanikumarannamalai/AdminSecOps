import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';
import type { AssessmentResult } from '@adminsecops/schemas';

export interface StoredSession {
  idHash: string; tenantId: string; userId: string; displayName: string;
  expiresAt: Date; encryptedTokens: string;
  /** JSON map of connector -> separately sealed connector tokens (see auth.ts ConnectorMap). */
  encryptedConnectors?: string | null;
}
export interface Job {
  id: string; tenantId: string; userId: string;
  status: 'queued'|'running'|'completed'|'failed';
  createdAt: string; completedAt: string|null; assessmentId: string|null; error: string|null;
}
export interface Store {
  putSession(session: StoredSession): Promise<void>;
  getSession(idHash: string): Promise<StoredSession|null>;
  deleteSession(idHash: string): Promise<void>;
  createJob(tenantId: string,userId: string,encryptedTokens: string,encryptedConnectors?: string|null): Promise<{id:string;status:string}>;
  listJobs(tenantId:string): Promise<Job[]>;
  listAssessments(tenantId:string): Promise<AssessmentResult[]>;
  getAssessment(tenantId:string,id:string): Promise<AssessmentResult|null>;
}
export interface ClaimedJob { id:string; tenantId:string; userId:string; encryptedTokens:string; encryptedConnectors?:string|null }
export class PostgresStore implements Store {
  constructor(readonly pool:Pool) {}
  async initialize():Promise<void> {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS aso_sessions (
        id_hash text PRIMARY KEY, tenant_id uuid NOT NULL, user_id uuid NOT NULL,
        display_name text NOT NULL, expires_at timestamptz NOT NULL, encrypted_tokens text NOT NULL);
      CREATE TABLE IF NOT EXISTS aso_jobs (
        id uuid PRIMARY KEY, tenant_id uuid NOT NULL, user_id uuid NOT NULL,
        status text NOT NULL CHECK(status IN ('queued','running','completed','failed')),
        encrypted_tokens text, created_at timestamptz NOT NULL DEFAULT now(),
        started_at timestamptz, completed_at timestamptz, assessment_id text, error text);
      CREATE UNIQUE INDEX IF NOT EXISTS aso_one_active_job ON aso_jobs(tenant_id)
        WHERE status IN ('queued','running');
      CREATE TABLE IF NOT EXISTS aso_assessments (
        tenant_id uuid NOT NULL, id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
        result jsonb NOT NULL, PRIMARY KEY(tenant_id,id));
      CREATE TABLE IF NOT EXISTS aso_audit (
        id bigserial PRIMARY KEY, tenant_id uuid NOT NULL, user_id uuid,
        action text NOT NULL, target_id text, created_at timestamptz NOT NULL DEFAULT now());
    `);
    // Connector column (0.3.0). ALTER needs table ownership, so it runs only when the column is missing;
    // a restricted runtime role starts normally once the owner has applied it (docs/ONLINE-CONNECTORS.md).
    const existing=await this.pool.query<{table_name:string}>("SELECT table_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name IN ('aso_sessions','aso_jobs') AND column_name='encrypted_connectors'");
    const present=new Set(existing.rows.map(r=>r.table_name));
    for(const table of ['aso_sessions','aso_jobs'] as const) if(!present.has(table)) await this.pool.query(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS encrypted_connectors text`);
  }
  async putSession(s:StoredSession):Promise<void> {
    await this.pool.query('INSERT INTO aso_sessions(id_hash,tenant_id,user_id,display_name,expires_at,encrypted_tokens,encrypted_connectors) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id_hash) DO UPDATE SET expires_at=$5,encrypted_tokens=$6,encrypted_connectors=$7',
      [s.idHash,s.tenantId,s.userId,s.displayName,s.expiresAt,s.encryptedTokens,s.encryptedConnectors??null]);
  }
  async getSession(idHash:string):Promise<StoredSession|null> {
    const r=await this.pool.query('SELECT id_hash AS "idHash",tenant_id AS "tenantId",user_id AS "userId",display_name AS "displayName",expires_at AS "expiresAt",encrypted_tokens AS "encryptedTokens",encrypted_connectors AS "encryptedConnectors" FROM aso_sessions WHERE id_hash=$1 AND expires_at>now()',[idHash]);
    return r.rows[0] as StoredSession|undefined ?? null;
  }
  async deleteSession(idHash:string):Promise<void> {await this.pool.query('DELETE FROM aso_sessions WHERE id_hash=$1',[idHash]);}
  async createJob(tenantId:string,userId:string,encryptedTokens:string,encryptedConnectors:string|null=null):Promise<{id:string;status:string}> {
    const id=randomUUID();
    const c=await this.pool.connect();
    try {
      await c.query('BEGIN');
      await c.query("INSERT INTO aso_jobs(id,tenant_id,user_id,status,encrypted_tokens,encrypted_connectors) VALUES($1,$2,$3,'queued',$4,$5)",[id,tenantId,userId,encryptedTokens,encryptedConnectors]);
      await c.query("INSERT INTO aso_audit(tenant_id,user_id,action,target_id) VALUES($1,$2,'assessment.queued',$3)",[tenantId,userId,id]);
      await c.query('COMMIT');
    } catch(e){await c.query('ROLLBACK');throw e;} finally {c.release();}
    return {id,status:'queued'};
  }
  async listJobs(tenantId:string):Promise<Job[]> {
    const r=await this.pool.query<Omit<Job,'createdAt'|'completedAt'> & {createdAt:Date;completedAt:Date|null}>('SELECT id,tenant_id AS "tenantId",user_id AS "userId",status,created_at AS "createdAt",completed_at AS "completedAt",assessment_id AS "assessmentId",error FROM aso_jobs WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100',[tenantId]);
    return r.rows.map((r)=>({...r,createdAt:r.createdAt.toISOString(),completedAt:r.completedAt?r.completedAt.toISOString():null}));
  }
  async listAssessments(tenantId:string):Promise<AssessmentResult[]> {
    const r=await this.pool.query<{result:AssessmentResult}>('SELECT result FROM aso_assessments WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100',[tenantId]);
    return r.rows.map(r=>r.result);
  }
  async getAssessment(tenantId:string,id:string):Promise<AssessmentResult|null> {
    const r=await this.pool.query<{result:AssessmentResult}>('SELECT result FROM aso_assessments WHERE tenant_id=$1 AND id=$2',[tenantId,id]);
    return (r.rows[0]?.result)??null;
  }
  async claim():Promise<ClaimedJob|null> {
    // One atomic statement claims a durable job. Multiple processes cannot claim the same row.
    const r=await this.pool.query(`UPDATE aso_jobs SET status='running',started_at=now()
      WHERE id=(SELECT id FROM aso_jobs WHERE status='queued' AND created_at>=now()-interval '1 hour' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1)
      RETURNING id,tenant_id AS "tenantId",user_id AS "userId",encrypted_tokens AS "encryptedTokens",encrypted_connectors AS "encryptedConnectors"`);
    return r.rows[0] as ClaimedJob|undefined ?? null;
  }
  async complete(job:ClaimedJob,result:AssessmentResult):Promise<void> {
    if(result.collection.environment.tenantId!==job.tenantId) throw new Error('Assessment tenant mismatch');
    const c=await this.pool.connect();
    try {
      await c.query('BEGIN');
      const current=await c.query("SELECT id FROM aso_jobs WHERE id=$1 AND tenant_id=$2 AND status='running' FOR UPDATE",[job.id,job.tenantId]);
      if(current.rowCount!==1) throw new Error('Job lease expired');
      await c.query('INSERT INTO aso_assessments(tenant_id,id,result) VALUES($1,$2,$3)',[job.tenantId,result.assessmentId,JSON.stringify(result)]);
      await c.query("UPDATE aso_jobs SET status='completed',completed_at=now(),assessment_id=$3,encrypted_tokens=NULL,encrypted_connectors=NULL WHERE id=$1 AND tenant_id=$2",[job.id,job.tenantId,result.assessmentId]);
      await c.query("INSERT INTO aso_audit(tenant_id,action,target_id) VALUES($1,'assessment.completed',$2)",[job.tenantId,job.id]);
      await c.query('COMMIT');
    } catch(e){await c.query('ROLLBACK');throw e;} finally {c.release();}
  }
  async fail(job:ClaimedJob,message:string):Promise<void> {
    await this.pool.query("UPDATE aso_jobs SET status='failed',completed_at=now(),error=$3,encrypted_tokens=NULL,encrypted_connectors=NULL WHERE id=$1 AND tenant_id=$2 AND status='running'",[job.id,job.tenantId,message]);
  }
  async cleanup():Promise<void> {
    await this.pool.query('DELETE FROM aso_sessions WHERE expires_at<now()');
    await this.pool.query("UPDATE aso_jobs SET status='failed',error='The worker stopped or exceeded the time limit. Please start another assessment.',completed_at=now(),encrypted_tokens=NULL,encrypted_connectors=NULL WHERE status='running' AND started_at<now()-interval '15 minutes'");
    await this.pool.query("UPDATE aso_jobs SET status='failed',error='The queued job expired. Sign in and start another assessment.',completed_at=now(),encrypted_tokens=NULL,encrypted_connectors=NULL WHERE status='queued' AND created_at<now()-interval '1 hour'");
    await this.pool.query("DELETE FROM aso_assessments WHERE created_at<now()-interval '30 days'");
    await this.pool.query("DELETE FROM aso_jobs WHERE completed_at<now()-interval '30 days'");
    await this.pool.query("DELETE FROM aso_audit WHERE created_at<now()-interval '90 days'");
  }
}
