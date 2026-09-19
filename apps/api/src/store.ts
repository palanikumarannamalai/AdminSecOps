import { randomUUID } from 'node:crypto';
import { chmod, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { AdminSecOpsError, safeJsonParse } from '@adminsecops/core';
import { AssessmentResultSchema, GuidSchema, type AssessmentResult, type AssessmentSummary } from '@adminsecops/schemas';
import { z } from 'zod';

export type AssessmentSource = 'upload' | 'sample';

export interface AssessmentListItem {
  assessmentId: string;
  label: string | null;
  tenantDisplayName: string | null;
  primaryDomain: string | null;
  adForestName: string | null;
  assessedAt: string;
  processedAt: string;
  integrityVerified: boolean;
  source: AssessmentSource;
  summary: AssessmentSummary;
}

const StoredSchema = z.object({
  storeVersion: z.literal(1),
  source: z.enum(['upload', 'sample']),
  result: AssessmentResultSchema,
});

/**
 * File-based store for processed assessment results. Raw evidence packages are never
 * written to disk; only the processed result (which is itself sensitive) is kept so
 * the dashboard survives restarts. Files are written atomically with owner-only
 * permissions where the platform supports POSIX modes.
 */
export class AssessmentStore {
  private readonly dir: string;
  private readonly cache = new Map<string, { source: AssessmentSource; result: AssessmentResult }>();
  private loaded = false;

  constructor(dataDir: string) {
    this.dir = path.join(dataDir, 'assessments');
  }

  private fileFor(id: string): string {
    // IDs are validated as GUIDs before touching the file system (path traversal protection).
    if (!GuidSchema.safeParse(id).success) {
      throw new AdminSecOpsError('ASSESSMENT_ID_INVALID', 'Assessment ID is not valid.', { statusCode: 400 });
    }
    const file = path.join(this.dir, `${id.toLowerCase()}.json`);
    if (path.dirname(file) !== this.dir) throw new AdminSecOpsError('ASSESSMENT_ID_INVALID', 'Assessment ID is not valid.');
    return file;
  }

  private async ensureLoaded(): Promise<void> {
    if (this.loaded) return;
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    for (const name of await readdir(this.dir)) {
      if (!/^[0-9a-f-]{36}\.json$/.test(name)) continue;
      try {
        const raw = safeJsonParse(await readFile(path.join(this.dir, name)), { label: 'stored assessment', maxBytes: 200 * 1024 * 1024 });
        const stored = StoredSchema.parse(raw);
        this.cache.set(stored.result.assessmentId.toLowerCase(), { source: stored.source, result: stored.result });
      } catch {
        // A corrupt or incompatible stored result is skipped rather than crashing the server.
      }
    }
    this.loaded = true;
  }

  async save(result: AssessmentResult, source: AssessmentSource): Promise<void> {
    await this.ensureLoaded();
    const file = this.fileFor(result.assessmentId);
    const temp = path.join(this.dir, `.${randomUUID()}.tmp`);
    const body = JSON.stringify({ storeVersion: 1, source, result });
    await writeFile(temp, body, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    try {
      await rename(temp, file);
      await chmod(file, 0o600).catch(() => undefined);
    } catch (error) {
      await rm(temp, { force: true });
      throw error;
    }
    this.cache.set(result.assessmentId.toLowerCase(), { source, result });
  }

  async get(id: string): Promise<AssessmentResult | undefined> {
    this.fileFor(id);
    await this.ensureLoaded();
    return this.cache.get(id.toLowerCase())?.result;
  }

  async delete(id: string): Promise<boolean> {
    const file = this.fileFor(id);
    await this.ensureLoaded();
    const existed = this.cache.delete(id.toLowerCase());
    await rm(file, { force: true });
    return existed;
  }

  async list(): Promise<AssessmentListItem[]> {
    await this.ensureLoaded();
    return [...this.cache.values()]
      .map(({ source, result }) => ({
        assessmentId: result.assessmentId,
        label: result.collection.environment.label,
        tenantDisplayName: result.collection.environment.tenantDisplayName,
        primaryDomain: result.collection.environment.primaryDomain,
        adForestName: result.collection.environment.adForestName,
        assessedAt: result.assessedAt,
        processedAt: result.processedAt,
        integrityVerified: result.evidence.integrityVerified,
        source,
        summary: result.summary,
      }))
      .sort((a, b) => b.processedAt.localeCompare(a.processedAt));
  }
}
