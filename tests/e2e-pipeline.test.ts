/**
 * End-to-end demonstration of the full local pipeline on sanitized data:
 * sanitized environment -> collector-compatible evidence (ZIP) -> schema validation
 * -> normalized inventory -> deterministic controls -> findings -> prioritization
 * -> HTML / JSON report -> comparison with a later assessment.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { CONTROL_LIBRARY } from '@adminsecops/controls';
import { assessZip, compareAssessments } from '@adminsecops/engine';
import { buildJsonReport, renderHtmlReport } from '@adminsecops/reporting';
import { AssessmentResultSchema, type AssessmentResult } from '@adminsecops/schemas';
import { makeZip } from '../packages/evidence/test/zip.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixtures = path.join(root, 'fixtures', 'assessments');

function filesOf(dir: string, base = dir): Array<{ name: string; data: Buffer }> {
  return readdirSync(dir).flatMap((entry) => {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) return filesOf(full, base);
    return [{ name: path.relative(base, full).split(path.sep).join('/'), data: readFileSync(full) }];
  });
}

async function assessFixture(name: string): Promise<AssessmentResult> {
  const zip = await makeZip(filesOf(path.join(fixtures, name)));
  return assessZip(zip, { processedAt: new Date('2026-09-19T00:00:00Z') });
}

const status = (result: AssessmentResult, id: string) => result.results.find((r) => r.controlId === id)?.status;

describe('end-to-end local assessment pipeline', () => {
  it('assesses the Contoso sample from a collector-format ZIP', async () => {
    const result = await assessFixture('contoso');
    expect(AssessmentResultSchema.safeParse(result).success).toBe(true);
    expect(result.evidence.integrityVerified).toBe(true);
    expect(result.results).toHaveLength(CONTROL_LIBRARY.length);
    expect(result.summary.byStatus.ERROR).toBe(0);

    // Intentional issues in the sanitized environment are detected.
    // The sample has MFA-related policies whose enforcement/scope needs review.
    expect(status(result, 'ENTRA-CA-002')).toBe('REVIEW');
    expect(status(result, 'GPO-PWD-001')).toBe('FAIL');
    expect(status(result, 'ADCS-TPL-001')).toBe('FAIL');
    expect(status(result, 'AZ-NET-001')).toBe('FAIL');
    // Collection states propagate honestly.
    expect(status(result, 'M365-MDO-001')).toBe('NOT_APPLICABLE'); // no Defender for Office 365
    expect(status(result, 'AD-DC-001')).toBe('NOT_ASSESSED'); // optional collection not run
    expect(status(result, 'HYB-SYNC-001')).toBe('NOT_ASSESSED'); // collector unauthorized

    // Prioritization: unique ranks, critical confirmed failures first.
    const ranks = result.findings.map((f) => f.priority.rank);
    expect(new Set(ranks).size).toBe(ranks.length);
    expect(result.findings[0]?.severity).toBe('critical');
    expect(result.findings[0]?.status).toBe('FAIL');

    // Every finding carries evidence traceable to verified files.
    for (const finding of result.findings) {
      expect(finding.evidence.some((e) => e.sha256 !== null)).toBe(true);
      expect(finding.rollback.length).toBeGreaterThan(0);
    }

    const html = renderHtmlReport(result, { generatedAt: new Date('2026-09-19T00:00:00Z') });
    expect(html).toContain('What should I fix first?');
    expect(html).not.toMatch(/<script/i);
    expect(buildJsonReport(result).assessment.findings.length).toBe(result.findings.length);
  });

  it('compares Contoso with its follow-up assessment (drift)', async () => {
    const before = await assessFixture('contoso');
    const after = await assessFixture('contoso-followup');
    const comparison = compareAssessments(before, after);
    expect(comparison.sameEnvironment).toBe(true);
    expect(comparison.resolvedFindings.length).toBeGreaterThan(0);
    // Legacy-auth exclusions already require review in the baseline.
    expect(before.results.find((r) => r.controlId === 'ENTRA-CA-003')?.status).toBe('REVIEW');
    expect(comparison.newFindings.map((f) => f.controlId)).toContain('HYB-SYNC-001');
    expect(comparison.direction).toBe('improved');
  });

  it('assesses an on-premises-only environment without inventing cloud results', async () => {
    const result = await assessFixture('fabrikam');
    const cloud = result.results.filter((r) => ['entra', 'm365', 'azure', 'intune', 'hybrid'].includes(r.technology));
    expect(cloud.every((r) => r.status === 'NOT_ASSESSED')).toBe(true);
    expect(status(result, 'ADCS-TPL-003')).toBe('FAIL');
    expect(status(result, 'WIN-SMB-001')).toBe('FAIL');
  });
});
