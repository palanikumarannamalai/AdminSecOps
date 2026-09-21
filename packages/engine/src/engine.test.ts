import { describe, expect, it } from 'vitest';
import { defineControl, fail, pass, review, type ControlDefinition } from '@adminsecops/controls';
import { loadEvidenceBundle, buildEvidencePackage } from '@adminsecops/evidence';
import { createInventoryFromData } from '@adminsecops/inventory';
import type { AssessmentResult, ControlMetadataInput } from '@adminsecops/schemas';
import { runAssessment } from './assess.js';
import { compareAssessments } from './compare.js';
import { evaluateControl } from './evaluate.js';
import { prioritize, sortKeyFor, tierFor } from './prioritize.js';
import { envelope, manifestBase } from '../../evidence/test/sample.js';

function meta(id: string, overrides: Partial<ControlMetadataInput> = {}): ControlMetadataInput {
  return {
    id,
    version: '1.0.0',
    lifecycle: 'stable',
    title: `Test control ${id}`,
    technology: 'entra',
    category: 'Test',
    subcategory: 'Test',
    description: 'A control used only by engine tests.',
    rationale: 'Exercises engine semantics in isolation.',
    severity: 'high',
    confidence: 'high',
    applicability: { description: 'Always.' },
    requiredEvidence: ['entra.securityDefaults'],
    evaluation: { logic: 'Test logic that reads security defaults.' },
    expectedState: 'Security defaults are enabled.',
    remediation: { summary: 'Enable security defaults for testing.', steps: ['Do it'], effort: 'low' },
    implementationConsiderations: ['None.'],
    impact: 'None for tests.',
    rollback: ['Undo'],
    validation: ['Re-run'],
    references: [{ title: 'Security defaults', url: 'https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults', publisher: 'Microsoft' }],
    frameworkMappings: [],
    tags: [],
    ...overrides,
  };
}

const sdControl = defineControl({
  ...meta('TEST-SD-001'),
  evaluate: (ctx) =>
    ctx.data('entra.securityDefaults').isEnabled
      ? pass({ reason: 'on', summary: 'Security defaults on' })
      : fail({ reason: 'off', summary: 'Security defaults off', affectedObjects: [{ type: 'tenant', id: 't', name: 'Tenant' }] }),
});

describe('evaluateControl semantics', () => {
  it('evaluates PASS and FAIL', () => {
    expect(evaluateControl(sdControl, createInventoryFromData({ 'entra.securityDefaults': { isEnabled: true } })).status).toBe('PASS');
    expect(evaluateControl(sdControl, createInventoryFromData({ 'entra.securityDefaults': { isEnabled: false } })).status).toBe('FAIL');
  });

  it('never passes on missing evidence', () => {
    const result = evaluateControl(sdControl, createInventoryFromData({}));
    expect(result.status).toBe('NOT_ASSESSED');
    expect(result.evidence[0]?.datasetId).toBe('entra.securityDefaults');
  });

  it('returns NOT_APPLICABLE only when all unavailable evidence is NotApplicable', () => {
    const mixed = defineControl({
      ...meta('TEST-MIX-001', { requiredEvidence: ['entra.securityDefaults', 'entra.subscribedSkus'] }),
      evaluate: () => pass({ reason: 'x', summary: 'x' }),
    });
    const na = createInventoryFromData({}, { unavailable: { 'entra.securityDefaults': 'NotApplicable', 'entra.subscribedSkus': 'NotApplicable' } });
    const partlyFailed = createInventoryFromData({}, { unavailable: { 'entra.securityDefaults': 'NotApplicable', 'entra.subscribedSkus': 'Failed' } });
    expect(evaluateControl(mixed, na).status).toBe('NOT_APPLICABLE');
    expect(evaluateControl(mixed, partlyFailed).status).toBe('NOT_ASSESSED');
  });

  it('downgrades PASS on partial evidence but keeps FAIL', () => {
    const on = createInventoryFromData({ 'entra.securityDefaults': { isEnabled: true } }, { partial: ['entra.securityDefaults'] });
    const off = createInventoryFromData({ 'entra.securityDefaults': { isEnabled: false } }, { partial: ['entra.securityDefaults'] });
    expect(evaluateControl(sdControl, on).status).toBe('REVIEW');
    expect(evaluateControl(sdControl, on).confidence).toBe('medium');
    const failed = evaluateControl(sdControl, off);
    expect(failed.status).toBe('FAIL');
    expect(failed.notes.join(' ')).toContain('partially collected');
  });

  it('converts exceptions to ERROR without leaking the message', () => {
    const broken = defineControl({
      ...meta('TEST-ERR-001'),
      evaluate: () => {
        throw new Error('secret value 12345');
      },
    });
    const result = evaluateControl(broken, createInventoryFromData({ 'entra.securityDefaults': { isEnabled: true } }));
    expect(result.status).toBe('ERROR');
    expect(result.statusReason).not.toContain('12345');
  });

  it('turns unavailable optional evidence into NOT_ASSESSED', () => {
    const optional = defineControl({
      ...meta('TEST-OPT-001', { optionalEvidence: ['entra.conditionalAccessPolicies'] }),
      evaluate: (ctx) => {
        ctx.data('entra.conditionalAccessPolicies');
        return pass({ reason: 'x', summary: 'x' });
      },
    });
    const result = evaluateControl(optional, createInventoryFromData({ 'entra.securityDefaults': { isEnabled: true } }));
    expect(result.status).toBe('NOT_ASSESSED');
    expect(result.evidence.map((e) => e.datasetId)).toContain('entra.conditionalAccessPolicies');
  });

  it('applies NOT_APPLICABLE from applies()', () => {
    const scoped = defineControl({
      ...meta('TEST-APP-001'),
      applies: () => ({ applicable: false, reason: 'No licence' }),
      evaluate: () => pass({ reason: 'x', summary: 'x' }),
    });
    const result = evaluateControl(scoped, createInventoryFromData({ 'entra.securityDefaults': { isEnabled: true } }));
    expect(result.status).toBe('NOT_APPLICABLE');
    expect(result.statusReason).toBe('No licence');
  });

  it('never raises confidence above the declared confidence', () => {
    const medium = defineControl({
      ...meta('TEST-CONF-001', { confidence: 'medium' }),
      evaluate: () => ({ ...review({ reason: 'x', summary: 'x' }), confidence: 'high' as const }),
    });
    const low = defineControl({
      ...meta('TEST-CONF-002'),
      evaluate: () => ({ ...review({ reason: 'x', summary: 'x' }), confidence: 'low' as const }),
    });
    const inv = createInventoryFromData({ 'entra.securityDefaults': { isEnabled: true } });
    expect(evaluateControl(medium, inv).confidence).toBe('medium');
    expect(evaluateControl(low, inv).confidence).toBe('low');
  });

  it('rejects invalid control metadata at definition time', () => {
    expect(() => defineControl({ ...meta('TEST-BAD-001', { rollback: [] }), evaluate: () => pass({ reason: 'x', summary: 'x' }) })).toThrow(
      /rollback/,
    );
    expect(() =>
      defineControl({ ...meta('TEST-BAD-002', { requiredEvidence: ['entra.doesNotExist'] }), evaluate: () => pass({ reason: 'x', summary: 'x' }) }),
    ).toThrow(/unknown dataset/);
    expect(() =>
      defineControl({
        ...meta('TEST-BAD-003', { references: [{ title: 'Insecure', url: 'http://example.com', publisher: 'Other' }] }),
        evaluate: () => pass({ reason: 'x', summary: 'x' }),
      }),
    ).toThrow(/https/);
  });
});

describe('prioritization', () => {
  const base = { status: 'FAIL' as const, severity: 'high' as const, confidence: 'high' as const, tags: [], effort: 'medium' as const };

  it('orders confirmed findings before review, then severity, confidence, exposure and effort', () => {
    expect(sortKeyFor({ ...base, key: 'a', severity: 'critical', status: 'REVIEW' })).toBeLessThan(sortKeyFor({ ...base, key: 'b' }));
    expect(sortKeyFor({ ...base, key: 'a' })).toBeGreaterThan(sortKeyFor({ ...base, key: 'b', status: 'REVIEW' }));
    expect(sortKeyFor({ ...base, key: 'a' })).toBeGreaterThan(sortKeyFor({ ...base, key: 'b', confidence: 'medium' }));
    expect(sortKeyFor({ ...base, key: 'a', tags: ['privileged-access'] })).toBeGreaterThan(sortKeyFor({ ...base, key: 'b' }));
    expect(sortKeyFor({ ...base, key: 'a', effort: 'low' })).toBeGreaterThan(sortKeyFor({ ...base, key: 'b' }));
    expect(sortKeyFor({ ...base, key: 'a', tags: ['x', 'y', 'z'] })).toBe(sortKeyFor({ ...base, key: 'b' }));
  });

  it('assigns tiers', () => {
    expect(tierFor({ ...base, key: 'a' })).toBe('fix-now');
    expect(tierFor({ ...base, key: 'a', confidence: 'low' })).toBe('fix-next');
    expect(tierFor({ ...base, key: 'a', severity: 'medium' })).toBe('fix-next');
    expect(tierFor({ ...base, key: 'a', severity: 'low' })).toBe('plan');
    expect(tierFor({ ...base, key: 'a', status: 'REVIEW', severity: 'critical' })).toBe('review');
  });

  it('assigns unique ranks with a deterministic tie-breaker', () => {
    const ranks = prioritize([
      { ...base, key: 'B' },
      { ...base, key: 'A' },
      { ...base, key: 'C', severity: 'critical' },
    ]);
    expect(ranks.get('C')?.rank).toBe(1);
    expect(ranks.get('A')?.rank).toBe(2);
    expect(ranks.get('B')?.rank).toBe(3);
  });
});

function assessmentWith(securityDefaults: boolean, assessmentId: string): AssessmentResult {
  const { files } = buildEvidencePackage({ ...manifestBase(), assessmentId }, [
    { path: 'evidence/entra/securityDefaults.json', envelope: envelope('entra.securityDefaults', { isEnabled: securityDefaults }, { assessmentId }) },
  ]);
  const controls: ControlDefinition[] = [sdControl];
  return runAssessment(loadEvidenceBundle(files), controls, { processedAt: new Date('2026-09-02T00:00:00Z') });
}

describe('runAssessment', () => {
  it('produces results, prioritized findings and a summary', () => {
    const result = assessmentWith(false, '6f1c1a52-4b7e-4f8e-9a51-0c6f7d2b9e10');
    expect(result.results).toHaveLength(1);
    expect(result.findings).toHaveLength(1);
    const finding = result.findings[0];
    expect(finding?.priority.rank).toBe(1);
    expect(finding?.findingId).toMatch(/^F-[a-f0-9]{20}$/);
    expect(finding?.rollback.length).toBeGreaterThan(0);
    expect(result.summary.byStatus.FAIL).toBe(1);
    expect(result.summary.findingsBySeverity.high).toBe(1);
    expect(result.summary.assessmentCoverage).toEqual({ assessed: 1, applicable: 1 });
    expect(result.evidence.integrityVerified).toBe(true);
    expect(result.evidence.datasets.find((d) => d.datasetId === 'entra.securityDefaults')?.state).toBe('available');
  });

  it('is deterministic apart from processedAt', () => {
    const a = assessmentWith(false, '6f1c1a52-4b7e-4f8e-9a51-0c6f7d2b9e10');
    const b = assessmentWith(false, '6f1c1a52-4b7e-4f8e-9a51-0c6f7d2b9e10');
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
  });
});

describe('compareAssessments', () => {
  it('detects resolved and new findings', () => {
    const before = assessmentWith(false, '6f1c1a52-4b7e-4f8e-9a51-0c6f7d2b9e10');
    const after = assessmentWith(true, '7f1c1a52-4b7e-4f8e-9a51-0c6f7d2b9e10');
    const improved = compareAssessments(before, after);
    expect(improved.resolvedFindings.map((f) => f.controlId)).toEqual(['TEST-SD-001']);
    expect(improved.direction).toBe('improved');
    expect(improved.controlStatusChanges).toEqual([{ controlId: 'TEST-SD-001', title: 'Test control TEST-SD-001', from: 'FAIL', to: 'PASS' }]);
    const regressed = compareAssessments(after, before);
    expect(regressed.newFindings).toHaveLength(1);
    expect(regressed.direction).toBe('regressed');
    expect(compareAssessments(before, before).direction).toBe('unchanged');
    expect(compareAssessments(before, before).unchangedFindingCount).toBe(1);
    expect(improved.sameEnvironment).toBe(true);
    expect(improved.resolvedFindings[0]?.otherStatus).toBe('PASS');
  });

  it('does not count findings that disappear because evidence was not collected as improvement', () => {
    const before = assessmentWith(false, '6f1c1a52-4b7e-4f8e-9a51-0c6f7d2b9e10');
    const { files } = buildEvidencePackage({ ...manifestBase(), assessmentId: '8f1c1a52-4b7e-4f8e-9a51-0c6f7d2b9e10' }, []);
    const empty = runAssessment(loadEvidenceBundle(files), [sdControl], { processedAt: new Date('2026-09-02T00:00:00Z') });
    const comparison = compareAssessments(before, empty);
    expect(comparison.resolvedFindings).toHaveLength(1);
    expect(comparison.resolvedFindings[0]?.otherStatus).toBe('NOT_ASSESSED');
    expect(comparison.direction).toBe('unchanged');
    expect(compareAssessments(empty, before).direction).toBe('unchanged');
  });
});
