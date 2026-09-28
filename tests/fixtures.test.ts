import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { CONTROL_LIBRARY } from '@adminsecops/controls';
import { compareAssessments, runAssessment } from '@adminsecops/engine';
import { loadEvidenceBundle, readDirectoryPackage, type EvidenceBundle, type PackageFiles } from '@adminsecops/evidence';
import { listDatasetDefinitions, type AssessmentResult } from '@adminsecops/schemas';
import {
  CONTOSO_ASSESSMENT_ID,
  CONTOSO_FOLLOWUP_ASSESSMENT_ID,
  FABRIKAM_ASSESSMENT_ID,
  FIXTURES_ROOT,
  buildFixturePackages,
  type FixturePackage,
} from '../scripts/fixtures/index.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PROCESSED_AT = new Date('2026-09-10T00:00:00Z');
const DIRECTORIES = ['contoso', 'contoso-followup', 'fabrikam'] as const;
type Directory = (typeof DIRECTORIES)[number];

const onDisk = new Map<Directory, PackageFiles>();
const bundles = new Map<Directory, EvidenceBundle>();
const results = new Map<Directory, AssessmentResult>();
let generated: FixturePackage[] = [];

function get<T>(map: Map<Directory, T>, key: Directory): T {
  const value = map.get(key);
  if (value === undefined) throw new Error(`No fixture data for ${key}`);
  return value;
}

beforeAll(async () => {
  generated = buildFixturePackages();
  for (const directory of DIRECTORIES) {
    const files = await readDirectoryPackage(path.join(repoRoot, FIXTURES_ROOT, directory));
    onDisk.set(directory, files);
    const bundle = loadEvidenceBundle(files);
    bundles.set(directory, bundle);
    results.set(directory, runAssessment(bundle, CONTROL_LIBRARY, { processedAt: PROCESSED_AT }));
  }
});

describe.each(DIRECTORIES)('fixture %s', (directory) => {
  it('is byte-for-byte identical to a fresh in-memory regeneration', () => {
    const pkg = generated.find((p) => p.directory === directory);
    expect(pkg, 'generator produces this fixture').toBeDefined();
    const committed = get(onDisk, directory);
    expect([...committed.keys()].sort()).toEqual([...(pkg?.files.keys() ?? [])].sort());
    for (const [file, bytes] of pkg?.files ?? []) {
      expect(Buffer.from(committed.get(file) ?? new Uint8Array(0)).equals(bytes), `${file} matches the generator (run npm run fixtures)`).toBe(true);
    }
  });

  it('uses LF line endings and a trailing newline', () => {
    for (const [file, bytes] of get(onDisk, directory)) {
      const text = Buffer.from(bytes).toString('utf8');
      expect(text.includes('\r'), `${file} has no CR`).toBe(false);
      expect(text.endsWith('}\n'), `${file} ends with a newline`).toBe(true);
    }
  });

  it('passes integrity verification with no secret-like content', () => {
    const bundle = get(bundles, directory);
    expect(bundle.integrityVerified).toBe(true);
    expect(bundle.files.length).toBeGreaterThan(0);
    for (const check of bundle.files) {
      expect(check.integrity, check.path).toBe('verified');
      expect(check.sensitiveContent, check.path).toBe(false);
    }
    expect(bundle.issues.filter((i) => i.origin === 'ingestion')).toEqual([]);
  });

  it('validates every usable dataset against its schema', () => {
    const bundle = get(bundles, directory);
    for (const check of bundle.files) {
      const usable = check.collectionStatus === 'Success' || check.collectionStatus === 'Partial';
      expect(check.schema, `${check.path} (${check.collectionStatus ?? 'unknown'})`).toBe(usable ? 'valid' : 'not-checked');
    }
    for (const dataset of bundle.datasets.values()) {
      const expected = dataset.collectionStatus === 'Success' ? 'available' : dataset.collectionStatus === 'Partial' ? 'partial' : 'unavailable';
      expect(dataset.state, dataset.datasetId).toBe(expected);
    }
  });

  it('assesses without ERROR results', () => {
    const result = get(results, directory);
    expect(result.evidence.integrityVerified).toBe(true);
    expect(result.results.length).toBe(CONTROL_LIBRARY.length);
    const errors = result.results.filter((r) => r.status === 'ERROR').map((r) => `${r.controlId}: ${r.statusReason}`);
    expect(errors).toEqual([]);
  });
});

describe('fixture environments', () => {
  it('have distinct fixed assessment IDs matching their manifests', () => {
    expect(get(bundles, 'contoso').manifest.assessmentId).toBe(CONTOSO_ASSESSMENT_ID);
    expect(get(bundles, 'contoso-followup').manifest.assessmentId).toBe(CONTOSO_FOLLOWUP_ASSESSMENT_ID);
    expect(get(bundles, 'fabrikam').manifest.assessmentId).toBe(FABRIKAM_ASSESSMENT_ID);
    expect(new Set([CONTOSO_ASSESSMENT_ID, CONTOSO_FOLLOWUP_ASSESSMENT_ID, FABRIKAM_ASSESSMENT_ID]).size).toBe(3);
  });

  it('contoso includes every dataset known to the engine', () => {
    const present = new Set(get(bundles, 'contoso').manifest.files.map((f) => f.datasetId));
    for (const definition of listDatasetDefinitions()) expect(present.has(definition.id), definition.id).toBe(true);
  });

  it('contoso demonstrates each non-success collection state', () => {
    const bundle = get(bundles, 'contoso');
    const status = (id: string) => bundle.datasets.get(id)?.collectionStatus;
    expect(status('entra.onPremisesSynchronization')).toBe('Unauthorized');
    expect(status('entra.servicePrincipals')).toBe('Partial');
    expect(status('exchange.atpPolicy')).toBe('NotApplicable');
    expect(status('ad.domainControllerSettings')).toBe('NotCollected');
    const unauthorizedCount = bundle.manifest.files.filter((f) => f.module === 'Entra' && f.status === 'Unauthorized').length;
    expect(unauthorizedCount).toBe(1);
    expect(bundle.manifest.modules.find((m) => m.name === 'Entra')?.status).toBe('CompletedWithErrors');
  });

  it('contoso-followup newly collects the dataset that was unauthorized', () => {
    const bundle = get(bundles, 'contoso-followup');
    expect(bundle.datasets.get('entra.onPremisesSynchronization')?.state).toBe('available');
    expect(bundle.datasets.get('entra.servicePrincipals')?.state).toBe('available');
    expect(bundle.manifest.modules.find((m) => m.name === 'Entra')?.status).toBe('Completed');
  });

  it('fabrikam only contains on-premises modules and no tenant', () => {
    const bundle = get(bundles, 'fabrikam');
    expect(bundle.manifest.environment.tenantId).toBeNull();
    expect(new Set(bundle.manifest.modules.map((m) => m.name))).toEqual(new Set(['AD', 'ADCS', 'GPO', 'Windows']));
    expect(bundle.manifest.files.every((f) => ['AD', 'ADCS', 'GPO', 'Windows'].includes(f.module))).toBe(true);
  });

  it('fabrikam does not evaluate cloud controls as passing', () => {
    const result = get(results, 'fabrikam');
    const cloud = result.results.filter((r) => ['entra', 'm365', 'azure', 'intune'].includes(r.technology));
    for (const r of cloud) expect(['NOT_ASSESSED', 'NOT_APPLICABLE'], r.controlId).toContain(r.status);
  });

  it('comparison of contoso and contoso-followup reports resolved and new findings', () => {
    const baseline = get(results, 'contoso');
    const current = get(results, 'contoso-followup');
    expect(baseline.findings.length).toBeGreaterThan(0);
    const comparison = compareAssessments(baseline, current);
    expect(comparison.sameEnvironment).toBe(true);
    expect(comparison.baseline.assessmentId).toBe(CONTOSO_ASSESSMENT_ID);
    expect(comparison.current.assessmentId).toBe(CONTOSO_FOLLOWUP_ASSESSMENT_ID);
    expect(comparison.resolvedFindings.length).toBeGreaterThan(0);
    expect(comparison.newFindings.length).toBeGreaterThan(0);
    expect(comparison.direction).toBe('improved');
    expect(comparison.controlStatusChanges.length).toBeGreaterThan(0);
  });
});

it('compares observed values separately from lost coverage and ignores changed rule versions',()=>{
 const original=get(results,'contoso');const current=structuredClone(original);const target=current.results.find(r=>r.observed.facts.length>0&&r.status==='FAIL')!;
 const old=target.observed.facts[0]!;old.value='Synthetic changed value';
 expect(compareAssessments(original,current).factChanges?.some(c=>c.controlId===target.controlId&&c.to==='"Synthetic changed value"')).toBe(true);
 target.controlVersion='99.0.0';expect(compareAssessments(original,current).factChanges?.some(c=>c.controlId===target.controlId)).toBe(false);
 target.status='NOT_ASSESSED';expect(compareAssessments(original,current).lostCoverage?.some(c=>c.controlId===target.controlId)).toBe(true);
});
