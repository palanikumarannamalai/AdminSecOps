/**
 * Cross-language contract test: the PowerShell collector (offline replay of the sanitized Contoso
 * scenario) must produce a package that the TypeScript evidence loader verifies and the engine
 * assesses. Skipped only when PowerShell 7 (`pwsh`) is not installed.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { isUsableCollectionStatus } from '@adminsecops/core';
import { CONTROL_LIBRARY } from '@adminsecops/controls';
import { runAssessment } from '@adminsecops/engine';
import { loadEvidenceBundle, readZipPackage, type EvidenceBundle } from '@adminsecops/evidence';
import { listDatasetDefinitions } from '@adminsecops/schemas';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const moduleManifest = path.join(
  repoRoot,
  'collectors',
  'powershell',
  'AdminSecOps.Collector.psd1',
);
const replayPath = path.join(repoRoot, 'collectors', 'powershell', 'tests', 'replay', 'contoso');

function pwshAvailable(): boolean {
  try {
    const result = spawnSync(
      'pwsh',
      ['-NoProfile', '-NonInteractive', '-Command', '$PSVersionTable.PSVersion.Major'],
      {
        encoding: 'utf8',
        timeout: 60_000,
      },
    );
    return result.status === 0 && Number.parseInt(result.stdout.trim(), 10) >= 7;
  } catch {
    return false;
  }
}

const hasPwsh = pwshAvailable();

/** Statuses the Contoso replay scenario is designed to produce for non-Success datasets. */
const EXPECTED_NON_SUCCESS: Record<string, string> = {
  'entra.roleAssignmentScheduleInstances': 'NotApplicable',
  'entra.roleEligibilitySchedules': 'NotApplicable',
  'entra.onPremisesSynchronization': 'Unauthorized',
  'exchange.atpPolicy': 'NotApplicable',
  'azure.keyVaults': 'Partial',
  'ad.domainControllerSettings': 'NotCollected',
};

function quote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

describe.skipIf(!hasPwsh)('PowerShell collector contract (replay)', () => {
  let outputDir = '';
  let bundle: EvidenceBundle;
  let zipPath = '';

  beforeAll(async () => {
    outputDir = mkdtempSync(path.join(tmpdir(), 'aso-contract-'));
    const script = [
      "$ErrorActionPreference = 'Stop'",
      `Import-Module ${quote(moduleManifest)} -Force`,
      `$r = Invoke-AdminSecOpsCollection -Module All -ReplayPath ${quote(replayPath)} -OutputPath ${quote(outputDir)} -SkipConnect`,
      'Write-Output ("ZIP=" + $r.ZipPath)',
    ].join('; ');
    const result = spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-Command', script], {
      encoding: 'utf8',
      timeout: 240_000,
      maxBuffer: 16 * 1024 * 1024,
    });
    if (result.status !== 0) {
      throw new Error(
        `Collector run failed (exit ${String(result.status)}): ${result.stderr}\n${result.stdout}`,
      );
    }
    const line = result.stdout.split(/\r?\n/).find((l) => l.startsWith('ZIP='));
    if (line === undefined)
      throw new Error(`Collector did not report a ZIP path: ${result.stdout}`);
    zipPath = line.slice(4).trim();
    const files = await readZipPackage(readFileSync(zipPath));
    bundle = loadEvidenceBundle(files);
  }, 300_000);

  afterAll(() => {
    if (outputDir !== '') rmSync(outputDir, { recursive: true, force: true });
  });

  it('produces a ZIP whose integrity verifies', () => {
    expect(path.basename(zipPath)).toMatch(/^adminsecops-assessment-\d{8}-\d{6}\.zip$/);
    expect(bundle.integrityVerified).toBe(true);
    expect(bundle.manifest.product).toBe('AdminSecOps');
    expect(bundle.manifest.collector.name).toBe('AdminSecOps.Collector');
    expect(bundle.manifest.environment.tenantId).toBe('11111111-2222-4333-8444-555555555555');
    expect(bundle.manifest.environment.adForestName).toBe('corp.contoso.example');
    for (const check of bundle.files) {
      expect(check.integrity, check.path).toBe('verified');
    }
  });

  it('contains no sensitive content', () => {
    for (const check of bundle.files) {
      expect(check.sensitiveContent, check.path).toBe(false);
    }
    expect(bundle.issues.filter((i) => i.code === 'SENSITIVE_CONTENT')).toEqual([]);
  });

  it('covers every dataset the engine knows', () => {
    const produced = new Set(bundle.manifest.files.map((f) => f.datasetId));
    const missing = listDatasetDefinitions()
      .map((d) => d.id)
      .filter((id) => !produced.has(id));
    expect(missing).toEqual([]);
    for (const definition of listDatasetDefinitions()) {
      expect(bundle.datasets.has(definition.id), definition.id).toBe(true);
    }
  });

  it('writes schema-valid data for every usable dataset', () => {
    for (const check of bundle.files) {
      const status = check.collectionStatus;
      expect(status, check.path).not.toBeNull();
      if (status !== null && isUsableCollectionStatus(status)) {
        expect({ path: check.path, schema: check.schema, messages: check.messages }).toEqual({
          path: check.path,
          schema: 'valid',
          messages: [],
        });
      } else {
        expect(check.schema, check.path).toBe('not-checked');
      }
    }
  });

  it('reports the intended statuses for the licence, permission and option cases', () => {
    for (const entry of bundle.manifest.files) {
      const expected = EXPECTED_NON_SUCCESS[entry.datasetId] ?? 'Success';
      expect({ id: entry.datasetId, status: entry.status }).toEqual({
        id: entry.datasetId,
        status: expected,
      });
    }
  });

  it('assesses without ERROR results', () => {
    const result = runAssessment(bundle, CONTROL_LIBRARY, {
      processedAt: new Date('2026-09-19T00:00:00Z'),
    });
    const errors = result.results.filter((r) => r.status === 'ERROR').map((r) => r.controlId);
    expect(errors).toEqual([]);
    expect(result.results.length).toBe(CONTROL_LIBRARY.length);
    // The replayed evidence is actually evaluated: a control may be NOT_ASSESSED only
    // when it depends on a dataset the scenario intentionally leaves unusable
    // (Unauthorized / NotCollected / Failed), never because valid evidence was ignored.
    const unusable = new Set(
      result.evidence.datasets
        .filter((d) => d.state === 'unavailable' && d.collectionStatus !== 'NotApplicable')
        .map((d) => d.datasetId),
    );
    expect(unusable.size).toBeGreaterThan(0);
    for (const r of result.results.filter((x) => x.status === 'NOT_ASSESSED')) {
      expect(r.evidence.some((e) => unusable.has(e.datasetId)), `${r.controlId} is NOT_ASSESSED without an unusable dataset`).toBe(true);
    }
    expect(result.evidence.integrityVerified).toBe(true);
  });
});
