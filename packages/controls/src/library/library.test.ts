import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { evaluateControl } from '@adminsecops/engine';
import { createInventoryFromData } from '@adminsecops/inventory';
import type { DatasetId } from '@adminsecops/schemas';
import { CONTROL_LIBRARY } from './index.js';

const libraryDir = path.dirname(fileURLToPath(import.meta.url));

function testSources(dir: string): string {
  let text = '';
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) text += testSources(full);
    else if (entry.endsWith('.test.ts') && entry !== 'library.test.ts') text += readFileSync(full, 'utf8');
  }
  return text;
}

describe('control library invariants', () => {
  it('contains controls with unique IDs', () => {
    const ids = CONTROL_LIBRARY.map((c) => c.metadata.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('has a dedicated test referencing every control ID', () => {
    const sources = testSources(libraryDir);
    const untested = CONTROL_LIBRARY.map((c) => c.metadata.id).filter((id) => !sources.includes(id));
    expect(untested).toEqual([]);
  });

  it('files each control under the directory of its technology', () => {
    // The technology index files are the only place controls are registered, so a
    // control's ID prefix must be consistent with its technology.
    for (const control of CONTROL_LIBRARY) {
      expect(control.metadata.id.split('-')[0]).toMatch(/^[A-Z0-9]+$/);
    }
  });

  describe.each(CONTROL_LIBRARY.map((c) => [c.metadata.id, c] as const))('%s', (_id, control) => {
    it('is NOT_ASSESSED when no evidence was collected (never PASS)', () => {
      const result = evaluateControl(control, createInventoryFromData({}));
      expect(result.status).toBe('NOT_ASSESSED');
      expect(result.statusReason.length).toBeGreaterThan(0);
    });

    it('is NOT_ASSESSED when required evidence collection failed', () => {
      const unavailable = Object.fromEntries(control.metadata.requiredEvidence.map((id) => [id, 'Failed'])) as Partial<
        Record<DatasetId, 'Failed'>
      >;
      const result = evaluateControl(control, createInventoryFromData({}, { unavailable }));
      expect(result.status).toBe('NOT_ASSESSED');
    });

    it('is NOT_APPLICABLE when the collector reported all required evidence as not applicable', () => {
      const unavailable = Object.fromEntries(
        control.metadata.requiredEvidence.map((id) => [id, 'NotApplicable']),
      ) as Partial<Record<DatasetId, 'NotApplicable'>>;
      const result = evaluateControl(control, createInventoryFromData({}, { unavailable }));
      expect(result.status).toBe('NOT_APPLICABLE');
    });

    it('has complete administrator guidance', () => {
      const meta = control.metadata;
      expect(meta.references.length).toBeGreaterThan(0);
      expect(meta.remediation.steps.length).toBeGreaterThan(0);
      expect(meta.rollback.length).toBeGreaterThan(0);
      expect(meta.validation.length).toBeGreaterThan(0);
      expect(meta.references.every((r) => r.url.startsWith('https://'))).toBe(true);
    });
  });
});
