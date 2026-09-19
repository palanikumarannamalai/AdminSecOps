/*
 * Browser-safe entry point (hosted mode). Identical evaluation semantics to the Node.js pipeline:
 * the same ZIP limits, integrity verification, secret rejection, schema validation, control
 * library, prioritisation and comparison. Only file-system access is absent.
 */
import { CONTROL_LIBRARY } from '@adminsecops/controls';
import { DEFAULT_PACKAGE_LIMITS, loadEvidenceBundle, readZipBytes, type PackageFiles } from '@adminsecops/evidence/browser';
import type { AssessmentResult } from '@adminsecops/schemas';
import { runAssessment } from './assess.js';
import type { PipelineOptions } from './pipeline-options.js';

export * from './evaluate.js';
export * from './prioritize.js';
export * from './assess.js';
export * from './compare.js';
export type { PipelineOptions } from './pipeline-options.js';

/** ZIP bytes -> verified evidence -> inventory -> controls -> findings (in memory). */
export function assessZipBytes(archive: Uint8Array, options: PipelineOptions = {}): AssessmentResult {
  const files = readZipBytes(archive, options.limits ?? DEFAULT_PACKAGE_LIMITS);
  return runAssessment(loadEvidenceBundle(files), options.controls ?? CONTROL_LIBRARY, options);
}

/** Already-extracted package files (e.g. bundled sample data) -> assessment. */
export function assessPackageFiles(files: PackageFiles, options: PipelineOptions = {}): AssessmentResult {
  return runAssessment(loadEvidenceBundle(files), options.controls ?? CONTROL_LIBRARY, options);
}
