import { CONTROL_LIBRARY, type ControlDefinition } from '@adminsecops/controls';
import {
  DEFAULT_PACKAGE_LIMITS,
  loadEvidenceBundle,
  readDirectoryPackage,
  readZipPackage,
  type PackageLimits,
} from '@adminsecops/evidence';
import type { AssessmentResult } from '@adminsecops/schemas';
import { runAssessment, type AssessmentOptions } from './assess.js';

export interface PipelineOptions extends AssessmentOptions {
  limits?: PackageLimits;
  controls?: readonly ControlDefinition[];
}

/** ZIP bytes -> verified evidence -> inventory -> controls -> findings. */
export async function assessZip(archive: Buffer, options: PipelineOptions = {}): Promise<AssessmentResult> {
  const files = await readZipPackage(archive, options.limits ?? DEFAULT_PACKAGE_LIMITS);
  return runAssessment(loadEvidenceBundle(files), options.controls ?? CONTROL_LIBRARY, options);
}

/** Extracted evidence directory -> verified evidence -> inventory -> controls -> findings. */
export async function assessDirectory(directory: string, options: PipelineOptions = {}): Promise<AssessmentResult> {
  const files = await readDirectoryPackage(directory, options.limits ?? DEFAULT_PACKAGE_LIMITS);
  return runAssessment(loadEvidenceBundle(files), options.controls ?? CONTROL_LIBRARY, options);
}
