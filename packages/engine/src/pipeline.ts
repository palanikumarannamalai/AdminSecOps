import { CONTROL_LIBRARY } from '@adminsecops/controls';
import { DEFAULT_PACKAGE_LIMITS, loadEvidenceBundle, readDirectoryPackage, readZipPackage } from '@adminsecops/evidence';
import type { AssessmentResult } from '@adminsecops/schemas';
import { runAssessment } from './assess.js';
import type { PipelineOptions } from './pipeline-options.js';

/** ZIP bytes -> verified evidence -> inventory -> controls -> findings (Node.js reader). */
export async function assessZip(archive: Uint8Array, options: PipelineOptions = {}): Promise<AssessmentResult> {
  const files = await readZipPackage(Buffer.from(archive.buffer, archive.byteOffset, archive.byteLength), options.limits ?? DEFAULT_PACKAGE_LIMITS);
  return runAssessment(loadEvidenceBundle(files), options.controls ?? CONTROL_LIBRARY, options);
}

/** Extracted evidence directory -> verified evidence -> inventory -> controls -> findings. */
export async function assessDirectory(directory: string, options: PipelineOptions = {}): Promise<AssessmentResult> {
  const files = await readDirectoryPackage(directory, options.limits ?? DEFAULT_PACKAGE_LIMITS);
  return runAssessment(loadEvidenceBundle(files), options.controls ?? CONTROL_LIBRARY, options);
}
