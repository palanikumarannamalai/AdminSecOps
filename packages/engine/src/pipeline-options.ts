import type { ControlDefinition } from '@adminsecops/controls';
import type { PackageLimits } from '@adminsecops/evidence/browser';
import type { AssessmentOptions } from './assess.js';

export interface PipelineOptions extends AssessmentOptions {
  limits?: PackageLimits;
  controls?: readonly ControlDefinition[];
}
