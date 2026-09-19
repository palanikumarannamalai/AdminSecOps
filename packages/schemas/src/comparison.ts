import { z } from 'zod';
import { ControlStatusSchema, GuidSchema, SeveritySchema, TimestampSchema } from './common.js';

export const FindingChangeSchema = z.object({
  findingKey: z.string(),
  controlId: z.string(),
  title: z.string(),
  severity: SeveritySchema,
  changes: z.array(
    z.object({
      field: z.enum(['status', 'severity', 'affectedObjectCount', 'affectedObjects', 'controlVersion']),
      from: z.union([z.string(), z.number()]),
      to: z.union([z.string(), z.number()]),
    }),
  ),
  addedObjects: z.array(z.string()),
  removedObjects: z.array(z.string()),
});

export const ComparisonFindingRefSchema = z.object({
  findingKey: z.string(),
  controlId: z.string(),
  title: z.string(),
  severity: SeveritySchema,
  status: z.enum(['FAIL', 'REVIEW']),
  /**
   * Status of the control in the other assessment. For a new finding, NOT_ASSESSED
   * means the issue was newly *observed* (evidence newly collected) rather than a
   * configuration regression.
   */
  otherStatus: ControlStatusSchema.nullable(),
});

/**
 * Comparison of two assessments of the same environment (baseline -> current).
 * Only results are compared; raw evidence is not needed.
 */
export const AssessmentComparisonSchema = z.object({
  baseline: z.object({ assessmentId: GuidSchema, assessedAt: TimestampSchema }),
  current: z.object({ assessmentId: GuidSchema, assessedAt: TimestampSchema }),
  sameEnvironment: z.boolean(),
  newFindings: z.array(ComparisonFindingRefSchema),
  resolvedFindings: z.array(ComparisonFindingRefSchema),
  changedFindings: z.array(FindingChangeSchema),
  unchangedFindingCount: z.number().int().nonnegative(),
  controlStatusChanges: z.array(
    z.object({
      controlId: z.string(),
      title: z.string(),
      from: ControlStatusSchema.nullable(),
      to: ControlStatusSchema.nullable(),
    }),
  ),
  /**
   * improved: findings resolved and none new; regressed: new findings and none resolved;
   * mixed: both; unchanged: neither. Coverage changes are reported separately.
   */
  direction: z.enum(['improved', 'regressed', 'mixed', 'unchanged']),
});
export type AssessmentComparison = z.infer<typeof AssessmentComparisonSchema>;
