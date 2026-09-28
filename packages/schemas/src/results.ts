import { z } from 'zod';
import {
  CollectionMessageSchema,
  CollectionStatusSchema,
  CollectorModuleSchema,
  ConfidenceSchema,
  ControlStatusSchema,
  GuidSchema,
  SeveritySchema,
  TechnologySchema,
  TimestampSchema,
  VersionSchema,
} from './common.js';
import {
  ControlIdSchema,
  EffortSchema,
  FrameworkMappingSchema,
  ReferenceSchema,
  RemediationSchema,
} from './control.js';
import { EvidenceSourceSchema, ManifestEnvironmentSchema, ManifestModuleSchema } from './evidence.js';

/** Maximum affected objects stored per result; the full count is kept in affectedObjectCount. */
export const MAX_AFFECTED_OBJECTS = 500;

export const AffectedObjectSchema = z.object({
  /** e.g. user, servicePrincipal, conditionalAccessPolicy, storageAccount, gpo, certificateTemplate */
  type: z.string().min(1).max(100),
  /** Stable identifier within the environment (object ID, resource ID, SID, DN, name). */
  id: z.string().min(1).max(1000),
  name: z.string().max(500),
  /** Why this object is affected, e.g. "Client secret valid for 730 days". */
  detail: z.string().max(1000).optional(),
});
export type AffectedObject = z.infer<typeof AffectedObjectSchema>;

export const ObservedFactSchema = z.object({
  label: z.string().max(200),
  value: z.union([z.string().max(2000), z.number(), z.boolean(), z.null()]),
});
export type ObservedFact = z.infer<typeof ObservedFactSchema>;

export const EvidenceReferenceSchema = z.object({
  datasetId: z.string(),
  path: z.string().nullable(),
  sha256: z.string().nullable(),
  collectedAt: TimestampSchema.nullable(),
  status: CollectionStatusSchema.nullable(),
  source: EvidenceSourceSchema.nullable(),
});
export type EvidenceReference = z.infer<typeof EvidenceReferenceSchema>;

export const ControlResultSchema = z.object({
  controlId: ControlIdSchema,
  controlVersion: VersionSchema,
  title: z.string(),
  technology: TechnologySchema,
  category: z.string(),
  subcategory: z.string(),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  status: ControlStatusSchema,
  /** Plain-language reason for the status (never contains secrets). */
  statusReason: z.string().max(2000),
  observed: z.object({
    summary: z.string().max(2000),
    facts: z.array(ObservedFactSchema).max(50),
  }),
  expected: z.string(),
  affectedObjects: z.array(AffectedObjectSchema).max(MAX_AFFECTED_OBJECTS),
  affectedObjectCount: z.number().int().nonnegative(),
  evidence: z.array(EvidenceReferenceSchema),
  notes: z.array(z.string().max(2000)).max(20),
});
export type ControlResult = z.infer<typeof ControlResultSchema>;

export const PRIORITY_TIERS = ['fix-now', 'fix-next', 'plan', 'review'] as const;
export const PriorityTierSchema = z.enum(PRIORITY_TIERS);
export type PriorityTier = z.infer<typeof PriorityTierSchema>;

export const PrioritySchema = z.object({
  /** 1 = fix first. Unique within an assessment. */
  rank: z.number().int().positive(),
  tier: PriorityTierSchema,
  /** Deterministic sort key; see docs/CONTROL-MODEL.md "Prioritization". Not a security score. */
  sortKey: z.number(),
  factors: z.array(z.string().max(300)).max(20),
});
export type Priority = z.infer<typeof PrioritySchema>;

export const FindingSchema = z.object({
  findingId: z.string(),
  /** Stable across assessments of the same environment; used for comparison. */
  findingKey: z.string(),
  assessmentId: GuidSchema,
  controlId: ControlIdSchema,
  controlVersion: VersionSchema,
  status: z.enum(['FAIL', 'REVIEW']),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  technology: TechnologySchema,
  category: z.string(),
  title: z.string(),
  description: z.string(),
  observedState: z.object({
    summary: z.string(),
    facts: z.array(ObservedFactSchema),
  }),
  expectedState: z.string(),
  affectedObjects: z.array(AffectedObjectSchema),
  affectedObjectCount: z.number().int().nonnegative(),
  evidence: z.array(EvidenceReferenceSchema),
  risk: z.string(),
  remediation: RemediationSchema,
  implementationConsiderations: z.array(z.string()),
  impact: z.string(),
  rollback: z.array(z.string()),
  validation: z.array(z.string()),
  references: z.array(ReferenceSchema),
  frameworkMappings: z.array(FrameworkMappingSchema),
  tags: z.array(z.string()),
  effort: EffortSchema,
  notes: z.array(z.string()),
  priority: PrioritySchema,
});
export type Finding = z.infer<typeof FindingSchema>;

export const EvidenceFileCheckSchema = z.object({
  path: z.string(),
  datasetId: z.string().nullable(),
  module: CollectorModuleSchema.nullable(),
  /** verified: hash matches and content validated; see message otherwise */
  integrity: z.enum(['verified', 'hash-mismatch', 'missing', 'unlisted', 'size-mismatch']),
  schema: z.enum(['valid', 'invalid', 'unknown-dataset', 'not-checked']),
  sensitiveContent: z.boolean(),
  collectionStatus: CollectionStatusSchema.nullable(),
  sha256: z.string().nullable(),
  expectedSha256: z.string().nullable(),
  sizeBytes: z.number().int().nonnegative().nullable(),
  messages: z.array(z.string().max(1000)).max(50),
});
export type EvidenceFileCheck = z.infer<typeof EvidenceFileCheckSchema>;

export const CollectionIssueSchema = CollectionMessageSchema.extend({
  level: z.enum(['error', 'warning']),
  module: CollectorModuleSchema.nullable(),
  datasetId: z.string().nullable(),
  origin: z.enum(['collector', 'ingestion']),
});
export type CollectionIssue = z.infer<typeof CollectionIssueSchema>;

export const InventoryItemSchema = z.object({
  technology: TechnologySchema,
  key: z.string(),
  label: z.string(),
  /** null when the underlying dataset was not available */
  count: z.number().int().nonnegative().nullable(),
  datasetId: z.string(),
});
export type InventoryItem = z.infer<typeof InventoryItemSchema>;

export const DatasetAvailabilitySchema = z.object({
  datasetId: z.string(),
  title: z.string(),
  technology: TechnologySchema,
  module: CollectorModuleSchema,
  state: z.enum(['available', 'partial', 'unavailable']),
  gapCategory: z.enum(['not-connected', 'permission', 'licence', 'failed', 'not-collected', 'unsupported', 'partial']).nullable().optional(),
  collectionStatus: CollectionStatusSchema.nullable(),
  reason: z.string().max(1000),
});
export type DatasetAvailability = z.infer<typeof DatasetAvailabilitySchema>;

const StatusCountsSchema = z.object({
  PASS: z.number().int().nonnegative(),
  FAIL: z.number().int().nonnegative(),
  REVIEW: z.number().int().nonnegative(),
  NOT_APPLICABLE: z.number().int().nonnegative(),
  NOT_ASSESSED: z.number().int().nonnegative(),
  ERROR: z.number().int().nonnegative(),
});
export type StatusCounts = z.infer<typeof StatusCountsSchema>;

const SeverityCountsSchema = z.object({
  critical: z.number().int().nonnegative(),
  high: z.number().int().nonnegative(),
  medium: z.number().int().nonnegative(),
  low: z.number().int().nonnegative(),
  informational: z.number().int().nonnegative(),
});
export type SeverityCounts = z.infer<typeof SeverityCountsSchema>;

export const AssessmentSummarySchema = z.object({
  controlsEvaluated: z.number().int().nonnegative(),
  byStatus: StatusCountsSchema,
  findingsBySeverity: SeverityCountsSchema,
  byTechnology: z.record(TechnologySchema, StatusCountsSchema),
  /**
   * Share of assessable controls (PASS+FAIL+REVIEW) out of applicable controls. A
   * coverage indicator, not a security score. See docs/CONTROL-MODEL.md.
   */
  assessmentCoverage: z.object({
    assessed: z.number().int().nonnegative(),
    applicable: z.number().int().nonnegative(),
  }),
});
export type AssessmentSummary = z.infer<typeof AssessmentSummarySchema>;

export const AssessmentResultSchema = z.object({
  resultSchemaVersion: z.literal('1.0'),
  engineVersion: VersionSchema,
  controlLibraryVersion: VersionSchema,
  assessmentId: GuidSchema,
  /** When the collector created the evidence package (the point in time assessed). */
  assessedAt: TimestampSchema,
  /** When the engine processed the evidence. */
  processedAt: TimestampSchema,
  collection: z.object({
    collector: z.object({
      name: z.string(),
      version: z.string(),
      powershellVersion: z.string().nullable(),
      platform: z.string().nullable(),
    }),
    environment: ManifestEnvironmentSchema,
    options: z.record(z.string(), z.unknown()),
    modules: z.array(ManifestModuleSchema),
    manifestSha256: z.string(),
  }),
  evidence: z.object({
    integrityVerified: z.boolean(),
    files: z.array(EvidenceFileCheckSchema),
    datasets: z.array(DatasetAvailabilitySchema),
    issues: z.array(CollectionIssueSchema),
  }),
  inventory: z.array(InventoryItemSchema),
  summary: AssessmentSummarySchema,
  results: z.array(ControlResultSchema),
  findings: z.array(FindingSchema),
});
export type AssessmentResult = z.infer<typeof AssessmentResultSchema>;
