import { z } from 'zod';
import { ConfidenceSchema, SeveritySchema, TechnologySchema, VersionSchema } from './common.js';

/** Control identifiers look like ENTRA-CA-001, AD-KRB-002, ADCS-TPL-001. */
export const ControlIdSchema = z
  .string()
  .regex(/^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$/, 'Control IDs look like ENTRA-CA-001');

export const REFERENCE_PUBLISHERS = ['Microsoft', 'NIST', 'CISA', 'MITRE', 'CIS', 'Other'] as const;

export const ReferenceSchema = z.object({
  title: z.string().min(3).max(300),
  url: z
    .url()
    .max(1000)
    .refine((u) => u.startsWith('https://'), 'References must use https'),
  publisher: z.enum(REFERENCE_PUBLISHERS),
});
export type Reference = z.infer<typeof ReferenceSchema>;

/**
 * Framework identifiers. Only identifiers are stored; framework text is not copied
 * (see docs/CONTROL-MODEL.md, "Framework mappings").
 */
export const FRAMEWORKS = {
  'NIST-800-53r5': 'NIST SP 800-53 Rev. 5',
  'CISA-SCuBA': 'CISA Secure Cloud Business Applications (SCuBA) baselines',
  'MITRE-ATTACK': 'MITRE ATT&CK (Enterprise)',
  MCSB: 'Microsoft cloud security benchmark',
} as const;
export type FrameworkId = keyof typeof FRAMEWORKS;
export const FrameworkIdSchema = z.enum(Object.keys(FRAMEWORKS) as [FrameworkId, ...FrameworkId[]]);

export const FrameworkMappingSchema = z.object({
  framework: FrameworkIdSchema,
  id: z.string().min(1).max(50),
  /** Optional clarification, e.g. "partial: covers administrators only" */
  note: z.string().max(300).optional(),
});
export type FrameworkMapping = z.infer<typeof FrameworkMappingSchema>;

export const EffortSchema = z.enum(['low', 'medium', 'high']);

export const RemediationSchema = z.object({
  summary: z.string().min(10).max(1000),
  steps: z.array(z.string().min(3).max(2000)).min(1).max(30),
  /** Example commands for the administrator to review and run themselves. AdminSecOps never executes them. */
  scriptExample: z.string().max(4000).optional(),
  effort: EffortSchema,
});
export type Remediation = z.infer<typeof RemediationSchema>;

export const ControlParameterValueSchema = z.union([z.number(), z.string(), z.boolean()]);

/**
 * Serializable metadata of a control. The evaluation logic itself lives in code
 * (packages/controls) and is described in `evaluation.logic` for administrators.
 */
export const ControlMetadataSchema = z.object({
  id: ControlIdSchema,
  version: VersionSchema,
  lifecycle: z.enum(['stable', 'preview', 'deprecated']),
  title: z.string().min(10).max(200),
  technology: TechnologySchema,
  category: z.string().min(2).max(100),
  subcategory: z.string().min(2).max(100),
  description: z.string().min(20).max(2000),
  rationale: z.string().min(20).max(3000),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  applicability: z.object({
    description: z.string().min(5).max(1000),
  }),
  requiredEvidence: z.array(z.string().regex(/^[a-z0-9]+\.[A-Za-z0-9]+$/)).min(1).max(20),
  optionalEvidence: z.array(z.string().regex(/^[a-z0-9]+\.[A-Za-z0-9]+$/)).max(20).default([]),
  evaluation: z.object({
    logic: z.string().min(20).max(3000),
    parameters: z.record(z.string(), ControlParameterValueSchema).default({}),
  }),
  expectedState: z.string().min(10).max(1000),
  remediation: RemediationSchema,
  implementationConsiderations: z.array(z.string().min(5).max(2000)).min(1).max(20),
  impact: z.string().min(10).max(2000),
  rollback: z.array(z.string().min(3).max(2000)).min(1).max(20),
  validation: z.array(z.string().min(3).max(2000)).min(1).max(20),
  references: z.array(ReferenceSchema).min(1).max(20),
  frameworkMappings: z.array(FrameworkMappingSchema).max(40),
  tags: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]*$/)).max(20),
});
export type ControlMetadata = z.output<typeof ControlMetadataSchema>;
export type ControlMetadataInput = z.input<typeof ControlMetadataSchema>;
