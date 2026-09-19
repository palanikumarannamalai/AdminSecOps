import { z } from 'zod';
import { SUPPORTED_EVIDENCE_SCHEMA_VERSIONS, SUPPORTED_MANIFEST_VERSIONS } from '@adminsecops/core';
import {
  CollectionMessageSchema,
  CollectionStatusSchema,
  CollectorModuleSchema,
  GuidSchema,
  Sha256Schema,
  TimestampSchema,
  VersionSchema,
  list,
  optString,
} from './common.js';

/** Identifies the collector build that produced evidence. */
export const CollectorIdentitySchema = z.object({
  name: z.string().min(1).max(200),
  version: VersionSchema,
});

/**
 * Where evidence came from. `operations` lists the read operations performed, e.g.
 * "GET https://graph.microsoft.com/v1.0/policies/authorizationPolicy" or
 * "Get-OrganizationConfig". It must never contain tokens or query secrets.
 */
export const EvidenceSourceSchema = z.object({
  system: z.enum([
    'MicrosoftGraph',
    'ExchangeOnline',
    'AzureResourceManager',
    'ActiveDirectory',
    'GroupPolicy',
    'WindowsHost',
    'DNS',
    'Other',
  ]),
  operations: z.array(z.string().max(2000)).max(200),
  apiVersion: optString,
});
export type EvidenceSource = z.infer<typeof EvidenceSourceSchema>;

/**
 * Envelope of one evidence file (one dataset). The `data` payload is validated
 * separately against the dataset's schema (see datasets/registry.ts).
 */
export const EvidenceEnvelopeSchema = z.object({
  schemaVersion: z.enum(SUPPORTED_EVIDENCE_SCHEMA_VERSIONS),
  datasetId: z.string().regex(/^[a-z0-9]+\.[A-Za-z0-9]+$/, 'Dataset IDs look like module.datasetName'),
  assessmentId: GuidSchema,
  collector: CollectorIdentitySchema.extend({
    module: CollectorModuleSchema,
    moduleVersion: VersionSchema,
  }),
  collectedAt: TimestampSchema,
  source: EvidenceSourceSchema,
  status: CollectionStatusSchema,
  errors: list(CollectionMessageSchema),
  warnings: list(CollectionMessageSchema),
  data: z.unknown(),
});
export type EvidenceEnvelope = z.infer<typeof EvidenceEnvelopeSchema>;

export const PrerequisiteCheckSchema = z.object({
  name: z.string().max(200),
  satisfied: z.boolean(),
  detail: optString,
});

export const ManifestModuleSchema = z.object({
  name: CollectorModuleSchema,
  version: VersionSchema,
  status: z.enum(['Completed', 'CompletedWithErrors', 'Failed', 'Skipped']),
  startedAt: TimestampSchema.nullish().transform((v) => v ?? null),
  completedAt: TimestampSchema.nullish().transform((v) => v ?? null),
  prerequisites: list(PrerequisiteCheckSchema),
  errors: list(CollectionMessageSchema),
  warnings: list(CollectionMessageSchema),
});
export type ManifestModule = z.infer<typeof ManifestModuleSchema>;

/** Relative path inside the package: forward slashes, no traversal, limited charset. */
export const PackagePathSchema = z
  .string()
  .max(260)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*){0,5}$/, 'Invalid package path')
  .refine((p) => !p.split('/').some((segment) => segment === '.' || segment === '..'), 'Invalid package path');

export const ManifestFileSchema = z.object({
  path: PackagePathSchema,
  datasetId: z.string().regex(/^[a-z0-9]+\.[A-Za-z0-9]+$/),
  module: CollectorModuleSchema,
  sha256: Sha256Schema,
  sizeBytes: z.number().int().nonnegative(),
  schemaVersion: z.enum(SUPPORTED_EVIDENCE_SCHEMA_VERSIONS),
  status: CollectionStatusSchema,
  collectedAt: TimestampSchema,
});
export type ManifestFile = z.infer<typeof ManifestFileSchema>;

/**
 * Environment identification. Values are optional because a partial collection
 * (e.g. AD only) may not know the tenant. Only identifiers, never credentials.
 */
export const ManifestEnvironmentSchema = z.object({
  label: optString,
  tenantId: GuidSchema.nullish().transform((v) => v ?? null),
  tenantDisplayName: optString,
  primaryDomain: optString,
  adForestName: optString,
  adDomainName: optString,
});
export type ManifestEnvironment = z.infer<typeof ManifestEnvironmentSchema>;

export const EvidenceManifestSchema = z.object({
  manifestVersion: z.enum(SUPPORTED_MANIFEST_VERSIONS),
  product: z.literal('AdminSecOps'),
  assessmentId: GuidSchema,
  createdAt: TimestampSchema,
  collector: CollectorIdentitySchema.extend({
    powershellVersion: optString,
    platform: optString,
  }),
  environment: ManifestEnvironmentSchema,
  options: z
    .record(z.string().max(100), z.union([z.string().max(500), z.number(), z.boolean(), z.array(z.string().max(200)).max(50)]))
    .nullish()
    .transform((v) => v ?? {}),
  modules: z.array(ManifestModuleSchema).max(50),
  files: z.array(ManifestFileSchema).max(2000),
});
export type EvidenceManifest = z.infer<typeof EvidenceManifestSchema>;

export const MANIFEST_FILE_NAME = 'evidence-manifest.json';
