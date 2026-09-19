import { z } from 'zod';
import {
  COLLECTION_STATUSES,
  COLLECTOR_MODULES,
  CONFIDENCES,
  CONTROL_STATUSES,
  SEVERITIES,
  TECHNOLOGIES,
} from '@adminsecops/core';

export const ControlStatusSchema = z.enum(CONTROL_STATUSES);
export const SeveritySchema = z.enum(SEVERITIES);
export const ConfidenceSchema = z.enum(CONFIDENCES);
export const TechnologySchema = z.enum(TECHNOLOGIES);
export const CollectionStatusSchema = z.enum(COLLECTION_STATUSES);
export const CollectorModuleSchema = z.enum(COLLECTOR_MODULES);

const ISO_TIMESTAMP =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

/**
 * ISO-8601 timestamp with an explicit offset. PowerShell's round-trip format ("o")
 * produces seven fractional digits, which is accepted.
 */
export const TimestampSchema = z
  .string()
  .regex(ISO_TIMESTAMP, 'Expected an ISO-8601 timestamp with a time zone offset')
  .refine((value) => !Number.isNaN(Date.parse(value)), 'Invalid timestamp');

/** GUID in 8-4-4-4-12 form. Graph/ARM identifiers do not always satisfy RFC 4122 variant bits. */
export const GuidSchema = z
  .string()
  .regex(/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/, 'Expected a GUID');

export const Sha256Schema = z.string().regex(/^[a-f0-9]{64}$/, 'Expected a lower-case hex SHA-256');

/** Semantic-ish version string, e.g. 0.1.0 or 1.2.3-preview.1 */
export const VersionSchema = z.string().regex(/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/, 'Expected a version such as 1.0.0');

/** Array that tolerates `null` / missing from Microsoft APIs and normalises to []. */
export function list<T extends z.ZodType>(item: T) {
  return z
    .array(item)
    .nullish()
    .transform((value) => value ?? []);
}

/** String that Microsoft APIs may return as null or omit. */
export const optString = z.string().nullish().transform((v) => v ?? null);
export const optBool = z.boolean().nullish().transform((v) => v ?? null);
export const optNumber = z.number().nullish().transform((v) => v ?? null);
export const optTimestamp = TimestampSchema.nullish().transform((v) => v ?? null);

/** Collector-reported error or warning. Messages must not contain evidence values or secrets. */
export const CollectionMessageSchema = z.object({
  code: z.string().min(1).max(200),
  message: z.string().max(4000),
  target: z.string().max(1000).nullish().transform((v) => v ?? null),
});
export type CollectionMessage = z.infer<typeof CollectionMessageSchema>;
