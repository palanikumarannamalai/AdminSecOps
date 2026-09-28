import {
  AdminSecOpsError,
  findSensitiveContent,
  isUsableCollectionStatus,
  safeJsonParse,
  sha256Hex,
  type CollectionStatus,
  type CollectorModule,
} from '@adminsecops/core';
import {
  EvidenceEnvelopeSchema,
  EvidenceManifestSchema,
  MANIFEST_FILE_NAME,
  getDatasetDefinition,
  type CollectionIssue,
  type DatasetDefinition,
  type EvidenceEnvelope,
  type EvidenceFileCheck,
  type EvidenceManifest,
  type EvidenceReference,
  type ManifestFile,
} from '@adminsecops/schemas';
import type { z } from 'zod';
import type { PackageFiles } from './paths.js';

export type DatasetState = 'available' | 'partial' | 'unavailable';

/** A dataset loaded from the package, validated against its schema when usable. */
export interface LoadedDataset {
  readonly datasetId: string;
  readonly definition: DatasetDefinition;
  readonly state: DatasetState;
  /** Why the dataset is partial/unavailable; for available datasets a short confirmation. */
  readonly reason: string;
  readonly collectionStatus: CollectionStatus | null;
  /** Validated payload; null unless state is available or partial. */
  readonly data: unknown;
  readonly reference: EvidenceReference;
}

export interface EvidenceBundle {
  readonly manifest: EvidenceManifest;
  readonly manifestSha256: string;
  readonly integrityVerified: boolean;
  readonly files: readonly EvidenceFileCheck[];
  readonly datasets: ReadonlyMap<string, LoadedDataset>;
  readonly issues: readonly CollectionIssue[];
}

const IGNORED_PREFIXES = ['logs/'];
const MAX_VALIDATION_MESSAGES = 10;

/**
 * Verify and load an evidence package that has already been read into memory.
 *
 * Integrity rules (see docs/EVIDENCE-MODEL.md):
 * - the manifest must exist and be valid, otherwise the package is rejected;
 * - every manifest entry must exist and match its SHA-256 and size, otherwise that
 *   dataset is unavailable (it is never partially trusted);
 * - files containing secret material are rejected;
 * - each envelope must agree with its manifest entry;
 * - payloads are validated against the dataset schema, unknown properties stripped.
 */
export function loadEvidenceBundle(files: PackageFiles): EvidenceBundle {
  const manifestBytes = files.get(MANIFEST_FILE_NAME);
  if (manifestBytes === undefined) {
    throw new AdminSecOpsError('MANIFEST_MISSING', `The evidence package does not contain ${MANIFEST_FILE_NAME}.`);
  }
  const manifestJson = safeJsonParse(manifestBytes, { label: MANIFEST_FILE_NAME, maxBytes: 5 * 1024 * 1024 });
  const manifestResult = EvidenceManifestSchema.safeParse(manifestJson);
  if (!manifestResult.success) {
    throw new AdminSecOpsError('MANIFEST_INVALID', `${MANIFEST_FILE_NAME} does not match the expected schema.`, {
      internalDetail: summarizeZodIssues(manifestResult.error).join('; '),
    });
  }
  const manifest = manifestResult.data;
  const manifestSha256 = sha256Hex(manifestBytes);

  const issues: CollectionIssue[] = [];
  const fileChecks: EvidenceFileCheck[] = [];
  const datasets = new Map<string, LoadedDataset>();

  for (const module of manifest.modules) {
    for (const error of module.errors) issues.push({ ...error, level: 'error', module: module.name, datasetId: null, origin: 'collector' });
    for (const warning of module.warnings) issues.push({ ...warning, level: 'warning', module: module.name, datasetId: null, origin: 'collector' });
  }

  const listedPaths = new Set<string>();
  for (const entry of manifest.files) {
    if (listedPaths.has(entry.path)) {
      issues.push(ingestionIssue('error', entry.module, entry.datasetId, 'MANIFEST_DUPLICATE_PATH', `The manifest lists ${entry.path} more than once; the duplicate was ignored.`));
      continue;
    }
    listedPaths.add(entry.path);
    const { check, dataset } = loadManifestEntry(entry, files.get(entry.path), manifest, issues);
    fileChecks.push(check);
    if (dataset === undefined) continue;
    if (datasets.has(dataset.datasetId)) {
      issues.push(ingestionIssue('error', entry.module, entry.datasetId, 'DATASET_DUPLICATE', `Dataset ${entry.datasetId} appears in more than one file; only the first was used.`));
      continue;
    }
    datasets.set(dataset.datasetId, dataset);
  }

  for (const filePath of files.keys()) {
    if (filePath === MANIFEST_FILE_NAME || listedPaths.has(filePath)) continue;
    if (IGNORED_PREFIXES.some((prefix) => filePath.startsWith(prefix))) continue;
    fileChecks.push({
      path: filePath,
      datasetId: null,
      module: null,
      integrity: 'unlisted',
      schema: 'not-checked',
      sensitiveContent: false,
      collectionStatus: null,
      sha256: sha256Hex(files.get(filePath) ?? new Uint8Array(0)),
      expectedSha256: null,
      sizeBytes: files.get(filePath)?.byteLength ?? null,
      messages: ['File is not listed in the manifest and was ignored.'],
    });
    issues.push(ingestionIssue('warning', null, null, 'FILE_UNLISTED', `${filePath} is not listed in the manifest and was ignored.`));
  }

  const integrityVerified = fileChecks.every((check) => check.integrity === 'verified' || check.integrity === 'unlisted');
  return { manifest, manifestSha256, integrityVerified, files: fileChecks, datasets, issues };
}

function loadManifestEntry(
  entry: ManifestFile,
  content: Uint8Array | undefined,
  manifest: EvidenceManifest,
  issues: CollectionIssue[],
): { check: EvidenceFileCheck; dataset?: LoadedDataset } {
  const messages: string[] = [];
  const check: EvidenceFileCheck = {
    path: entry.path,
    datasetId: entry.datasetId,
    module: entry.module,
    integrity: 'verified',
    schema: 'not-checked',
    sensitiveContent: false,
    collectionStatus: entry.status,
    sha256: null,
    expectedSha256: entry.sha256,
    sizeBytes: null,
    messages,
  };
  const definition = getDatasetDefinition(entry.datasetId);
  const reference: EvidenceReference = {
    datasetId: entry.datasetId,
    path: entry.path,
    sha256: entry.sha256,
    collectedAt: entry.collectedAt,
    status: entry.status,
    source: null,
  };
  const unavailable = (reason: string): LoadedDataset | undefined =>
    definition === undefined
      ? undefined
      : { datasetId: entry.datasetId, definition, state: 'unavailable', reason, collectionStatus: entry.status, data: null, reference };

  if (content === undefined) {
    check.integrity = 'missing';
    messages.push('File listed in the manifest is missing from the package.');
    issues.push(ingestionIssue('error', entry.module, entry.datasetId, 'FILE_MISSING', `${entry.path} is listed in the manifest but missing.`));
    return { check, dataset: unavailable('Evidence file listed in the manifest is missing from the package.') };
  }

  const actualSha = sha256Hex(content);
  check.sha256 = actualSha;
  check.sizeBytes = content.byteLength;
  if (actualSha !== entry.sha256) {
    check.integrity = 'hash-mismatch';
    messages.push('SHA-256 does not match the manifest. The file was modified or corrupted after collection.');
    issues.push(ingestionIssue('error', entry.module, entry.datasetId, 'HASH_MISMATCH', `${entry.path} does not match its manifest SHA-256 and was not used.`));
    return { check, dataset: unavailable('Evidence file failed SHA-256 integrity verification and was not used.') };
  }
  if (content.byteLength !== entry.sizeBytes) {
    check.integrity = 'size-mismatch';
    messages.push('File size does not match the manifest.');
    issues.push(ingestionIssue('error', entry.module, entry.datasetId, 'SIZE_MISMATCH', `${entry.path} does not match its manifest size and was not used.`));
    return { check, dataset: unavailable('Evidence file size does not match the manifest.') };
  }

  let parsed: unknown;
  try {
    parsed = safeJsonParse(content, { label: entry.path });
  } catch (error) {
    check.schema = 'invalid';
    const message = error instanceof AdminSecOpsError ? error.message : 'File could not be parsed.';
    messages.push(message);
    issues.push(ingestionIssue('error', entry.module, entry.datasetId, 'FILE_UNPARSEABLE', message));
    return { check, dataset: unavailable('Evidence file could not be parsed as JSON.') };
  }

  const sensitive = findSensitiveContent(parsed);
  if (sensitive.length > 0) {
    check.sensitiveContent = true;
    check.schema = 'not-checked';
    const locations = sensitive.slice(0, 5).map((s) => `${s.path} (${s.description})`).join(', ');
    messages.push(`Secret-like content detected at ${locations}. The file was rejected and not used.`);
    issues.push(
      ingestionIssue(
        'error',
        entry.module,
        entry.datasetId,
        'SENSITIVE_CONTENT',
        `${entry.path} contains data that looks like secret material (${sensitive.length} location(s)) and was rejected. Delete the package and re-run the collector.`,
      ),
    );
    return { check, dataset: unavailable('Evidence file was rejected because it contained secret-like content.') };
  }

  const envelopeResult = EvidenceEnvelopeSchema.safeParse(parsed);
  if (!envelopeResult.success) {
    check.schema = 'invalid';
    const details = summarizeZodIssues(envelopeResult.error);
    messages.push(...details.map((d) => `Envelope: ${d}`));
    issues.push(ingestionIssue('error', entry.module, entry.datasetId, 'ENVELOPE_INVALID', `${entry.path} is not a valid evidence envelope.`));
    return { check, dataset: unavailable('Evidence envelope failed schema validation.') };
  }
  const envelope = envelopeResult.data;
  reference.source = envelope.source;

  const mismatch = envelopeMismatch(envelope, entry, manifest);
  if (mismatch !== undefined) {
    check.schema = 'invalid';
    messages.push(mismatch);
    issues.push(ingestionIssue('error', entry.module, entry.datasetId, 'ENVELOPE_MISMATCH', `${entry.path}: ${mismatch}`));
    return { check, dataset: unavailable(`Evidence envelope does not match the manifest: ${mismatch}`) };
  }

  for (const error of envelope.errors) issues.push({ ...error, level: 'error', module: entry.module, datasetId: entry.datasetId, origin: 'collector' });
  for (const warning of envelope.warnings) issues.push({ ...warning, level: 'warning', module: entry.module, datasetId: entry.datasetId, origin: 'collector' });

  if (definition === undefined) {
    check.schema = 'unknown-dataset';
    messages.push('Dataset is not known to this version of AdminSecOps and was ignored.');
    issues.push(ingestionIssue('warning', entry.module, entry.datasetId, 'DATASET_UNKNOWN', `Dataset ${entry.datasetId} is not known to this engine version and was ignored.`));
    return { check };
  }

  if (!isUsableCollectionStatus(envelope.status)) {
    check.schema = 'not-checked';
    const firstError = envelope.errors[0]?.message ?? envelope.warnings[0]?.message;
    const reason = `Collector reported status ${envelope.status}${firstError !== undefined ? `: ${firstError}` : '.'}`;
    return {
      check,
      dataset: { datasetId: entry.datasetId, definition, state: 'unavailable', reason, collectionStatus: envelope.status, data: null, reference },
    };
  }

  const dataResult = (definition.schema).safeParse(envelope.data);
  if (!dataResult.success) {
    check.schema = 'invalid';
    const details = summarizeZodIssues(dataResult.error);
    messages.push(...details.map((d) => `Data: ${d}`));
    issues.push(ingestionIssue('error', entry.module, entry.datasetId, 'DATA_INVALID', `${entry.path} data does not match the ${entry.datasetId} schema and was not used.`));
    return { check, dataset: unavailable('Evidence data failed schema validation.') };
  }

  check.schema = 'valid';
  const partial = envelope.status === 'Partial';
  return {
    check,
    dataset: {
      datasetId: entry.datasetId,
      definition,
      state: partial ? 'partial' : 'available',
      reason: partial
        ? `Collector reported partial collection${envelope.errors[0] !== undefined ? `: ${envelope.errors[0].message}` : '.'}`
        : 'Collected successfully and verified.',
      collectionStatus: envelope.status,
      data: dataResult.data,
      reference,
    },
  };
}

function envelopeMismatch(envelope: EvidenceEnvelope, entry: ManifestFile, manifest: EvidenceManifest): string | undefined {
  if (envelope.datasetId !== entry.datasetId) return 'datasetId differs from the manifest.';
  if (envelope.assessmentId.toLowerCase() !== manifest.assessmentId.toLowerCase()) return 'assessmentId differs from the manifest.';
  if (envelope.collector.module !== entry.module) return 'collector module differs from the manifest.';
  if (envelope.status !== entry.status) return 'collection status differs from the manifest.';
  if (envelope.schemaVersion !== entry.schemaVersion) return 'schemaVersion differs from the manifest.';
  return undefined;
}

/** Produce issue descriptions containing only paths and issue codes - never input values. */
export function summarizeZodIssues(error: z.ZodError): string[] {
  return error.issues.slice(0, MAX_VALIDATION_MESSAGES).map((issue) => {
    const where = issue.path.length > 0 ? issue.path.map(String).join('.') : '(root)';
    return `${where}: ${issue.code}`;
  });
}

function ingestionIssue(
  level: 'error' | 'warning',
  module: CollectorModule | null,
  datasetId: string | null,
  code: string,
  message: string,
): CollectionIssue {
  return { level, module, datasetId, code, message, target: null, origin: 'ingestion' };
}
