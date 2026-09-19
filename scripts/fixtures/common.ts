/**
 * Shared helpers for the sanitized sample assessment fixtures.
 *
 * Everything here is deterministic: GUIDs are derived from fixed seeds, timestamps
 * are computed from fixed assessment dates (never the wall clock) and objects are
 * written with a fixed key order, so regenerating the fixtures produces identical
 * bytes. All names, domains, addresses and identifiers are fictional.
 */
import { createHash } from 'node:crypto';
import type { CollectionStatus, CollectorModule } from '@adminsecops/core';
import type {
  CollectionMessage,
  DatasetDefinition,
  EvidenceEnvelope,
  EvidenceManifest,
  ManifestModule,
} from '@adminsecops/schemas';
import type { z } from 'zod';

export const COLLECTOR = { name: 'AdminSecOps.Collector', version: '0.1.0' } as const;
export const COLLECTOR_HOST = { powershellVersion: '7.4.6', platform: 'Win32NT' } as const;
export const MODULE_VERSION = '0.1.0';

/** Deterministic GUID (8-4-4-4-12, RFC 4122 version 4 / variant bits set) derived from a seed. */
export function guid(seed: string): string {
  const hex = createHash('sha256').update(`adminsecops-fixture:${seed}`).digest('hex');
  const variant = ((Number.parseInt(hex.charAt(16), 16) & 0x3) | 0x8).toString(16);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-${variant}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

/** Deterministic opaque identifier in the style of Graph object IDs (URL-safe base64). */
export function opaqueId(seed: string, length = 43): string {
  return createHash('sha256').update(`adminsecops-fixture-id:${seed}`).digest('base64url').slice(0, length);
}

/** ISO-8601 UTC timestamp without fractional seconds. */
export function iso(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** ISO-8601 UTC timestamp in PowerShell round-trip format (seven fractional digits). */
export function isoRoundTrip(date: Date): string {
  return date.toISOString().replace(/\.(\d{3})Z$/, '.$10000Z');
}

/** Fixed point in time an environment's evidence describes, with relative helpers. */
export class Clock {
  constructor(readonly at: Date) {}

  static of(value: string): Clock {
    return new Clock(new Date(value));
  }

  /** Timestamp `days` (and optional hours/minutes) before the assessment time. */
  ago(days: number, hours = 0, minutes = 0): string {
    return iso(new Date(this.at.getTime() - ((days * 24 + hours) * 60 + minutes) * 60_000));
  }

  /** Timestamp `days` (and optional hours) after the assessment time. */
  ahead(days: number, hours = 0): string {
    return iso(new Date(this.at.getTime() + (days * 24 + hours) * 3_600_000));
  }

  /** Date relative to the assessment time (minutes offset, may be negative). */
  offsetMinutes(minutes: number): Date {
    return new Date(this.at.getTime() + minutes * 60_000);
  }
}

/** One dataset of a fixture environment, before serialisation. */
export interface DatasetFixture {
  readonly definition: DatasetDefinition;
  readonly status: CollectionStatus;
  readonly data: unknown;
  readonly errors: CollectionMessage[];
  readonly warnings: CollectionMessage[];
}

export interface FixtureMessages {
  errors?: CollectionMessage[];
  warnings?: CollectionMessage[];
}

/**
 * A collected dataset (status Success, or Partial when errors are supplied with
 * `partial: true`). The payload is typed with the schema input type so the
 * TypeScript compiler checks it against the collector contract; the builder also
 * validates it at runtime with the real schema.
 */
export function collected<S extends z.ZodType>(
  definition: DatasetDefinition<S>,
  data: z.input<S>,
  options: FixtureMessages & { partial?: boolean } = {},
): DatasetFixture {
  return {
    definition,
    status: options.partial === true ? 'Partial' : 'Success',
    data,
    errors: options.errors ?? [],
    warnings: options.warnings ?? [],
  };
}

/** A dataset the collector could not (or deliberately did not) collect. `data` is null. */
export function uncollected(
  definition: DatasetDefinition,
  status: Exclude<CollectionStatus, 'Success' | 'Partial'>,
  messages: FixtureMessages,
): DatasetFixture {
  return { definition, status, data: null, errors: messages.errors ?? [], warnings: messages.warnings ?? [] };
}

export function message(code: string, text: string, target: string | null = null): CollectionMessage {
  return { code, message: text, target };
}

/** Relative path of a dataset inside the package: evidence/<module-lower>/<datasetName>.json */
export function evidencePath(definition: DatasetDefinition): string {
  const name = definition.id.slice(definition.id.indexOf('.') + 1);
  return `evidence/${definition.module.toLowerCase()}/${name}.json`;
}

export interface ModuleRun {
  module: CollectorModule;
  status: ManifestModule['status'];
  /** Minutes relative to the manifest createdAt (negative = before). */
  startedOffset: number;
  completedOffset: number;
  prerequisites: ManifestModule['prerequisites'];
  errors?: CollectionMessage[];
  warnings?: CollectionMessage[];
}

export interface EnvironmentFixture {
  /** Directory name under fixtures/assessments. */
  readonly directory: string;
  readonly assessmentId: string;
  readonly clock: Clock;
  readonly environment: EvidenceManifest['environment'];
  readonly options: EvidenceManifest['options'];
  readonly modules: readonly ModuleRun[];
  readonly datasets: readonly DatasetFixture[];
}

export function moduleCompletedAt(env: EnvironmentFixture, module: CollectorModule): Date {
  const run = env.modules.find((m) => m.module === module);
  if (run === undefined) throw new Error(`Fixture ${env.directory}: dataset for module ${module} but the module was not run`);
  return env.clock.offsetMinutes(run.completedOffset);
}

/** Build the manifest (without files) for an environment. Key order is fixed. */
export function manifestBase(env: EnvironmentFixture): Omit<EvidenceManifest, 'files'> {
  return {
    manifestVersion: '1.0',
    product: 'AdminSecOps',
    assessmentId: env.assessmentId,
    createdAt: isoRoundTrip(env.clock.at),
    collector: { name: COLLECTOR.name, version: COLLECTOR.version, ...COLLECTOR_HOST },
    environment: env.environment,
    options: env.options,
    modules: env.modules.map((run) => ({
      name: run.module,
      version: MODULE_VERSION,
      status: run.status,
      startedAt: isoRoundTrip(env.clock.offsetMinutes(run.startedOffset)),
      completedAt: isoRoundTrip(env.clock.offsetMinutes(run.completedOffset)),
      prerequisites: run.prerequisites,
      errors: run.errors ?? [],
      warnings: run.warnings ?? [],
    })),
  };
}

/** Build the evidence envelope of one dataset. Key order matches the collector output. */
export function envelopeFor(env: EnvironmentFixture, fixture: DatasetFixture): EvidenceEnvelope {
  const { definition } = fixture;
  // Datasets are collected in order within their module; stagger by position so each has a distinct time.
  const moduleDatasets = env.datasets.filter((d) => d.definition.module === definition.module);
  const position = moduleDatasets.indexOf(fixture);
  const completed = moduleCompletedAt(env, definition.module);
  const collectedAt = new Date(completed.getTime() - (moduleDatasets.length - position) * 7_000);
  return {
    schemaVersion: '1.0',
    datasetId: definition.id,
    assessmentId: env.assessmentId,
    collector: { name: COLLECTOR.name, version: COLLECTOR.version, module: definition.module, moduleVersion: MODULE_VERSION },
    collectedAt: isoRoundTrip(collectedAt),
    source: {
      system: definition.source,
      operations: [...definition.operations],
      apiVersion: apiVersionFor(definition),
    },
    status: fixture.status,
    errors: fixture.errors,
    warnings: fixture.warnings,
    data: fixture.data,
  };
}

function apiVersionFor(definition: DatasetDefinition): string | null {
  if (definition.source === 'MicrosoftGraph') return 'v1.0';
  if (definition.source === 'AzureResourceManager') {
    const match = /api-version=([0-9A-Za-z.-]+)/.exec(definition.operations.join(' '));
    return match?.[1] ?? null;
  }
  return null;
}
