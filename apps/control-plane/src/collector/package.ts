import { AdminSecOpsError, type CollectorModule } from '@adminsecops/core';
import {
  buildEvidencePackage,
  loadEvidenceBundle,
  type EvidenceBundle,
  type PackageFiles,
} from '@adminsecops/evidence/browser';
import {
  GuidSchema,
  type CollectionMessage,
  type DatasetDefinition,
  type EvidenceEnvelope,
  type EvidenceManifest,
  type ManifestModule,
} from '@adminsecops/schemas';
import { DEFAULT_GRAPH_LIMITS, GraphClient, type GraphLimits } from './graph-client.js';
import {
  message,
  runDataset,
  type CollectionContext,
  type DatasetCollector,
  type DatasetOutcome,
} from './runtime.js';

export const HOSTED_COLLECTOR_NAME = 'AdminSecOps.HostedGraphCollector';
export const HOSTED_COLLECTOR_VERSION = '0.2.0';

export interface HostedCollectionOptions {
  tenantId: string;
  assessmentId: string;
  /** Microsoft Graph access token. Used only in the Authorization header; never stored or logged. */
  accessToken: string;
  /**
   * Delegated scopes the identity platform reported as granted with the token. Used only to
   * explain Unauthorized results (missing consent); requests are made regardless.
   */
  grantedScopes?: readonly string[];
  fetch?: typeof globalThis.fetch;
  signal?: AbortSignal;
  /** Override collection bounds (tests, smaller tenants). */
  limits?: Partial<GraphLimits>;
  /** Clock used for timestamps and budgets; injectable for reproducible tests. */
  now?: () => Date;
}

export interface HostedCollectionResult {
  /** Package files (manifest + evidence) suitable for storage or re-loading with loadEvidenceBundle. */
  readonly files: PackageFiles;
  readonly manifest: EvidenceManifest;
  /** The verified bundle, usable with runAssessment(bundle, CONTROL_LIBRARY). */
  readonly bundle: EvidenceBundle;
}

export interface PlannedDataset {
  readonly definition: DatasetDefinition;
  readonly collector: DatasetCollector;
}

/** A module the hosted collector cannot collect at all, recorded as Skipped with the reason. */
export interface SkippedModule {
  readonly name: CollectorModule;
  readonly code: string;
  readonly reason: string;
}

export interface CollectionPlan {
  /** Datasets in collection order. The first must be entra.organization (tenant verification). */
  readonly datasets: readonly PlannedDataset[];
  /** Registry datasets of the collected modules that are intentionally not produced, per module. */
  readonly notCollected: ReadonlyMap<CollectorModule, readonly string[]>;
  readonly skippedModules: readonly SkippedModule[];
}

/**
 * Run a collection plan read-only through Microsoft Graph v1.0 and return a verified
 * evidence bundle. The organization is read first and must match the requested tenant
 * before any other customer data is requested. Datasets that cannot be read are reported
 * with an honest status and never as passing data. Throws CollectionCancelledError when
 * `signal` aborts.
 */
export async function collectHostedEvidence(
  options: HostedCollectionOptions,
  plan: CollectionPlan,
): Promise<HostedCollectionResult> {
  const { tenantId, assessmentId, accessToken } = validateOptions(options);
  if (plan.datasets[0]?.definition.id !== 'entra.organization')
    throw new Error('A hosted collection plan must verify the organization first.');
  const clock = options.now ?? (() => new Date());
  const overrides = Object.entries(options.limits ?? {}).filter(
    ([, v]) => typeof v === 'number' && Number.isFinite(v) && v >= 0,
  );
  const limits: GraphLimits = {
    ...DEFAULT_GRAPH_LIMITS,
    ...(Object.fromEntries(overrides) as Partial<GraphLimits>),
  };
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  const client = new GraphClient({
    accessToken,
    fetch: fetchImpl,
    signal: options.signal,
    limits,
    now: () => clock().getTime(),
  });

  const startedAt = clock().toISOString();
  const context: CollectionContext = {
    client,
    clock,
    tenantId,
    limits,
    grantedScopes: normalizeScopes(options.grantedScopes),
    servicePlans: undefined,
    organization: undefined,
  };
  const outcomes: DatasetOutcome[] = [];
  for (const { definition, collector } of plan.datasets) {
    client.throwIfCancelled();
    const outcome = await runDataset(definition, collector, context);
    outcomes.push(outcome);
    if (definition.id === 'entra.organization' && outcome.status !== 'Success') {
      throw new AdminSecOpsError(
        'TENANT_NOT_VERIFIED',
        'The organization could not be verified. No tenant evidence was produced.',
        { statusCode: 403 },
      );
    }
  }
  client.throwIfCancelled();
  const completedAt = clock().toISOString();

  const collectedModules = [...new Set(plan.datasets.map((d) => d.definition.module))];
  const modules: ManifestModule[] = collectedModules.map((name) => {
    const own = outcomes.filter((o) => o.definition.module === name);
    const warnings: CollectionMessage[] = [];
    const notCollected = plan.notCollected.get(name) ?? [];
    if (notCollected.length > 0) {
      warnings.push(
        message(
          'DATASETS_NOT_COLLECTED',
          `The hosted collector does not collect these datasets; controls that need them are not assessed: ${notCollected.join(', ')}.`,
        ),
      );
    }
    return {
      name,
      version: HOSTED_COLLECTOR_VERSION,
      status: moduleStatus(own),
      startedAt,
      completedAt,
      prerequisites: [],
      errors: [],
      warnings,
    };
  });
  for (const skipped of plan.skippedModules) {
    modules.push({
      name: skipped.name,
      version: HOSTED_COLLECTOR_VERSION,
      status: 'Skipped',
      startedAt: null,
      completedAt: null,
      prerequisites: [],
      errors: [],
      warnings: [message(skipped.code, skipped.reason)],
    });
  }

  const environment: EvidenceManifest['environment'] = {
    label: null,
    tenantId,
    tenantDisplayName: context.organization?.displayName ?? null,
    primaryDomain: context.organization?.primaryDomain ?? null,
    adForestName: null,
    adDomainName: null,
  };
  const manifestBase: Omit<EvidenceManifest, 'files'> = {
    manifestVersion: '1.0',
    product: 'AdminSecOps',
    assessmentId,
    createdAt: completedAt,
    collector: {
      name: HOSTED_COLLECTOR_NAME,
      version: HOSTED_COLLECTOR_VERSION,
      powershellVersion: null,
      platform: 'MicrosoftGraph',
    },
    environment,
    options: {
      modules: collectedModules,
      collectionMode: 'hosted-graph',
      datasets: outcomes.map((o) => o.definition.id),
    },
    modules,
  };

  const { files, manifest } = buildEvidencePackage(
    manifestBase,
    outcomes.map((outcome) => ({
      path: evidencePath(outcome.definition),
      envelope: toEnvelope(outcome, assessmentId),
    })),
  );
  return { files, manifest, bundle: loadEvidenceBundle(files) };
}

function moduleStatus(outcomes: readonly DatasetOutcome[]): ManifestModule['status'] {
  const bad = outcomes.filter((o) => o.status === 'Failed' || o.status === 'Unauthorized');
  if (bad.length === outcomes.length) return 'Failed';
  if (bad.length > 0 || outcomes.some((o) => o.status === 'Partial')) return 'CompletedWithErrors';
  return 'Completed';
}

function toEnvelope(outcome: DatasetOutcome, assessmentId: string): EvidenceEnvelope {
  return {
    schemaVersion: '1.0',
    datasetId: outcome.definition.id,
    assessmentId,
    collector: {
      name: HOSTED_COLLECTOR_NAME,
      version: HOSTED_COLLECTOR_VERSION,
      module: outcome.definition.module,
      moduleVersion: HOSTED_COLLECTOR_VERSION,
    },
    collectedAt: outcome.collectedAt,
    source: {
      system: 'MicrosoftGraph',
      operations: outcome.operations.slice(0, 200).map((o) => o.slice(0, 2000)),
      apiVersion: 'v1.0',
    },
    status: outcome.status,
    errors: [...outcome.errors],
    warnings: [...outcome.warnings],
    data: outcome.data,
  };
}

function evidencePath(definition: DatasetDefinition): string {
  const id = definition.id;
  return `evidence/${definition.module.toLowerCase()}/${id.slice(id.indexOf('.') + 1)}.json`;
}

function normalizeScopes(scopes: readonly string[] | undefined): ReadonlySet<string> | null {
  if (scopes === undefined) return null;
  return new Set(
    scopes
      .filter((s): s is string => typeof s === 'string')
      .map((s) => s.replace(/^https:\/\/graph\.microsoft\.com\//i, ''))
      .filter((s) => /^[A-Za-z]+(?:\.[A-Za-z]+)+$/.test(s)),
  );
}

function validateOptions(options: HostedCollectionOptions): {
  tenantId: string;
  assessmentId: string;
  accessToken: string;
} {
  if (!GuidSchema.safeParse(options.tenantId).success) {
    throw new AdminSecOpsError('INVALID_TENANT_ID', 'tenantId must be a tenant GUID.');
  }
  if (!GuidSchema.safeParse(options.assessmentId).success) {
    throw new AdminSecOpsError('INVALID_ASSESSMENT_ID', 'assessmentId must be a GUID.');
  }
  const token = options.accessToken;
  // Printable ASCII only: prevents header injection. The token value is never echoed.
  if (
    typeof token !== 'string' ||
    token.length === 0 ||
    token.length > 16_384 ||
    !/^[\x21-\x7e]+$/.test(token)
  ) {
    throw new AdminSecOpsError('INVALID_ACCESS_TOKEN', 'accessToken is missing or malformed.');
  }
  return {
    tenantId: options.tenantId.toLowerCase(),
    assessmentId: options.assessmentId.toLowerCase(),
    accessToken: token,
  };
}
