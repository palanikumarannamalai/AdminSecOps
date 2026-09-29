import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { AssessmentResult } from '@adminsecops/schemas';
import { listDatasetDefinitions } from '@adminsecops/schemas';

/**
 * Anonymous aggregate usage counters for the hosted service (docs/PRIVACY.md "Online service").
 * Counts are computed on the server and stored per UTC day. No tenant ID, domain, user ID,
 * display name, error text or finding is stored; organisations are counted as a keyed hash.
 */
export const FAILURE_CODES = ['NOT_APPROVED', 'CONSENT_OR_TOKEN', 'COLLECTION_FAILED', 'TIMEOUT', 'QUEUE_EXPIRED', 'UNKNOWN'] as const;
export type FailureCode = (typeof FAILURE_CODES)[number];
export const COLLECTORS = ['entra', 'm365', 'intune', 'azure', 'exchange', 'dns'] as const;
export type CollectorName = (typeof COLLECTORS)[number];
export const EXPORT_FORMATS = ['json', 'html'] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

/** The only counter names that can be written or reported. */
export const USAGE_COUNTERS: readonly string[] = [
  'assessments_started', 'assessments_completed', 'assessments_failed', 'controls_evaluated',
  ...EXPORT_FORMATS.map(format => `exports_${format}`),
  ...COLLECTORS.map(name => `collector_${name}`),
  ...FAILURE_CODES.map(code => `failed_${code}`),
];
const ALLOWED: ReadonlySet<string> = new Set(USAGE_COUNTERS);
export const isUsageCounter = (value: unknown): value is string => typeof value === 'string' && ALLOWED.has(value);

export type UsageIncrements = Record<string, number>;
export interface UsageSummary {
  from: string | null; to: string;
  totals: Record<string, number>;
  distinctOrganisations: number;
  days: { day: string; counters: Record<string, number> }[];
}
export interface UsageStore {
  recordUsage(increments: UsageIncrements, orgHash?: string | null): Promise<void>;
}
export interface UsageSettings { counting: boolean; hashSalt: string | null }

/** Keyed one-way hash (HMAC-SHA-256 with USAGE_HASH_SALT) so an organisation is counted once per day. */
export function hashOrganisation(tenantId: string, salt: string): string {
  return createHmac('sha256', salt).update(tenantId.trim().toLowerCase()).digest('hex');
}

/** Constant-time check of `Authorization: Bearer <secret>`; both sides are compared as SHA-256 digests. */
export function usageSecretMatches(header: unknown, secret: string): boolean {
  const supplied = typeof header === 'string' ? /^Bearer ([^\s]+)$/.exec(header)?.[1] : undefined;
  const equal = timingSafeEqual(createHash('sha256').update(supplied ?? '').digest(), createHash('sha256').update(secret).digest());
  return equal && supplied !== undefined;
}

const MODULE_COLLECTORS: Readonly<Record<string, CollectorName>> = { Entra: 'entra', M365: 'm365', Intune: 'intune', Azure: 'azure', Exchange: 'exchange' };
const DNS_DATASETS: ReadonlySet<string> = new Set(listDatasetDefinitions().filter(d => d.source === 'DNS').map(d => d.id));

/** Collectors that returned at least one available or partial dataset in a completed assessment. */
export function collectorsRan(result: AssessmentResult): CollectorName[] {
  const ran = new Set<CollectorName>();
  for (const dataset of result.evidence.datasets) {
    if (dataset.state === 'unavailable') continue;
    const name = DNS_DATASETS.has(dataset.datasetId) ? 'dns' : MODULE_COLLECTORS[dataset.module];
    if (name) ran.add(name);
  }
  return COLLECTORS.filter(name => ran.has(name));
}

/** Classifies a worker failure by the stage it happened in; a cancelled or timed-out collection is TIMEOUT. */
export function failureCode(stage: FailureCode, error: unknown): FailureCode {
  const name = (error as { name?: unknown } | null)?.name;
  return name === 'CollectionCancelledError' || name === 'TimeoutError' || name === 'AbortError' ? 'TIMEOUT' : stage;
}

/**
 * Records counters without ever failing or delaying the caller: every method resolves, and a
 * failed write logs one fixed message with no data.
 */
export class UsageCounters {
  constructor(private readonly store: UsageStore, private readonly settings: UsageSettings) {}
  private async record(build: () => UsageIncrements, tenantId?: string): Promise<void> {
    if (!this.settings.counting) return;
    try {
      const increments: UsageIncrements = {};
      for (const [counter, value] of Object.entries(build())) {
        if (!isUsageCounter(counter)) throw new Error('Unknown usage counter');
        if (Number.isSafeInteger(value) && value > 0) increments[counter] = value;
      }
      const orgHash = tenantId !== undefined && this.settings.hashSalt ? hashOrganisation(tenantId, this.settings.hashSalt) : null;
      if (Object.keys(increments).length || orgHash) await this.store.recordUsage(increments, orgHash);
    } catch { console.error('Usage counter update failed.'); }
  }
  started(tenantId: string): Promise<void> { return this.record(() => ({ assessments_started: 1 }), tenantId); }
  completed(result: AssessmentResult, tenantId: string): Promise<void> {
    return this.record(() => {
      const increments: UsageIncrements = { assessments_completed: 1, controls_evaluated: result.summary.controlsEvaluated };
      for (const name of collectorsRan(result)) increments[`collector_${name}`] = 1;
      return increments;
    }, tenantId);
  }
  failed(code: FailureCode, count = 1, tenantId?: string): Promise<void> { return this.record(() => ({ assessments_failed: count, [`failed_${code}`]: count }), tenantId); }
  exported(format: ExportFormat, tenantId?: string): Promise<void> { return this.record(() => ({ [`exports_${format}`]: 1 }), tenantId); }
}
