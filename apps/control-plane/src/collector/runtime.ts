import { findSensitiveContent, type CollectionStatus } from '@adminsecops/core';
import { summarizeZodIssues } from '@adminsecops/evidence/browser';
import type { CollectionMessage, DatasetDefinition } from '@adminsecops/schemas';
import {
  GraphRequestError,
  asRecord,
  type GraphClient,
  type GraphLimits,
  type GraphPageResult,
} from './graph-client.js';

/**
 * Shared runtime of the hosted collectors: per-dataset state, Graph helpers, licence
 * gating, bounded fan-out and the mapping from Graph failures to honest collection
 * statuses. Workload collectors (entra.ts, intune.ts, m365.ts) only map Graph
 * responses to dataset payloads; everything that decides whether evidence is usable
 * lives here.
 */

/** Why a non-Graph connector cannot be used for this collection (never a passing state). */
export type ConnectorGapState = 'not-connected' | 'consent-required' | 'expired' | 'unavailable';

export interface ConnectorGap {
  readonly state: ConnectorGapState;
  /** Secret-free explanation shown in evidence and on the Coverage page. */
  readonly reason: string;
}

/** Collection status and message code recorded for datasets of an unusable connector. */
export const CONNECTOR_GAP_OUTCOME: Readonly<Record<ConnectorGapState, { status: CollectionStatus; code: string }>> = {
  'not-connected': { status: 'NotCollected', code: 'CONNECTOR_NOT_CONNECTED' },
  'consent-required': { status: 'Unauthorized', code: 'CONNECTOR_CONSENT_REQUIRED' },
  expired: { status: 'NotCollected', code: 'CONNECTOR_EXPIRED' },
  unavailable: { status: 'NotCollected', code: 'CONNECTOR_UNAVAILABLE' },
};

export interface ArmRuntime {
  readonly state: 'connected';
  /** Client bound to the Azure Resource Manager policy and the ARM token only. */
  readonly client: GraphClient;
  /** Subscriptions of the verified tenant, filled by azure.subscriptions. */
  subscriptions: { readonly ids: readonly string[]; readonly complete: boolean } | undefined;
  /** Set when the subscription list itself could not be read. */
  listError?: GraphRequestError | undefined;
}

export interface CollectionContext {
  /** Microsoft Graph client (Graph token only). */
  readonly client: GraphClient;
  readonly clock: () => Date;
  readonly tenantId: string;
  readonly limits: GraphLimits;
  /** Delegated scopes granted to the token, when the identity platform reported them. */
  readonly grantedScopes: ReadonlySet<string> | null;
  /** Enabled service plan names; null when licences could not be determined. */
  servicePlans: ReadonlySet<string> | null | undefined;
  organization: { displayName: string | null; primaryDomain: string | null } | undefined;
  /** Verified domains of the tenant (from entra.organization); undefined until verified. */
  verifiedDomains?: readonly { name: string; capabilities: string | null }[] | undefined;
  /** Azure Resource Manager connection, or why it cannot be used. */
  readonly arm?: ArmRuntime | ConnectorGap | undefined;
  /** Connector-specific state shared between datasets of one collection. */
  readonly shared: Map<string, unknown>;
}

export interface DatasetState {
  readonly definition: DatasetDefinition;
  readonly operations: string[];
  readonly errors: CollectionMessage[];
  readonly warnings: CollectionMessage[];
  partial: boolean;
  /** Set by a collector that decides the dataset does not apply (licence absent). */
  notApplicable: boolean;
  /** Set by a collector whose connector cannot be used; the dataset gets that honest status. */
  connectorGap?: ConnectorGap | undefined;
  /** Set by a collector that reports a status directly (for example every target failed). */
  forcedStatus?: { status: CollectionStatus; code: string; message: string } | undefined;
}

/** Records that a connector cannot be used; the collector must then return without data. */
export function connectorUnavailable(state: DatasetState, gap: ConnectorGap): null {
  state.connectorGap = gap;
  return null;
}

export interface DatasetOutcome {
  readonly definition: DatasetDefinition;
  readonly status: CollectionStatus;
  readonly data: unknown;
  readonly operations: readonly string[];
  readonly errors: readonly CollectionMessage[];
  readonly warnings: readonly CollectionMessage[];
  readonly collectedAt: string;
}

export type DatasetCollector = (state: DatasetState, context: CollectionContext) => Promise<unknown>;

/** Runs one dataset collector and validates its payload. Only cancellation and tenant errors escape. */
export async function runDataset(
  definition: DatasetDefinition,
  collector: DatasetCollector | undefined,
  context: CollectionContext,
): Promise<DatasetOutcome> {
  const state: DatasetState = {
    definition,
    operations: [],
    errors: [],
    warnings: [],
    partial: false,
    notApplicable: false,
  };
  const finish = (status: CollectionStatus, data: unknown): DatasetOutcome => ({
    definition,
    status,
    data: status === 'Success' || status === 'Partial' ? data : null,
    operations: state.operations.length > 0 ? state.operations : [...definition.operations],
    errors: state.errors,
    warnings: state.warnings,
    collectedAt: context.clock().toISOString(),
  });

  if (collector === undefined) {
    state.errors.push(
      message('COLLECTOR_MISSING', 'No hosted collector is implemented for this dataset.'),
    );
    return finish('NotCollected', null);
  }

  let data: unknown;
  try {
    data = await collector(state, context);
  } catch (error) {
    if (!(error instanceof GraphRequestError)) throw error; // cancellation, tenant mismatch, programming errors
    const status = statusForError(error);
    state.errors.push(
      message(codeForError(error, status), explainError(error, status, definition, context)),
    );
    return finish(status, null);
  }
  if (state.connectorGap !== undefined) {
    const outcome = CONNECTOR_GAP_OUTCOME[state.connectorGap.state];
    state.errors.push(message(outcome.code, state.connectorGap.reason));
    return finish(outcome.status, null);
  }
  if (state.forcedStatus !== undefined) {
    state.errors.push(message(state.forcedStatus.code, state.forcedStatus.message));
    return finish(state.forcedStatus.status, null);
  }
  if (state.notApplicable) return finish('NotApplicable', null);

  // Defence in depth: the payload must satisfy the dataset schema and contain no secret material.
  const sensitive = findSensitiveContent(data);
  if (sensitive.length > 0) {
    state.errors.push(
      message(
        'SENSITIVE_CONTENT',
        `Collected data contained ${sensitive.length} secret-like value(s) and was discarded.`,
      ),
    );
    return finish('Failed', null);
  }
  const parsed = definition.schema.safeParse(data);
  if (!parsed.success) {
    const where = summarizeZodIssues(parsed.error).join('; ');
    state.errors.push(
      message(
        'DATA_INVALID',
        `The ${serviceName(definition)} response did not match the ${definition.id} schema and was not used (${where}).`,
      ),
    );
    return finish('Failed', null);
  }
  if (definition.id === 'entra.subscribedSkus' && !state.partial && Array.isArray(parsed.data)) {
    context.servicePlans = enabledServicePlans(parsed.data.map(rec));
  }
  return finish(state.partial ? 'Partial' : 'Success', data);
}

function statusForError(error: GraphRequestError): CollectionStatus {
  if (error.kind !== 'http') return 'Failed';
  if (error.licenceHint) return 'NotApplicable';
  if (error.status === 401 || error.status === 403) return 'Unauthorized';
  return 'Failed';
}

function codeForError(error: GraphRequestError, status: CollectionStatus): string {
  if (status === 'NotApplicable') return 'LICENSE_OR_FEATURE_NOT_AVAILABLE';
  if (status === 'Unauthorized') return 'UNAUTHORIZED';
  if (error.kind === 'http' && error.status !== null) return `HTTP_${error.status}`;
  return error.kind.toUpperCase().replace(/-/g, '_');
}

/** Graph permission names declared by a dataset definition ("Graph: X.Read.All ..."). */
export function graphPermissionsOf(definition: DatasetDefinition): string[] {
  const out: string[] = [];
  for (const entry of definition.permissions) {
    const match = /^Graph: ([A-Za-z]+(?:\.[A-Za-z]+)+)/.exec(entry);
    if (match?.[1] !== undefined) out.push(match[1]);
  }
  return out;
}

/**
 * Microsoft Graph delegated permission the hosted collector uses for a dataset when it
 * differs from the least-privileged permission in the dataset definition. Each substitute is
 * documented by Microsoft as sufficient for the request (listed as a higher-privileged,
 * read-only permission) and is already part of the online consent, so no additional scope is
 * requested:
 * - PIM lists: RoleManagement.Read.Directory is listed for roleAssignmentScheduleInstances and
 *   roleEligibilitySchedules.
 * - applications, servicePrincipals and appRoleAssignedTo: Directory.Read.All is listed.
 */
export const HOSTED_PERMISSION_OVERRIDES: Readonly<Record<string, readonly string[]>> = {
  'entra.roleAssignmentScheduleInstances': ['RoleManagement.Read.Directory'],
  'entra.roleEligibilitySchedules': ['RoleManagement.Read.Directory'],
  'entra.applications': ['Directory.Read.All'],
  'entra.servicePrincipals': ['Directory.Read.All'],
  'entra.apiPermissionGrants': ['Directory.Read.All'],
};

/** Graph permissions the hosted collector relies on for a dataset (overrides applied). */
export function hostedGraphPermissionsOf(definition: DatasetDefinition): string[] {
  return [...(HOSTED_PERMISSION_OVERRIDES[definition.id] ?? graphPermissionsOf(definition))];
}

function serviceName(definition: DatasetDefinition): string {
  if (definition.source === 'AzureResourceManager') return 'Azure Resource Manager';
  if (definition.source === 'ExchangeOnline') return 'Exchange Online';
  if (definition.source === 'DNS') return 'DNS';
  return 'Microsoft Graph';
}

function explainError(
  error: GraphRequestError,
  status: CollectionStatus,
  definition: DatasetDefinition,
  context: CollectionContext,
): string {
  if (status === 'NotApplicable')
    return `${error.message} The service reported that the required licence or feature is not available.`;
  if (status === 'Unauthorized' && definition.source === 'AzureResourceManager') {
    return `${error.message} The signed-in account cannot read this Azure data. Required: ${definition.permissions.join('; ')}. Azure controls that need it are not assessed.`;
  }
  if (status === 'Unauthorized') {
    const granted = context.grantedScopes;
    const missing =
      granted === null ? [] : hostedGraphPermissionsOf(definition).filter((p) => !granted.has(p));
    const consent =
      missing.length > 0
        ? ` Delegated consent was not granted for: ${missing.join(', ')}. A tenant administrator must grant consent, then sign in again.`
        : '';
    return `${error.message} The collecting identity is not authorised to read this data.${consent} Required: ${definition.permissions.join('; ')}.`;
  }
  return error.message;
}

export function message(code: string, text: string, target: string | null = null): CollectionMessage {
  return { code, message: text.slice(0, 4000), target: target === null ? null : target.slice(0, 1000) };
}

// ---------------------------------------------------------------------------------------------
// Graph helpers
// ---------------------------------------------------------------------------------------------

export async function getOne(
  state: DatasetState,
  context: CollectionContext,
  url: string,
  client: GraphClient = context.client,
): Promise<Record<string, unknown>> {
  state.operations.push(`GET ${url}`);
  const body = asRecord(await client.get(url));
  if (body === undefined)
    throw new GraphRequestError(
      'invalid-response',
      `${client.policy.service} returned a response that is not a JSON object.`,
    );
  return body;
}

export async function getAll(
  state: DatasetState,
  context: CollectionContext,
  url: string,
  client: GraphClient = context.client,
  operation: string = url,
): Promise<unknown[]> {
  if (!state.operations.includes(`GET ${operation}`)) state.operations.push(`GET ${operation}`);
  const result: GraphPageResult = await client.getAll(url);
  if (result.incomplete !== null) {
    state.errors.push(message(result.incomplete.code, result.incomplete.message));
    state.partial = true;
  }
  return result.items;
}

/**
 * Sequential, bounded per-resource requests (for example one request per policy or team).
 * - At most `limits.maxFanoutRequests` requests are sent; items beyond the cap are not
 *   read and the dataset is marked Partial.
 * - A Graph failure for one item marks the dataset Partial and records the item; the
 *   callback receives `undefined` for it so the item is never treated as complete.
 * - Cancellation and non-Graph errors propagate; an exhausted time or size budget stops
 *   the fan-out immediately.
 */
export async function fanout<T>(
  state: DatasetState,
  context: CollectionContext,
  items: readonly T[],
  options: {
    /** Operation template recorded once, e.g. GET .../deviceCompliancePolicies/{id}/assignments */
    operation: string;
    url: (item: T) => string | undefined;
    target: (item: T) => string | null;
    what: string;
    /** Client to use; the Microsoft Graph client by default. */
    client?: GraphClient;
  },
): Promise<Map<T, Record<string, unknown> | undefined>> {
  const client = options.client ?? context.client;
  const results = new Map<T, Record<string, unknown> | undefined>();
  if (items.length === 0) return results;
  state.operations.push(`GET ${options.operation}`);
  const cap = Math.max(0, Math.floor(context.limits.maxFanoutRequests));
  let sent = 0;
  for (const item of items) {
    client.throwIfCancelled();
    const target = options.target(item);
    const url = options.url(item);
    if (url === undefined) {
      state.partial = true;
      state.errors.push(
        message('FANOUT_ITEM_INVALID', `The ${options.what} could not be requested (invalid identifier).`, target),
      );
      results.set(item, undefined);
      continue;
    }
    if (sent >= cap) {
      state.partial = true;
      state.errors.push(
        message(
          'FANOUT_LIMIT',
          `Stopped after ${sent} ${options.what} request(s) (collection limit); ${items.length - sent} item(s) were not read and results are incomplete.`,
        ),
      );
      for (const rest of items.slice(items.indexOf(item))) results.set(rest, undefined);
      break;
    }
    sent += 1;
    try {
      const body = asRecord(await client.get(url));
      if (body === undefined)
        throw new GraphRequestError('invalid-response', `${client.policy.service} returned a response that is not a JSON object.`);
      results.set(item, body);
    } catch (error) {
      if (!(error instanceof GraphRequestError)) throw error;
      state.partial = true;
      state.errors.push(
        message('FANOUT_ITEM_FAILED', `The ${options.what} could not be read. ${error.message}`, target),
      );
      results.set(item, undefined);
      if (error.kind === 'budget-exhausted') {
        for (const rest of items.slice(items.indexOf(item) + 1)) results.set(rest, undefined);
        break;
      }
    }
  }
  return results;
}

/** Marks the dataset NotApplicable when subscribedSkus shows none of the plans; warns when licences are unknown. */
export function licensed(
  state: DatasetState,
  context: CollectionContext,
  plans: readonly string[],
  feature: string,
): boolean {
  const known = context.servicePlans;
  if (known === null || known === undefined) {
    state.warnings.push(
      message(
        'LICENSE_UNKNOWN',
        `Licence information was not available; ${feature} availability is inferred from the service response.`,
      ),
    );
    return true;
  }
  if (plans.some((p) => known.has(p.toUpperCase()))) return true;
  state.warnings.push(
    message(
      'LICENSE_NOT_PRESENT',
      `${feature} is not licensed in this tenant (none of the service plans ${plans.join(', ')} is present in subscribedSkus). The dataset does not apply.`,
    ),
  );
  state.notApplicable = true;
  return false;
}

// Field pickers: copy only declared properties, never coerce. Missing values become null so
// the dataset schema - not this code - decides whether the evidence is acceptable.
export type Rec = Record<string, unknown>;
export const rec = (v: unknown): Rec | undefined => asRecord(v);
export const val = (o: Rec | undefined, key: string): unknown => o?.[key] ?? null;
export const arr = (v: unknown): unknown[] | null => (Array.isArray(v) ? v : null);
export const pick = (o: Rec | undefined, keys: readonly string[]): Rec =>
  Object.fromEntries(keys.map((k) => [k, val(o, k)]));
export const pickOrNull = (v: unknown, keys: readonly string[]): Rec | null => {
  const o = rec(v);
  return o === undefined ? null : pick(o, keys);
};
/** First property present (not undefined/null) among alternative Graph property names. */
export const firstOf = (o: Rec | undefined, keys: readonly string[]): unknown => {
  for (const key of keys) {
    const value = o?.[key];
    if (value !== undefined && value !== null) return value;
  }
  return null;
};

/** Graph OData type without the "#microsoft.graph." prefix, or null. */
export function odataType(o: Rec | undefined): string | null {
  const t = o?.['@odata.type'];
  return typeof t === 'string' ? t : null;
}

/** Graph resource identifiers used in fan-out URLs: GUIDs and other simple identifiers only. */
export function safeId(value: unknown): string | undefined {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,199}$/.test(value) ? value : undefined;
}

export function enabledServicePlans(skus: readonly (Rec | undefined)[]): Set<string> {
  const names = new Set<string>();
  for (const sku of skus) {
    const status = val(sku, 'capabilityStatus');
    if (typeof status === 'string' && !['Enabled', 'Warning', 'LockedOut'].includes(status))
      continue;
    for (const plan of arr(val(sku, 'servicePlans')) ?? []) {
      const p = rec(plan);
      if (val(p, 'provisioningStatus') === 'Disabled') continue;
      const name = val(p, 'servicePlanName');
      if (typeof name === 'string') names.add(name.toUpperCase());
    }
  }
  return names;
}
