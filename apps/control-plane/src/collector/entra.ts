import { AdminSecOpsError, findSensitiveContent, type CollectionStatus } from '@adminsecops/core';
import {
  buildEvidencePackage,
  loadEvidenceBundle,
  summarizeZodIssues,
  type EvidenceBundle,
  type PackageFiles,
} from '@adminsecops/evidence/browser';
import {
  ENTRA_DATASETS,
  GuidSchema,
  entraAuthenticationMethodsPolicy,
  entraAuthorizationPolicy,
  entraConditionalAccessPolicies,
  entraGuestUsers,
  entraOrganization,
  entraRoleAssignments,
  entraRoleDefinitions,
  entraSecurityDefaults,
  entraSubscribedSkus,
  entraUserRegistrationDetails,
  type CollectionMessage,
  type DatasetDefinition,
  type EvidenceEnvelope,
  type EvidenceManifest,
  type ManifestModule,
} from '@adminsecops/schemas';
import {
  DEFAULT_GRAPH_LIMITS,
  GRAPH_BASE,
  GraphClient,
  GraphRequestError,
  asRecord,
  type GraphLimits,
  type GraphPageResult,
} from './graph-client.js';

export const HOSTED_COLLECTOR_NAME = 'AdminSecOps.HostedGraphCollector';
export const HOSTED_COLLECTOR_VERSION = '0.1.0';

/**
 * Datasets this collector produces, in collection order. subscribedSkus is collected
 * before the licence-dependent datasets. Every other Entra dataset in the schema registry
 * is left out of the package (absent), so controls needing it are NOT_ASSESSED.
 */
export const HOSTED_ENTRA_DATASETS = [
  entraOrganization,
  entraSubscribedSkus,
  entraSecurityDefaults,
  entraAuthorizationPolicy,
  entraAuthenticationMethodsPolicy,
  entraConditionalAccessPolicies,
  entraUserRegistrationDetails,
  entraRoleDefinitions,
  entraRoleAssignments,
  entraGuestUsers,
] as const satisfies readonly DatasetDefinition[];

const COLLECTED_IDS: ReadonlySet<string> = new Set(HOSTED_ENTRA_DATASETS.map((d) => d.id));

/** Entra datasets defined by the schema registry that this hosted collector does not produce. */
export const HOSTED_ENTRA_UNSUPPORTED_DATASETS: readonly string[] = ENTRA_DATASETS.map(
  (d) => d.id,
).filter((id) => !COLLECTED_IDS.has(id));

export interface GraphPermissionRequirement {
  /** Microsoft Graph permission name, e.g. Policy.Read.All. */
  readonly permission: string;
  readonly datasets: readonly string[];
}

/**
 * Microsoft Graph permissions needed by this collector, derived from the `permissions`
 * of the dataset definitions (the single source of truth) - nothing is added here.
 * Entries that are not Graph permissions (e.g. directory-role requirements) are listed in
 * ENTRA_ADDITIONAL_REQUIREMENTS.
 */
export const ENTRA_GRAPH_PERMISSIONS: readonly GraphPermissionRequirement[] = derivePermissions();
export const ENTRA_REQUIRED_GRAPH_PERMISSIONS: readonly string[] = ENTRA_GRAPH_PERMISSIONS.map(
  (p) => p.permission,
);
export const ENTRA_ADDITIONAL_REQUIREMENTS: readonly {
  readonly datasetId: string;
  readonly requirement: string;
}[] = HOSTED_ENTRA_DATASETS.flatMap((d) =>
  d.permissions
    .filter((p) => !p.startsWith('Graph: '))
    .map((requirement) => ({ datasetId: d.id, requirement })),
);

function derivePermissions(): GraphPermissionRequirement[] {
  const byPermission = new Map<string, string[]>();
  for (const definition of HOSTED_ENTRA_DATASETS) {
    for (const entry of definition.permissions) {
      const match = /^Graph: ([A-Za-z]+(?:\.[A-Za-z]+)+)/.exec(entry);
      if (match?.[1] === undefined) continue;
      const list = byPermission.get(match[1]) ?? [];
      list.push(definition.id);
      byPermission.set(match[1], list);
    }
  }
  return [...byPermission.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([permission, datasets]) => ({ permission, datasets }));
}

/** Service plans that license a feature (same plan names as the PowerShell collector). */
const P1_PLANS = ['AAD_PREMIUM', 'AAD_PREMIUM_P2'];

export interface CollectEntraOptions {
  tenantId: string;
  assessmentId: string;
  /** Microsoft Graph access token. Used only in the Authorization header; never stored or logged. */
  accessToken: string;
  fetch?: typeof globalThis.fetch;
  signal?: AbortSignal;
  /** Override collection bounds (tests, smaller tenants). */
  limits?: Partial<GraphLimits>;
  /** Clock used for timestamps and budgets; injectable for reproducible tests. */
  now?: () => Date;
}

export interface EntraCollectionResult {
  /** Package files (manifest + evidence) suitable for storage or re-loading with loadEvidenceBundle. */
  readonly files: PackageFiles;
  readonly manifest: EvidenceManifest;
  /** The verified bundle, usable with runAssessment(bundle, CONTROL_LIBRARY). */
  readonly bundle: EvidenceBundle;
}

/**
 * Collect Microsoft Entra evidence read-only through Microsoft Graph v1.0 and return a
 * verified evidence bundle. Datasets that cannot be read are reported with an honest
 * status (Unauthorized / Failed / Partial / NotApplicable) and never as passing data.
 * Throws CollectionCancelledError when `signal` aborts.
 */
export async function collectEntra(options: CollectEntraOptions): Promise<EvidenceBundle> {
  return (await collectEntraEvidence(options)).bundle;
}

export async function collectEntraEvidence(
  options: CollectEntraOptions,
): Promise<EntraCollectionResult> {
  const { tenantId, assessmentId, accessToken } = validateOptions(options);
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
    servicePlans: undefined,
    organization: undefined,
  };
  const outcomes: DatasetOutcome[] = [];
  for (const definition of HOSTED_ENTRA_DATASETS) {
    client.throwIfCancelled();
    const outcome = await runDataset(definition, context);
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

  const moduleWarnings: CollectionMessage[] = [];
  if (HOSTED_ENTRA_UNSUPPORTED_DATASETS.length > 0) {
    moduleWarnings.push({
      code: 'DATASETS_NOT_COLLECTED',
      message: `The hosted collector does not collect these datasets; controls that need them are not assessed: ${HOSTED_ENTRA_UNSUPPORTED_DATASETS.join(', ')}.`,
      target: null,
    });
  }
  if (context.organization === undefined) {
    moduleWarnings.push({
      code: 'TENANT_NOT_VERIFIED',
      message:
        'The organization could not be read, so the tenant the token belongs to was not verified against the requested tenant.',
      target: null,
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
  const module: ManifestModule = {
    name: 'Entra',
    version: HOSTED_COLLECTOR_VERSION,
    status: moduleStatus(outcomes),
    startedAt,
    completedAt,
    prerequisites: [],
    errors: [],
    warnings: moduleWarnings,
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
      modules: ['Entra'],
      collectionMode: 'hosted-graph',
      datasets: outcomes.map((o) => o.definition.id),
    },
    modules: [module],
  };

  const { files, manifest } = buildEvidencePackage(
    manifestBase,
    outcomes.map((outcome) => ({
      path: evidencePath(outcome.definition.id),
      envelope: toEnvelope(outcome, assessmentId),
    })),
  );
  return { files, manifest, bundle: loadEvidenceBundle(files) };
}

// ---------------------------------------------------------------------------------------------
// Dataset execution and status mapping
// ---------------------------------------------------------------------------------------------

interface CollectionContext {
  readonly client: GraphClient;
  readonly clock: () => Date;
  readonly tenantId: string;
  /** Enabled service plan names; null when licences could not be determined. */
  servicePlans: ReadonlySet<string> | null | undefined;
  organization: { displayName: string | null; primaryDomain: string | null } | undefined;
}

interface DatasetState {
  readonly definition: DatasetDefinition;
  readonly operations: string[];
  readonly errors: CollectionMessage[];
  readonly warnings: CollectionMessage[];
  partial: boolean;
  /** Set by a collector that decides the dataset does not apply (licence absent). */
  notApplicable: boolean;
}

interface DatasetOutcome {
  readonly definition: DatasetDefinition;
  readonly status: CollectionStatus;
  readonly data: unknown;
  readonly operations: readonly string[];
  readonly errors: readonly CollectionMessage[];
  readonly warnings: readonly CollectionMessage[];
  readonly collectedAt: string;
}

type DatasetCollector = (state: DatasetState, context: CollectionContext) => Promise<unknown>;

async function runDataset(
  definition: DatasetDefinition,
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
  const collector = COLLECTORS[definition.id];
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
      message(codeForError(error, status), explainError(error, status, definition)),
    );
    return finish(status, null);
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
        `The Microsoft Graph response did not match the ${definition.id} schema and was not used (${where}).`,
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

function explainError(
  error: GraphRequestError,
  status: CollectionStatus,
  definition: DatasetDefinition,
): string {
  if (status === 'NotApplicable')
    return `${error.message} The service reported that the required licence or feature is not available.`;
  if (status === 'Unauthorized') {
    return `${error.message} The collecting identity is not authorised to read this data. Required: ${definition.permissions.join('; ')}.`;
  }
  return error.message;
}

function message(code: string, text: string, target: string | null = null): CollectionMessage {
  return { code, message: text.slice(0, 4000), target };
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
      module: 'Entra',
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

function evidencePath(datasetId: string): string {
  return `evidence/entra/${datasetId.slice(datasetId.indexOf('.') + 1)}.json`;
}

function validateOptions(options: CollectEntraOptions): {
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

// ---------------------------------------------------------------------------------------------
// Graph helpers
// ---------------------------------------------------------------------------------------------

async function getOne(
  state: DatasetState,
  context: CollectionContext,
  url: string,
): Promise<Record<string, unknown>> {
  state.operations.push(`GET ${url}`);
  const body = asRecord(await context.client.get(url));
  if (body === undefined)
    throw new GraphRequestError(
      'invalid-response',
      'Microsoft Graph returned a response that is not a JSON object.',
    );
  return body;
}

async function getAll(
  state: DatasetState,
  context: CollectionContext,
  url: string,
): Promise<unknown[]> {
  state.operations.push(`GET ${url}`);
  const result: GraphPageResult = await context.client.getAll(url);
  if (result.incomplete !== null) {
    state.errors.push(message(result.incomplete.code, result.incomplete.message));
    state.partial = true;
  }
  return result.items;
}

/** Marks the dataset NotApplicable when subscribedSkus shows none of the plans; warns when licences are unknown. */
function licensed(
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
type Rec = Record<string, unknown>;
const rec = (v: unknown): Rec | undefined => asRecord(v);
const val = (o: Rec | undefined, key: string): unknown => o?.[key] ?? null;
const arr = (v: unknown): unknown[] | null => (Array.isArray(v) ? v : null);
const strings = (v: unknown): unknown[] | null => arr(v);
const pick = (o: Rec | undefined, keys: readonly string[]): Rec =>
  Object.fromEntries(keys.map((k) => [k, val(o, k)]));
const pickOrNull = (v: unknown, keys: readonly string[]): Rec | null => {
  const o = rec(v);
  return o === undefined ? null : pick(o, keys);
};

function principalType(odataType: unknown): string {
  if (typeof odataType !== 'string') return 'other';
  const t = odataType.replace(/^#?microsoft\.graph\./, '');
  return t === 'user' || t === 'group' || t === 'servicePrincipal' ? t : 'other';
}

// ---------------------------------------------------------------------------------------------
// Dataset collectors
// ---------------------------------------------------------------------------------------------

const COLLECTORS: Record<string, DatasetCollector> = {
  'entra.organization': async (state, context) => {
    const orgs = await getAll(state, context, `${GRAPH_BASE}/organization`);
    const org = rec(orgs[0]);
    if (org === undefined)
      throw new GraphRequestError(
        'invalid-response',
        'The organization endpoint returned no tenant.',
      );
    const id = val(org, 'id');
    if (typeof id !== 'string' || !GuidSchema.safeParse(id).success)
      throw new GraphRequestError(
        'invalid-response',
        'The organization response did not contain a valid tenant ID.',
      );
    if (typeof id === 'string' && id.toLowerCase() !== context.tenantId) {
      throw new AdminSecOpsError(
        'TENANT_MISMATCH',
        'The access token belongs to a different tenant than the one requested. No evidence was produced.',
        { statusCode: 409 },
      );
    }
    const verifiedDomains =
      arr(val(org, 'verifiedDomains'))?.map((d) =>
        pick(rec(d), ['name', 'isDefault', 'isInitial', 'type', 'capabilities']),
      ) ?? null;
    const displayName = val(org, 'displayName');
    const primary = verifiedDomains?.find((d) => d['isDefault'] === true)?.['name'];
    context.organization = {
      displayName: typeof displayName === 'string' ? displayName.slice(0, 500) : null,
      primaryDomain: typeof primary === 'string' ? primary.slice(0, 500) : null,
    };
    return {
      id,
      displayName,
      createdDateTime: val(org, 'createdDateTime'),
      onPremisesSyncEnabled: val(org, 'onPremisesSyncEnabled'),
      onPremisesLastSyncDateTime: val(org, 'onPremisesLastSyncDateTime'),
      verifiedDomains,
    };
  },

  'entra.subscribedSkus': async (state, context) => {
    context.servicePlans = null;
    const skus = (await getAll(state, context, `${GRAPH_BASE}/subscribedSkus`)).map((s) => rec(s));
    if (skus.some((sku) => !Array.isArray(sku?.['servicePlans']))) {
      state.partial = true;
      state.errors.push(
        message(
          'SERVICE_PLANS_MISSING',
          'Service plan details were missing; licence availability could not be determined.',
        ),
      );
    }
    return skus.map((sku) => ({
      skuId: val(sku, 'skuId'),
      skuPartNumber: val(sku, 'skuPartNumber'),
      capabilityStatus: val(sku, 'capabilityStatus'),
      consumedUnits: val(sku, 'consumedUnits'),
      prepaidUnits: pickOrNull(val(sku, 'prepaidUnits'), ['enabled', 'suspended', 'warning']),
      servicePlans:
        arr(val(sku, 'servicePlans'))?.map((p) =>
          pick(rec(p), ['servicePlanId', 'servicePlanName', 'provisioningStatus', 'appliesTo']),
        ) ?? null,
    }));
  },

  'entra.securityDefaults': async (state, context) => {
    const policy = await getOne(
      state,
      context,
      `${GRAPH_BASE}/policies/identitySecurityDefaultsEnforcementPolicy`,
    );
    return { isEnabled: val(policy, 'isEnabled') };
  },

  'entra.authorizationPolicy': async (state, context) => {
    const response = await getOne(state, context, `${GRAPH_BASE}/policies/authorizationPolicy`);
    // v1.0 returns a single object; tolerate the collection form as well.
    const list = arr(response['value']);
    const policy = list !== null ? rec(list[0]) : response;
    if (policy === undefined)
      throw new GraphRequestError(
        'invalid-response',
        'The authorization policy response contained no policy.',
      );
    return {
      ...pick(policy, [
        'allowInvitesFrom',
        'allowedToSignUpEmailBasedSubscriptions',
        'allowEmailVerifiedUsersToJoinOrganization',
        'allowUserConsentForRiskyApps',
        'blockMsolPowerShell',
        'guestUserRoleId',
      ]),
      permissionGrantPolicyIdsAssignedToDefaultUserRole: strings(
        val(policy, 'permissionGrantPolicyIdsAssignedToDefaultUserRole'),
      ),
      defaultUserRolePermissions: pickOrNull(val(policy, 'defaultUserRolePermissions'), [
        'allowedToCreateApps',
        'allowedToCreateSecurityGroups',
        'allowedToCreateTenants',
        'allowedToReadBitlockerKeysForOwnedDevice',
        'allowedToReadOtherUsers',
      ]),
    };
  },

  'entra.authenticationMethodsPolicy': async (state, context) => {
    const policy = await getOne(
      state,
      context,
      `${GRAPH_BASE}/policies/authenticationMethodsPolicy`,
    );
    const configs = arr(val(policy, 'authenticationMethodConfigurations'));
    if (configs === null)
      throw new GraphRequestError(
        'invalid-response',
        'Authentication method configurations were absent from the response.',
      );
    const out: Rec[] = [];
    let lookups = 0;
    for (const raw of configs) {
      const config = rec(raw);
      const id = val(config, 'id');
      let source = config;
      if (config !== undefined && !('includeTargets' in config)) {
        // includeTargets is not always returned inline; read the individual configuration.
        if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,100}$/.test(id) || lookups >= 50) {
          state.errors.push(
            message(
              'METHOD_CONFIGURATION_UNREADABLE',
              'The targets of an authentication method configuration could not be read.',
              typeof id === 'string' ? id.slice(0, 100) : null,
            ),
          );
          state.partial = true;
        } else {
          lookups += 1;
          const url = `${GRAPH_BASE}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/${encodeURIComponent(id)}`;
          if (lookups === 1)
            state.operations.push(
              `GET ${GRAPH_BASE}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/{id}`,
            );
          try {
            source = rec(await context.client.get(url)) ?? config;
          } catch (error) {
            if (!(error instanceof GraphRequestError)) throw error;
            state.errors.push(
              message(
                'METHOD_CONFIGURATION_UNREADABLE',
                `The targets of the '${id}' method could not be read. ${error.message}`,
                id,
              ),
            );
            state.partial = true;
          }
        }
      }
      if (!Array.isArray(source?.['includeTargets'])) {
        state.partial = true;
        state.errors.push(
          message(
            'METHOD_TARGETS_MISSING',
            'Authentication method targets were absent; coverage is incomplete.',
          ),
        );
      }
      out.push({
        id,
        state: val(config, 'state'),
        includeTargets:
          arr(val(source, 'includeTargets'))?.map((t) => pick(rec(t), ['targetType', 'id'])) ??
          null,
      });
    }
    return {
      policyMigrationState: val(policy, 'policyMigrationState'),
      authenticationMethodConfigurations: out,
    };
  },

  'entra.conditionalAccessPolicies': async (state, context) => {
    if (!licensed(state, context, P1_PLANS, 'Conditional Access (Microsoft Entra ID P1)'))
      return null;
    const policies = await getAll(
      state,
      context,
      `${GRAPH_BASE}/identity/conditionalAccess/policies`,
    );
    return policies.map((raw) => {
      const p = rec(raw);
      const cond = rec(val(p, 'conditions'));
      // Preserve uncertainty when Graph returns scope dimensions the evaluator does not model.
      const applications = rec(val(cond, 'applications'));
      const unsupportedScope =
        ['clientApplications', 'servicePrincipalRiskLevels', 'insiderRiskLevels'].some((key) => {
          const value = val(cond, key);
          return value !== null && (!Array.isArray(value) || value.length > 0);
        }) || val(applications, 'applicationFilter') !== null;
      if (unsupportedScope) {
        state.partial = true;
        state.warnings.push(
          message(
            'CA_SCOPE_NOT_MODELED',
            'A Conditional Access policy uses scope conditions not modeled by this evaluator; passing checks require review.',
          ),
        );
      }
      const users = rec(val(cond, 'users'));
      const grant = rec(val(p, 'grantControls'));
      const session = rec(val(p, 'sessionControls'));
      const flows = rec(val(cond, 'authenticationFlows'));
      return {
        ...pick(p, ['id', 'displayName', 'state', 'createdDateTime', 'modifiedDateTime']),
        conditions: {
          users:
            users === undefined
              ? null
              : {
                  ...pick(users, [
                    'includeUsers',
                    'excludeUsers',
                    'includeGroups',
                    'excludeGroups',
                    'includeRoles',
                    'excludeRoles',
                  ]),
                  includeGuestsOrExternalUsers: val(users, 'includeGuestsOrExternalUsers'),
                  excludeGuestsOrExternalUsers: val(users, 'excludeGuestsOrExternalUsers'),
                },
          applications: pickOrNull(val(cond, 'applications'), [
            'includeApplications',
            'excludeApplications',
            'includeUserActions',
            'includeAuthenticationContextClassReferences',
          ]),
          clientAppTypes: strings(val(cond, 'clientAppTypes')),
          signInRiskLevels: strings(val(cond, 'signInRiskLevels')),
          userRiskLevels: strings(val(cond, 'userRiskLevels')),
          platforms: pickOrNull(val(cond, 'platforms'), ['includePlatforms', 'excludePlatforms']),
          locations: pickOrNull(val(cond, 'locations'), ['includeLocations', 'excludeLocations']),
          devices: pickOrNull(val(cond, 'devices'), [
            'includeDevices',
            'excludeDevices',
            'deviceFilter',
          ]),
          authenticationFlows:
            flows === undefined ? null : { transferMethods: val(flows, 'transferMethods') },
        },
        grantControls:
          grant === undefined
            ? null
            : {
                ...pick(grant, [
                  'operator',
                  'builtInControls',
                  'customAuthenticationFactors',
                  'termsOfUse',
                ]),
                authenticationStrength: pickOrNull(val(grant, 'authenticationStrength'), [
                  'id',
                  'displayName',
                  'requirementsSatisfied',
                ]),
              },
        sessionControls:
          session === undefined
            ? null
            : {
                signInFrequency: pickOrNull(val(session, 'signInFrequency'), [
                  'isEnabled',
                  'value',
                  'type',
                  'frequencyInterval',
                ]),
                persistentBrowser: pickOrNull(val(session, 'persistentBrowser'), [
                  'isEnabled',
                  'mode',
                ]),
              },
      };
    });
  },

  'entra.userRegistrationDetails': async (state, context) => {
    if (
      !licensed(
        state,
        context,
        P1_PLANS,
        'Authentication methods activity reports (Microsoft Entra ID P1/P2)',
      )
    )
      return null;
    const items = await getAll(
      state,
      context,
      `${GRAPH_BASE}/reports/authenticationMethods/userRegistrationDetails`,
    );
    return items.map((raw) =>
      pick(rec(raw), [
        'id',
        'userPrincipalName',
        'userType',
        'isAdmin',
        'isMfaRegistered',
        'isMfaCapable',
        'isPasswordlessCapable',
        'isSsprRegistered',
        'methodsRegistered',
      ]),
    );
  },

  'entra.roleDefinitions': async (state, context) => {
    const items = await getAll(
      state,
      context,
      `${GRAPH_BASE}/roleManagement/directory/roleDefinitions`,
    );
    // isPrivileged is only returned by the beta endpoint; it stays null from v1.0.
    return items.map((raw) =>
      pick(rec(raw), ['id', 'displayName', 'templateId', 'isBuiltIn', 'isEnabled', 'isPrivileged']),
    );
  },

  'entra.roleAssignments': async (state, context) => {
    const items = await getAll(
      state,
      context,
      `${GRAPH_BASE}/roleManagement/directory/roleAssignments?$expand=principal`,
    );
    return items.map((raw) => {
      const a = rec(raw);
      const principal = rec(val(a, 'principal'));
      return {
        ...pick(a, ['id', 'roleDefinitionId', 'principalId', 'directoryScopeId']),
        principal:
          principal === undefined
            ? null
            : {
                ...pick(principal, [
                  'id',
                  'displayName',
                  'userPrincipalName',
                  'userType',
                  'accountEnabled',
                  'onPremisesSyncEnabled',
                ]),
                principalType: principalType(principal['@odata.type']),
              },
      };
    });
  },

  'entra.guestUsers': async (state, context) => {
    const base = `${GRAPH_BASE}/users?$filter=${encodeURIComponent("userType eq 'Guest'")}&$top=999&$select=`;
    const fields = 'id,userPrincipalName,accountEnabled,createdDateTime,externalUserState';
    let items: unknown[];
    let withActivity = true;
    try {
      items = await getAll(state, context, `${base}${fields},signInActivity`);
    } catch (error) {
      // signInActivity needs AuditLog.Read.All and Entra ID P1/P2; collect the rest and flag the gap.
      if (
        !(error instanceof GraphRequestError) ||
        error.kind !== 'http' ||
        !(error.status === 403 || error.licenceHint)
      )
        throw error;
      withActivity = false;
      items = await getAll(state, context, `${base}${fields}`);
      state.errors.push(
        message(
          'SIGNIN_ACTIVITY_UNAVAILABLE',
          `Last sign-in times are unavailable (${error.message} signInActivity requires AuditLog.Read.All and Microsoft Entra ID P1/P2). Guest accounts were collected without activity data.`,
        ),
      );
      state.partial = true;
    }
    return items.map((raw) => {
      const u = rec(raw);
      const activity = withActivity ? rec(val(u, 'signInActivity')) : undefined;
      return {
        ...pick(u, [
          'id',
          'userPrincipalName',
          'accountEnabled',
          'createdDateTime',
          'externalUserState',
        ]),
        lastSignInDateTime: val(activity, 'lastSignInDateTime'),
        lastNonInteractiveSignInDateTime: val(activity, 'lastNonInteractiveSignInDateTime'),
      };
    });
  },
};

function enabledServicePlans(skus: readonly (Rec | undefined)[]): Set<string> {
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
