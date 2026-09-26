import {
  azureActivityLogDiagnostics,
  azureDefenderPlans,
  azureKeyVaults,
  azureNetworkSecurityGroups,
  azureRoleAssignments,
  azureSecurityContacts,
  azureStorageAccounts,
  azureSubscriptions,
} from '@adminsecops/schemas';
import { ARM_OPERATIONS, armUrl, type ArmOperation } from './arm-client.js';
import { GRAPH_BASE, GraphRequestError } from './graph-client.js';
import type { PlannedDataset } from './package.js';
import {
  arr,
  connectorUnavailable,
  getAll,
  message,
  rec,
  safeId,
  val,
  type ArmRuntime,
  type CollectionContext,
  type DatasetCollector,
  type DatasetState,
  type Rec,
} from './runtime.js';

/**
 * Azure datasets through Azure Resource Manager (GET only) with the separate, delegated ARM
 * token of the signed-in administrator. Mirrors collectors/powershell/azure/Azure.ps1 without
 * its coercions: a missing value stays null so the dataset schema decides.
 *
 * Tenant binding: only subscriptions whose tenantId is the verified session tenant are
 * assessed. Subscriptions of other tenants that the account can see (for example through
 * Azure Lighthouse or guest access) are excluded and counted, never collected.
 */

const READABLE_STATES = new Set(['enabled', 'warned', 'pastdue']);
const VISIBILITY_NOTE =
  'Only subscriptions of this tenant that the signed-in account can read (Reader or higher) are included; subscriptions it cannot see are not assessed.';

function connected(state: DatasetState, context: CollectionContext): ArmRuntime | null {
  const arm = context.arm;
  if (arm === undefined) {
    return connectorUnavailable(state, { state: 'not-connected', reason: 'Azure Resource Manager is not connected for this session.' });
  }
  if (arm.state !== 'connected') return connectorUnavailable(state, arm);
  return arm;
}

const subscriptions: DatasetCollector = async (state, context) => {
  const arm = connected(state, context);
  if (arm === null) return null;
  const url = armUrl('subscriptions');
  if (url === undefined) throw new GraphRequestError('url-rejected', 'The subscription list URL could not be built.');
  let items: (Rec | undefined)[];
  try {
    items = (await getAll(state, context, url, arm.client)).map((s) => rec(s));
  } catch (error) {
    if (error instanceof GraphRequestError) arm.listError = error;
    throw error;
  }
  let otherTenant = 0;
  let unbound = 0;
  const own: Rec[] = [];
  for (const s of items) {
    const tenant = val(s, 'tenantId');
    if (typeof tenant !== 'string') unbound += 1;
    else if (tenant.toLowerCase() !== context.tenantId) otherTenant += 1;
    else own.push(s ?? {});
  }
  if (otherTenant > 0) {
    state.warnings.push(
      message('SUBSCRIPTIONS_OTHER_TENANT', `${otherTenant} visible subscription(s) belong to another tenant and were excluded; only subscriptions of the verified tenant are assessed.`),
    );
  }
  if (unbound > 0) {
    state.partial = true;
    state.errors.push(message('SUBSCRIPTION_TENANT_UNKNOWN', `${unbound} subscription(s) were returned without a tenant ID and were excluded because they cannot be bound to the verified tenant.`));
  }
  const ids: string[] = [];
  for (const s of own) {
    const id = val(s, 'subscriptionId');
    const lifecycle = val(s, 'state');
    if (typeof id === 'string' && safeId(id) !== undefined && typeof lifecycle === 'string' && READABLE_STATES.has(lifecycle.toLowerCase())) ids.push(id.toLowerCase());
  }
  if (own.length === 0) {
    state.warnings.push(
      message('NO_VISIBLE_SUBSCRIPTIONS', 'No subscription of this tenant is visible to the signed-in account. Either the tenant has none or the account has no Azure role (Reader or higher) on any subscription; Azure controls are not assessed.'),
    );
  }
  state.warnings.push(message('SUBSCRIPTION_VISIBILITY', VISIBILITY_NOTE));
  arm.subscriptions = { ids, complete: !state.partial };
  return own.map((s) => ({
    subscriptionId: val(s, 'subscriptionId'),
    displayName: val(s, 'displayName'),
    state: val(s, 'state'),
    tenantId: val(s, 'tenantId'),
  }));
};

/**
 * One ARM list per assessed subscription. Failures are isolated per subscription (Partial);
 * when every subscription fails the dataset gets the common failure status, so an account
 * without Reader rights is reported Unauthorized and its controls NOT_ASSESSED.
 */
async function perSubscription(
  state: DatasetState,
  context: CollectionContext,
  operation: ArmOperation,
): Promise<Map<string, unknown[]> | null> {
  const arm = connected(state, context);
  if (arm === null) return null;
  const known = arm.subscriptions;
  if (known === undefined) {
    const e = arm.listError;
    state.forcedStatus =
      e?.kind === 'http' && (e.status === 401 || e.status === 403)
        ? { status: 'Unauthorized', code: 'SUBSCRIPTIONS_UNAUTHORIZED', message: `Azure Resource Manager refused to list subscriptions (${e.message}) Reconnect Azure; no subscription was assessed.` }
        : { status: 'Failed', code: 'SUBSCRIPTIONS_UNAVAILABLE', message: 'The subscription list could not be read, so no subscription was assessed.' };
    return null;
  }
  if (known.ids.length === 0) {
    state.forcedStatus = {
      status: 'Unauthorized',
      code: 'NO_ACCESSIBLE_SUBSCRIPTIONS',
      message: 'No enabled subscription of this tenant is visible to the signed-in account. Assign the Azure Reader role on the subscriptions to assess (or confirm the tenant has none); these controls are not assessed.',
    };
    return null;
  }
  if (!known.complete) {
    state.partial = true;
    state.errors.push(message('SUBSCRIPTION_LIST_INCOMPLETE', 'The subscription list was incomplete, so some subscriptions may not be included.'));
  }
  state.warnings.push(message('SUBSCRIPTION_VISIBILITY', VISIBILITY_NOTE));
  const op = ARM_OPERATIONS[operation];
  const template = `https://management.azure.com/subscriptions/{id}${op.path}?api-version=${op.apiVersion}`;
  const results = new Map<string, unknown[]>();
  const failures: GraphRequestError[] = [];
  const cap = Math.max(0, Math.floor(context.limits.maxFanoutRequests));
  for (const [index, id] of known.ids.entries()) {
    arm.client.throwIfCancelled();
    if (index >= cap) {
      state.partial = true;
      state.errors.push(message('FANOUT_LIMIT', `Stopped after ${cap} subscription(s) (collection limit); ${known.ids.length - cap} subscription(s) were not read.`));
      break;
    }
    const url = armUrl(operation, id);
    if (url === undefined) continue;
    try {
      results.set(id, await getAll(state, context, url, arm.client, template));
    } catch (error) {
      if (!(error instanceof GraphRequestError)) throw error;
      failures.push(error);
      state.errors.push(message(error.kind === 'http' && (error.status === 401 || error.status === 403) ? 'UNAUTHORIZED' : 'SUBSCRIPTION_FAILED', `The subscription could not be read. ${error.message}`, `subscription ${id}`));
      if (error.kind === 'budget-exhausted') break;
    }
  }
  if (results.size === 0 && failures.length > 0) {
    const denied = failures.every((e) => e.kind === 'http' && (e.status === 401 || e.status === 403) && !e.licenceHint);
    state.forcedStatus = denied
      ? { status: 'Unauthorized', code: 'READER_REQUIRED', message: 'The signed-in account cannot read this data in any assessed subscription. The Azure Reader role (or higher) on the subscriptions is required; these controls are not assessed.' }
      : { status: 'Failed', code: 'ALL_SUBSCRIPTIONS_FAILED', message: 'The data could not be read from any assessed subscription.' };
    return null;
  }
  if (failures.length > 0 || results.size < known.ids.length) state.partial = true;
  return results;
}

function resourceGroupOf(id: unknown): string | null {
  if (typeof id !== 'string') return null;
  return /\/resourceGroups\/([^/]+)(?:\/|$)/i.exec(id)?.[1] ?? null;
}

const props = (item: unknown): Rec | undefined => rec(val(rec(item), 'properties'));

/** Principal names through Graph GET /directoryObjects/{id} (Graph token only), bounded. */
async function principalNames(state: DatasetState, context: CollectionContext, ids: readonly string[]): Promise<Map<string, { displayName: unknown; userPrincipalName: unknown }>> {
  const names = new Map<string, { displayName: unknown; userPrincipalName: unknown }>();
  const unique = [...new Set(ids.map((id) => id.toLowerCase()))].filter((id) => safeId(id) !== undefined);
  const cap = Math.max(0, Math.floor(context.limits.maxFanoutRequests));
  if (unique.length === 0) return names;
  state.operations.push(`GET ${GRAPH_BASE}/directoryObjects/{principalId}?$select=id,displayName,userPrincipalName`);
  if (unique.length > cap) {
    state.warnings.push(message('PRINCIPAL_NAMES_TRUNCATED', `Only the first ${cap} of ${unique.length} principals were resolved to names.`));
  }
  let failed = 0;
  for (const id of unique.slice(0, cap)) {
    context.client.throwIfCancelled();
    try {
      const o = rec(await context.client.get(`${GRAPH_BASE}/directoryObjects/${encodeURIComponent(id)}?$select=id,displayName,userPrincipalName`));
      names.set(id, { displayName: val(o, 'displayName'), userPrincipalName: val(o, 'userPrincipalName') });
    } catch (error) {
      if (!(error instanceof GraphRequestError)) throw error;
      failed += 1;
      if (error.kind === 'budget-exhausted') break;
    }
  }
  if (failed > 0) {
    state.warnings.push(message('PRINCIPAL_NAMES_PARTIAL', `${failed} principal(s) could not be resolved to a name (deleted objects, other tenants or insufficient Graph permissions).`));
  }
  return names;
}

const roleAssignments: DatasetCollector = async (state, context) => {
  const perSub = await perSubscription(state, context, 'roleAssignments');
  if (perSub === null) return null;
  const arm = context.arm as ArmRuntime;
  const roleNames = new Map<string, string>();
  const defs = ARM_OPERATIONS.roleDefinitions;
  for (const subscriptionId of perSub.keys()) {
    const url = armUrl('roleDefinitions', subscriptionId);
    if (url === undefined) continue;
    try {
      for (const def of await getAll(state, context, url, arm.client, `https://management.azure.com/subscriptions/{id}${defs.path}?api-version=${defs.apiVersion}`)) {
        const name = val(rec(def), 'name');
        const roleName = val(props(def), 'roleName');
        if (typeof name === 'string' && typeof roleName === 'string') roleNames.set(name.toLowerCase(), roleName);
      }
    } catch (error) {
      if (!(error instanceof GraphRequestError)) throw error;
      // Role names fall back to the role definition GUID; controls also match built-in role IDs.
      state.warnings.push(message('ROLE_NAMES_UNRESOLVED', `Role definition names could not be read; role definition IDs are reported instead. ${error.message}`, `subscription ${subscriptionId}`));
    }
  }
  const principalIds = [...perSub.values()].flat().map((a) => val(props(a), 'principalId')).filter((p): p is string => typeof p === 'string');
  const names = await principalNames(state, context, principalIds);
  const out: Rec[] = [];
  for (const [subscriptionId, list] of perSub) {
    for (const a of list) {
      const p = props(a);
      const roleDefinitionId = val(p, 'roleDefinitionId');
      const roleGuid = typeof roleDefinitionId === 'string' ? (roleDefinitionId.split('/').pop() ?? '').toLowerCase() : '';
      const principalId = val(p, 'principalId');
      const resolved = typeof principalId === 'string' ? names.get(principalId.toLowerCase()) : undefined;
      const principalType = val(p, 'principalType');
      out.push({
        subscriptionId,
        roleAssignmentId: val(rec(a), 'id'),
        scope: val(p, 'scope'),
        roleDefinitionName: roleNames.get(roleGuid) ?? (roleGuid === '' ? null : roleGuid),
        roleDefinitionId,
        principalId,
        principalType: typeof principalType === 'string' && principalType !== '' ? principalType : 'Unknown',
        principalDisplayName: resolved?.displayName ?? null,
        principalSignInName: resolved?.userPrincipalName ?? null,
      });
    }
  }
  return out;
};

const defenderPlans: DatasetCollector = async (state, context) => {
  const perSub = await perSubscription(state, context, 'pricings');
  if (perSub === null) return null;
  return [...perSub].flatMap(([subscriptionId, list]) =>
    list.map((p) => ({ subscriptionId, name: val(rec(p), 'name'), pricingTier: val(props(p), 'pricingTier'), subPlan: val(props(p), 'subPlan') })),
  );
};

const securityContacts: DatasetCollector = async (state, context) => {
  const perSub = await perSubscription(state, context, 'securityContacts');
  if (perSub === null) return null;
  return [...perSub].map(([subscriptionId, list]) => ({
    subscriptionId,
    contacts: list.map((c) => {
      const p = props(c);
      // Only the number of addresses is kept; the addresses themselves are never stored.
      const emails = val(p, 'emails');
      const emailCount = typeof emails === 'string' ? emails.split(/[;,]/).filter((e) => e.trim() !== '').length : 0;
      const alert = arr(val(p, 'notificationsSources'))?.map((s) => rec(s)).find((s) => val(s, 'sourceType') === 'Alert');
      const byRole = rec(val(p, 'notificationsByRole'));
      return {
        name: val(rec(c), 'name'),
        emailCount,
        isEnabled: val(p, 'isEnabled'),
        notifyRoles: arr(val(byRole, 'roles')),
        notifyRolesState: val(byRole, 'state'),
        alertMinimalSeverity: val(alert, 'minimalSeverity'),
      };
    }),
  }));
};

const storageAccounts: DatasetCollector = async (state, context) => {
  const perSub = await perSubscription(state, context, 'storageAccounts');
  if (perSub === null) return null;
  return [...perSub].flatMap(([subscriptionId, list]) =>
    list.map((s) => {
      const p = props(s);
      const id = val(rec(s), 'id');
      return {
        subscriptionId,
        id,
        name: val(rec(s), 'name'),
        resourceGroup: resourceGroupOf(id),
        location: val(rec(s), 'location'),
        kind: val(rec(s), 'kind'),
        allowBlobPublicAccess: val(p, 'allowBlobPublicAccess'),
        supportsHttpsTrafficOnly: val(p, 'supportsHttpsTrafficOnly'),
        minimumTlsVersion: val(p, 'minimumTlsVersion'),
        allowSharedKeyAccess: val(p, 'allowSharedKeyAccess'),
        publicNetworkAccess: val(p, 'publicNetworkAccess'),
        networkDefaultAction: val(rec(val(p, 'networkAcls')), 'defaultAction'),
      };
    }),
  );
};

const keyVaults: DatasetCollector = async (state, context) => {
  const perSub = await perSubscription(state, context, 'keyVaults');
  if (perSub === null) return null;
  return [...perSub].flatMap(([subscriptionId, list]) =>
    list.map((v) => {
      const p = props(v);
      const id = val(rec(v), 'id');
      return {
        subscriptionId,
        id,
        name: val(rec(v), 'name'),
        resourceGroup: resourceGroupOf(id),
        location: val(rec(v), 'location'),
        enableSoftDelete: val(p, 'enableSoftDelete'),
        softDeleteRetentionInDays: val(p, 'softDeleteRetentionInDays'),
        enablePurgeProtection: val(p, 'enablePurgeProtection'),
        enableRbacAuthorization: val(p, 'enableRbacAuthorization'),
        publicNetworkAccess: val(p, 'publicNetworkAccess'),
        networkDefaultAction: val(rec(val(p, 'networkAcls')), 'defaultAction'),
      };
    }),
  );
};

const networkSecurityGroups: DatasetCollector = async (state, context) => {
  const perSub = await perSubscription(state, context, 'networkSecurityGroups');
  if (perSub === null) return null;
  return [...perSub].flatMap(([subscriptionId, list]) =>
    list.map((n) => {
      const id = val(rec(n), 'id');
      const rules = arr(val(props(n), 'securityRules'));
      if (rules === null) {
        state.partial = true;
        state.errors.push(message('SECURITY_RULES_MISSING', 'A network security group was returned without its security rules.', typeof id === 'string' ? id : null));
      }
      // Custom rules only; defaultSecurityRules are intentionally excluded.
      return {
        subscriptionId,
        id,
        name: val(rec(n), 'name'),
        resourceGroup: resourceGroupOf(id),
        securityRules: (rules ?? []).map((r) => {
          const p = props(r);
          return {
            name: val(rec(r), 'name'),
            direction: val(p, 'direction'),
            access: val(p, 'access'),
            priority: val(p, 'priority'),
            protocol: val(p, 'protocol'),
            sourceAddressPrefix: val(p, 'sourceAddressPrefix'),
            sourceAddressPrefixes: arr(val(p, 'sourceAddressPrefixes')),
            destinationPortRange: val(p, 'destinationPortRange'),
            destinationPortRanges: arr(val(p, 'destinationPortRanges')),
          };
        }),
      };
    }),
  );
};

const activityLogDiagnostics: DatasetCollector = async (state, context) => {
  const perSub = await perSubscription(state, context, 'diagnosticSettings');
  if (perSub === null) return null;
  const present = (v: unknown): boolean => typeof v === 'string' && v.trim() !== '';
  return [...perSub].map(([subscriptionId, list]) => ({
    subscriptionId,
    settings: list.map((s) => {
      const p = props(s);
      const enabled = (arr(val(p, 'logs')) ?? [])
        .map((l) => rec(l))
        .filter((l) => val(l, 'enabled') === true)
        .map((l) => val(l, 'category') ?? val(l, 'categoryGroup'))
        .filter((c): c is string => typeof c === 'string' && c !== '');
      return {
        name: val(rec(s), 'name'),
        workspaceConfigured: present(val(p, 'workspaceId')),
        storageAccountConfigured: present(val(p, 'storageAccountId')),
        eventHubConfigured: present(val(p, 'eventHubAuthorizationRuleId')) || present(val(p, 'eventHubName')),
        enabledCategories: enabled,
      };
    }),
  }));
};

export const AZURE_PLAN: readonly PlannedDataset[] = [
  { definition: azureSubscriptions, collector: subscriptions },
  { definition: azureRoleAssignments, collector: roleAssignments },
  { definition: azureDefenderPlans, collector: defenderPlans },
  { definition: azureSecurityContacts, collector: securityContacts },
  { definition: azureStorageAccounts, collector: storageAccounts },
  { definition: azureKeyVaults, collector: keyVaults },
  { definition: azureNetworkSecurityGroups, collector: networkSecurityGroups },
  { definition: azureActivityLogDiagnostics, collector: activityLogDiagnostics },
];
