import type { CollectorModule } from '@adminsecops/core';
import type { EvidenceBundle } from '@adminsecops/evidence/browser';
import {
  entraApiPermissionGrants,
  entraApplications,
  entraGroupSettings,
  entraOnPremisesSynchronization,
  entraRoleAssignmentScheduleInstances,
  entraRoleEligibilitySchedules,
  entraServicePrincipals,
  listDatasetDefinitions,
} from '@adminsecops/schemas';
import { AZURE_PLAN } from './azure.js';
import {
  HOSTED_ENTRA_DATASETS,
  derivePermissions,
  entraCollector,
  type GraphPermissionRequirement,
} from './entra.js';
import { EXCHANGE_PLAN } from './exchange.js';
import { INTUNE_PLAN } from './intune.js';
import { M365_PLAN } from './m365.js';
import {
  collectHostedEvidence,
  type CollectionPlan,
  type HostedCollectionOptions,
  type HostedCollectionResult,
  type PlannedDataset,
  type SkippedModule,
} from './package.js';

/**
 * Unified online collection with one bounded budget and tenant verification before any other
 * customer data is requested:
 * - Microsoft Graph v1.0 (delegated): Entra ID, SharePoint/OneDrive, Teams settings, Intune
 *   (plus one exact Graph beta exception for Intune tenant compliance settings).
 * - Azure Resource Manager (separate delegated ARM token): Azure subscriptions of the tenant.
 * - Exchange Online (separate delegated Exchange Online token, fixed server-side runner).
 * - Public DNS: SPF and DMARC records of the tenant's mail domains.
 * A connector that is not connected, not consented or not available on the server produces
 * datasets with an explicit status and code, never passing evidence.
 */

const ADDITIONAL_ENTRA = [
  entraGroupSettings,
  entraRoleAssignmentScheduleInstances,
  entraRoleEligibilitySchedules,
  entraApplications,
  entraServicePrincipals,
  entraApiPermissionGrants,
  entraOnPremisesSynchronization,
];

const ONLINE_DATASETS: readonly PlannedDataset[] = [
  ...HOSTED_ENTRA_DATASETS.map((definition) => ({ definition, collector: entraCollector(definition.id) })),
  ...ADDITIONAL_ENTRA.map((definition) => ({ definition, collector: entraCollector(definition.id) })),
  ...M365_PLAN,
  ...INTUNE_PLAN,
  ...AZURE_PLAN,
  ...EXCHANGE_PLAN,
];

/** Dataset definitions the online collector produces, in collection order. */
export const ONLINE_DATASETS_COLLECTED = ONLINE_DATASETS.map((d) => d.definition);

const COLLECTED: ReadonlySet<string> = new Set(ONLINE_DATASETS_COLLECTED.map((d) => d.id));
const COLLECTED_MODULES: ReadonlySet<CollectorModule> = new Set(ONLINE_DATASETS_COLLECTED.map((d) => d.module));

/**
 * Modules the online collector cannot read at all. Active Directory, AD CS, Group Policy and
 * Windows hosts are in private customer networks; see docs/ONLINE-CONNECTORS.md for the
 * on-premises connector design. They are not part of the online manifest.
 */
export const ONLINE_SKIPPED_MODULES: readonly SkippedModule[] = [];

/** Registry datasets of collected modules that the online collector does not produce, per module. */
export const ONLINE_NOT_COLLECTED: ReadonlyMap<CollectorModule, readonly string[]> = (() => {
  const map = new Map<CollectorModule, string[]>();
  for (const definition of listDatasetDefinitions()) {
    if (!COLLECTED_MODULES.has(definition.module) || COLLECTED.has(definition.id)) continue;
    map.set(definition.module, [...(map.get(definition.module) ?? []), definition.id]);
  }
  return map;
})();

/** Microsoft Graph delegated permissions the online collector uses, derived from the dataset definitions. */
export const ONLINE_GRAPH_PERMISSIONS: readonly GraphPermissionRequirement[] = derivePermissions(
  ONLINE_DATASETS_COLLECTED.filter((d) => d.source === 'MicrosoftGraph' || d.source === 'AzureResourceManager'),
);
export const ONLINE_REQUIRED_GRAPH_PERMISSIONS: readonly string[] = ONLINE_GRAPH_PERMISSIONS.map(
  (p) => p.permission,
);

export type CollectOnlineOptions = HostedCollectionOptions;
export type OnlineCollectionResult = HostedCollectionResult;

export async function collectOnline(options: CollectOnlineOptions): Promise<EvidenceBundle> {
  return (await collectOnlineEvidence(options)).bundle;
}

export async function collectOnlineEvidence(
  options: CollectOnlineOptions,
): Promise<OnlineCollectionResult> {
  const plan: CollectionPlan = {
    datasets: ONLINE_DATASETS,
    notCollected: ONLINE_NOT_COLLECTED,
    skippedModules: ONLINE_SKIPPED_MODULES,
  };
  return collectHostedEvidence(options, plan);
}
