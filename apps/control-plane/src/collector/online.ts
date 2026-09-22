import type { CollectorModule } from '@adminsecops/core';
import type { EvidenceBundle } from '@adminsecops/evidence/browser';
import { entraGroupSettings, listDatasetDefinitions } from '@adminsecops/schemas';
import {
  HOSTED_ENTRA_DATASETS,
  derivePermissions,
  entraCollector,
  type GraphPermissionRequirement,
} from './entra.js';
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
 * Unified online collection: Microsoft Entra ID, Microsoft 365 (SharePoint/OneDrive and
 * the Teams settings delegated Graph exposes) and Microsoft Intune, read-only through
 * Microsoft Graph v1.0 with one bounded client, one time/size budget and tenant
 * verification before any other customer data is requested.
 */

const ONLINE_DATASETS: readonly PlannedDataset[] = [
  ...HOSTED_ENTRA_DATASETS.map((definition) => ({ definition, collector: entraCollector(definition.id) })),
  { definition: entraGroupSettings, collector: entraCollector(entraGroupSettings.id) },
  ...M365_PLAN,
  ...INTUNE_PLAN,
];

/** Dataset definitions the online collector produces, in collection order. */
export const ONLINE_DATASETS_COLLECTED = ONLINE_DATASETS.map((d) => d.definition);

const COLLECTED: ReadonlySet<string> = new Set(ONLINE_DATASETS_COLLECTED.map((d) => d.id));
const COLLECTED_MODULES: ReadonlySet<CollectorModule> = new Set(ONLINE_DATASETS_COLLECTED.map((d) => d.module));

/**
 * Modules the online collector cannot read at all. Exchange Online organization,
 * transport, anti-spam and Defender for Office 365 settings are exposed through Exchange
 * Online PowerShell; Microsoft Graph offers them only through Tenant Configuration
 * Management, which does not support delegated access. Licence, domain or tenant data
 * is never used as a substitute, so the email-protection controls stay NOT_ASSESSED.
 */
export const ONLINE_SKIPPED_MODULES: readonly SkippedModule[] = [
  {
    name: 'Exchange',
    code: 'NOT_AVAILABLE_ONLINE',
    reason:
      'Exchange Online and Defender for Office 365 configuration (organization, transport, audit, DKIM, anti-spam, forwarding, SMTP AUTH, Safe Attachments) is not available through delegated Microsoft Graph. These controls are not assessed online; use the AdminSecOps PowerShell collector with Exchange Online PowerShell to assess them.',
  },
];

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
export const ONLINE_GRAPH_PERMISSIONS: readonly GraphPermissionRequirement[] =
  derivePermissions(ONLINE_DATASETS_COLLECTED);
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
