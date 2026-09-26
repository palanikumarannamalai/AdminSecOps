import type { CollectionStatus } from '@adminsecops/core';
import type { AssessmentResult } from '../api/types';

/**
 * Per-workload assessment coverage, computed only from what an assessment result records:
 * which datasets were actually collected, why others were not, and how many catalogue
 * controls produced a verdict. A workload whose evidence is missing is reported as not
 * assessed; it never counts as passing.
 */

export type WorkloadKey = 'entra' | 'exchange' | 'sharepoint' | 'teams' | 'intune' | 'azure' | 'onprem' | 'other';

export interface WorkloadDefinition {
  key: WorkloadKey;
  label: string;
}

export const WORKLOADS: readonly WorkloadDefinition[] = [
  { key: 'entra', label: 'Microsoft Entra ID' },
  { key: 'exchange', label: 'Exchange Online and email protection' },
  { key: 'sharepoint', label: 'SharePoint and OneDrive' },
  { key: 'teams', label: 'Microsoft Teams' },
  { key: 'intune', label: 'Microsoft Intune' },
  { key: 'azure', label: 'Azure subscriptions' },
  { key: 'onprem', label: 'On-premises (AD, AD CS, Group Policy, Windows)' },
  { key: 'other', label: 'Other' },
];

export function workloadOfDataset(datasetId: string): WorkloadKey {
  const prefix = datasetId.slice(0, datasetId.indexOf('.'));
  if (prefix === 'entra') return 'entra';
  if (prefix === 'exchange') return 'exchange';
  if (prefix === 'intune') return 'intune';
  if (prefix === 'azure') return 'azure';
  if (['ad', 'adcs', 'gpo', 'windows'].includes(prefix)) return 'onprem';
  if (datasetId === 'm365.sharePointSettings') return 'sharepoint';
  if (datasetId.startsWith('m365.teams')) return 'teams';
  return 'other';
}

/** Why a dataset is not usable, in administrator terms. */
export type GapReason = 'not-connected' | 'permission' | 'licence' | 'failed' | 'not-collected' | 'unsupported';

export const GAP_LABELS: Record<GapReason, string> = {
  'not-connected': 'Connector not connected or connection expired',
  permission: 'Missing permission or consent',
  licence: 'Not licensed or not applicable',
  failed: 'Collection failed or evidence was invalid',
  'not-collected': 'Not collected by this collector',
  unsupported: 'Not available to this collection method',
};

/** Collector message codes of the online connectors (apps/control-plane CONNECTOR_GAP_OUTCOME). */
const CONNECTOR_CODES: Readonly<Record<string, GapReason>> = {
  CONNECTOR_NOT_CONNECTED: 'not-connected',
  CONNECTOR_EXPIRED: 'not-connected',
  CONNECTOR_CONSENT_REQUIRED: 'permission',
  CONNECTOR_UNAVAILABLE: 'unsupported',
};

export function gapReason(status: CollectionStatus | null, moduleSkipped: boolean, codes: readonly string[] = []): GapReason {
  for (const code of codes) {
    const mapped = CONNECTOR_CODES[code];
    if (mapped !== undefined) return mapped;
  }
  if (status === 'Unauthorized') return 'permission';
  if (status === 'NotApplicable') return 'licence';
  if (status === 'Failed') return 'failed';
  if (status === null && moduleSkipped) return 'unsupported';
  return 'not-collected';
}

/** Order used to pick the reason shown for a workload with no usable evidence. */
const BLOCKER_PRIORITY: readonly GapReason[] = ['permission', 'failed', 'not-connected', 'unsupported', 'not-collected', 'licence'];

const ONLINE_COLLECTOR = 'AdminSecOps.HostedGraphCollector';
const ONPREM_REASON =
  'Active Directory, AD CS, Group Policy and Windows hosts are in private networks that the online service cannot reach. An outbound-only on-premises connector is designed but not available; these controls are not assessed online.';

export interface DatasetGap {
  datasetId: string;
  title: string;
  reason: GapReason;
  detail: string;
}

export interface WorkloadCoverage {
  key: WorkloadKey;
  label: string;
  /** Datasets collected completely or partially. */
  collected: string[];
  partial: string[];
  gaps: DatasetGap[];
  /** Controls in the library for this workload (the catalogue, not what was assessed). */
  catalogueControls: number;
  /** Controls with a PASS, FAIL or REVIEW verdict. */
  assessed: number;
  notAssessed: number;
  notApplicable: number;
  errors: number;
  /** Assessed: every dataset usable; partial: some evidence; not-assessed: no usable evidence. */
  state: 'assessed' | 'partial' | 'not-assessed';
  /** For a not-assessed workload: the main reason (not connected, consent, unsupported, failed...). */
  blocker: GapReason | null;
  /** Reasons recorded by the collector for modules it skipped entirely (for example not available online). */
  skippedReasons: string[];
}

export function computeCoverage(result: AssessmentResult): WorkloadCoverage[] {
  const online = result.collection.collector.name === ONLINE_COLLECTOR;
  const skippedModules = new Map(
    result.collection.modules.filter((m) => m.status === 'Skipped').map((m) => [m.name, m.warnings.map((w) => w.message)]),
  );
  const codes = new Map<string, string[]>();
  for (const issue of result.evidence.issues) {
    if (issue.datasetId === null) continue;
    codes.set(issue.datasetId, [...(codes.get(issue.datasetId) ?? []), issue.code]);
  }
  const byKey = new Map<WorkloadKey, WorkloadCoverage>(
    WORKLOADS.map((w) => [
      w.key,
      { key: w.key, label: w.label, collected: [], partial: [], gaps: [], catalogueControls: 0, assessed: 0, notAssessed: 0, notApplicable: 0, errors: 0, state: 'not-assessed', blocker: null, skippedReasons: [] },
    ]),
  );
  for (const dataset of result.evidence.datasets) {
    const key = workloadOfDataset(dataset.datasetId);
    const entry = byKey.get(key);
    if (entry === undefined) continue;
    if (dataset.state === 'available') entry.collected.push(dataset.datasetId);
    else if (dataset.state === 'partial') {
      entry.collected.push(dataset.datasetId);
      entry.partial.push(dataset.datasetId);
    } else {
      const skipped = skippedModules.get(dataset.module);
      if (skipped !== undefined) for (const reason of skipped) if (!entry.skippedReasons.includes(reason)) entry.skippedReasons.push(reason);
      // The online service cannot reach private networks: on-premises evidence is unsupported, not merely missing.
      const unreachable = online && key === 'onprem' && dataset.collectionStatus === null;
      if (unreachable && !entry.skippedReasons.includes(ONPREM_REASON)) entry.skippedReasons.push(ONPREM_REASON);
      entry.gaps.push({
        datasetId: dataset.datasetId,
        title: dataset.title,
        reason: gapReason(dataset.collectionStatus, skipped !== undefined || unreachable, codes.get(dataset.datasetId) ?? []),
        detail: dataset.reason,
      });
    }
  }
  for (const control of result.results) {
    const first = control.evidence[0]?.datasetId;
    const entry = byKey.get(first === undefined ? 'other' : workloadOfDataset(first));
    if (entry === undefined) continue;
    entry.catalogueControls += 1;
    if (control.status === 'PASS' || control.status === 'FAIL' || control.status === 'REVIEW') entry.assessed += 1;
    else if (control.status === 'NOT_APPLICABLE') entry.notApplicable += 1;
    else if (control.status === 'ERROR') entry.errors += 1;
    else entry.notAssessed += 1;
  }
  for (const entry of byKey.values()) {
    if (entry.collected.length === 0) {
      entry.state = 'not-assessed';
      entry.blocker = BLOCKER_PRIORITY.find((reason) => entry.gaps.some((g) => g.reason === reason)) ?? null;
    } else if (entry.gaps.length > 0 || entry.partial.length > 0 || entry.notAssessed > 0) entry.state = 'partial';
    else entry.state = 'assessed';
  }
  return [...byKey.values()].filter((w) => w.catalogueControls > 0 || w.collected.length > 0);
}
