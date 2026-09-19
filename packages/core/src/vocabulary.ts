/**
 * Shared vocabulary for AdminSecOps. These values are part of the public data
 * contract (reports, API responses, stored assessments). Changing or removing a
 * value is a breaking change and requires a schema version bump.
 */

/** Result of evaluating one control against one assessment. */
export const CONTROL_STATUSES = [
  'PASS',
  'FAIL',
  'REVIEW',
  'NOT_APPLICABLE',
  'NOT_ASSESSED',
  'ERROR',
] as const;
export type ControlStatus = (typeof CONTROL_STATUSES)[number];

/** Statuses that produce a finding an administrator should look at. */
export const FINDING_STATUSES = ['FAIL', 'REVIEW'] as const satisfies readonly ControlStatus[];
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export function isFindingStatus(status: ControlStatus): status is FindingStatus {
  return status === 'FAIL' || status === 'REVIEW';
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const;
export type Severity = (typeof SEVERITIES)[number];

/**
 * How certain the control logic is that the evidence supports the result.
 * - high: the evidence directly states the configuration being evaluated.
 * - medium: the result depends on interpretation (e.g. ACL analysis or a threshold
 *   defined by the control), or evidence may be incomplete by design.
 * - low: the result is indicative only and must be confirmed by an administrator.
 */
export const CONFIDENCES = ['high', 'medium', 'low'] as const;
export type Confidence = (typeof CONFIDENCES)[number];

/** Technology areas. A control belongs to exactly one technology. */
export const TECHNOLOGIES = [
  'entra',
  'm365',
  'azure',
  'intune',
  'ad',
  'adcs',
  'windows',
  'gpo',
  'hybrid',
] as const;
export type Technology = (typeof TECHNOLOGIES)[number];

export const TECHNOLOGY_LABELS: Record<Technology, string> = {
  entra: 'Entra ID',
  m365: 'Microsoft 365',
  azure: 'Azure',
  intune: 'Intune',
  ad: 'Active Directory',
  adcs: 'AD CS / PKI',
  windows: 'Windows',
  gpo: 'Group Policy',
  hybrid: 'Hybrid identity',
};

/**
 * Collector modules. A module produces one or more datasets. Module names match the
 * `-Module` parameter of `Invoke-AdminSecOpsCollection`.
 */
export const COLLECTOR_MODULES = ['Entra', 'M365', 'Exchange', 'Intune', 'Azure', 'AD', 'ADCS', 'GPO', 'Windows'] as const;
export type CollectorModule = (typeof COLLECTOR_MODULES)[number];

/**
 * Collection status reported by a collector for one evidence file (dataset).
 * - Success: the dataset was collected completely.
 * - Partial: some objects or pages could not be collected; see errors.
 * - Failed: the dataset could not be collected.
 * - Unauthorized: the collector lacked permission; see errors.
 * - NotCollected: the dataset was intentionally skipped (option not selected, prerequisite missing).
 * - NotApplicable: the dataset does not apply to this environment (e.g. licence absent).
 */
export const COLLECTION_STATUSES = [
  'Success',
  'Partial',
  'Failed',
  'Unauthorized',
  'NotCollected',
  'NotApplicable',
] as const;
export type CollectionStatus = (typeof COLLECTION_STATUSES)[number];

/** Collection statuses whose `data` payload may be evaluated. */
export function isUsableCollectionStatus(status: CollectionStatus): boolean {
  return status === 'Success' || status === 'Partial';
}

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  informational: 1,
};

export const CONFIDENCE_RANK: Record<Confidence, number> = {
  high: 3,
  medium: 2,
  low: 1,
};

/** Sort comparator: most severe first. */
export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_RANK[b] - SEVERITY_RANK[a];
}
