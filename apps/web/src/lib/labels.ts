import type { CollectionStatus, Confidence, ControlStatus, Severity } from '@adminsecops/core';
import type { AssessmentComparison, FrameworkId, PriorityTier } from '@adminsecops/schemas';

export const STATUS_LABELS: Record<ControlStatus, string> = {
  PASS: 'Pass',
  FAIL: 'Fail',
  REVIEW: 'Review',
  NOT_APPLICABLE: 'Not applicable',
  NOT_ASSESSED: 'Not assessed',
  ERROR: 'Error',
};

export const STATUS_DESCRIPTIONS: Record<ControlStatus, string> = {
  PASS: 'The evidence shows the expected configuration.',
  FAIL: 'The evidence shows a configuration that does not meet the expected state.',
  REVIEW: 'The result depends on context that an administrator must confirm.',
  NOT_APPLICABLE: 'The control does not apply to this environment.',
  NOT_ASSESSED: 'Required evidence was not available, so the control was not evaluated.',
  ERROR: 'The control could not be evaluated because of an error.',
};

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Informational',
};

export const CONFIDENCE_LABELS: Record<Confidence, string> = {
  high: 'High confidence',
  medium: 'Medium confidence',
  low: 'Low confidence',
};

export const CONFIDENCE_SHORT_LABELS: Record<Confidence, string> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

export const TIER_ORDER: readonly PriorityTier[] = ['fix-now', 'fix-next', 'plan', 'review'];

export const TIER_LABELS: Record<PriorityTier, string> = {
  'fix-now': 'Fix now',
  'fix-next': 'Fix next',
  plan: 'Plan',
  review: 'Review',
};

export const TIER_DESCRIPTIONS: Record<PriorityTier, string> = {
  'fix-now': 'Confirmed critical or high severity issues with medium or high confidence.',
  'fix-next': 'Confirmed medium severity issues, or high severity issues with low confidence.',
  plan: 'Confirmed low or informational issues to schedule into normal change windows.',
  review: 'Results that need an administrator to confirm whether the configuration is intended.',
};

export const EFFORT_LABELS: Record<'low' | 'medium' | 'high', string> = {
  low: 'Low effort',
  medium: 'Medium effort',
  high: 'High effort',
};

export const COLLECTION_STATUS_LABELS: Record<CollectionStatus, string> = {
  Success: 'Success',
  Partial: 'Partial',
  Failed: 'Failed',
  Unauthorized: 'Unauthorized',
  NotCollected: 'Not collected',
  NotApplicable: 'Not applicable',
};

/**
 * Display names of the framework identifiers. Kept in the web bundle (instead of
 * importing the zod-based schema module at runtime); `satisfies` keeps the keys in
 * sync with FRAMEWORKS in @adminsecops/schemas, and a unit test checks the labels.
 */
export const FRAMEWORK_LABELS = {
  'NIST-800-53r5': 'NIST SP 800-53 Rev. 5',
  'CISA-SCuBA': 'CISA Secure Cloud Business Applications (SCuBA) baselines',
  'MITRE-ATTACK': 'MITRE ATT&CK (Enterprise)',
  MCSB: 'Microsoft cloud security benchmark',
} as const satisfies Record<FrameworkId, string>;

export function frameworkLabel(id: string): string {
  return id in FRAMEWORK_LABELS ? FRAMEWORK_LABELS[id as FrameworkId] : id;
}

export type ComparisonDirection = AssessmentComparison['direction'];

export const DIRECTION_LABELS: Record<ComparisonDirection, string> = {
  improved: 'Improved',
  regressed: 'Regressed',
  mixed: 'Mixed',
  unchanged: 'Unchanged',
};

export const DIRECTION_DESCRIPTIONS: Record<ComparisonDirection, string> = {
  improved: 'Findings were resolved and no new findings appeared.',
  regressed: 'New findings appeared and none were resolved.',
  mixed: 'Some findings were resolved and some new findings appeared.',
  unchanged: 'No findings were resolved and no new findings appeared.',
};
