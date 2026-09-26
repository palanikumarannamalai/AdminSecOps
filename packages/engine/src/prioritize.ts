import { CONFIDENCE_RANK, SEVERITY_RANK, type Confidence, type Severity } from '@adminsecops/core';
import type { Priority, PriorityTier } from '@adminsecops/schemas';

/**
 * Tags that indicate a finding is directly exploitable or affects the most sensitive
 * assets. Each present tag adds one point to the tie-breaker (maximum 3).
 */
export const PRIORITY_TAGS: Readonly<Record<string, string>> = {
  'privileged-access': 'Affects privileged access',
  'internet-exposure': 'Exposed to the internet',
  'credential-exposure': 'Can expose credentials',
  'legacy-authentication': 'Allows legacy authentication (MFA bypass)',
  'mfa': 'Weakens multifactor authentication',
  'data-exfiltration': 'Enables data exfiltration',
};

export interface PrioritizationInput {
  key: string;
  status: 'FAIL' | 'REVIEW';
  severity: Severity;
  confidence: Confidence;
  tags: readonly string[];
  effort: 'low' | 'medium' | 'high';
}

/**
 * Deterministic "what should I fix first?" ordering. This is an ordering, not a
 * security score. The sort key is lexicographic in this order:
 *   1. status (FAIL before REVIEW: evidenced findings before ones needing judgement)
 *   2. severity (critical > high > medium > low > informational)
 *   3. confidence (high > medium > low)
 *   4. exposure tags (count of PRIORITY_TAGS present, max 3)
 *   5. effort (low effort first, so quick wins surface within equal risk)
 * Ties are broken by finding key (control ID) so the order is fully reproducible.
 * Documented in docs/CONTROL-MODEL.md and covered by prioritize.test.ts.
 */
export function sortKeyFor(input: PrioritizationInput): number {
  const severity = SEVERITY_RANK[input.severity];
  const status = input.status === 'FAIL' ? 2 : 1;
  const confidence = CONFIDENCE_RANK[input.confidence];
  const tagCount = Math.min(input.tags.filter((t) => t in PRIORITY_TAGS).length, 3);
  const effort = input.effort === 'low' ? 2 : input.effort === 'medium' ? 1 : 0;
  return status * 100000 + severity * 10000 + confidence * 100 + tagCount * 10 + effort;
}

export function tierFor(input: PrioritizationInput): PriorityTier {
  if (input.status === 'REVIEW') return 'review';
  const severe = input.severity === 'critical' || input.severity === 'high';
  if (severe && input.confidence !== 'low') return 'fix-now';
  if (severe || input.severity === 'medium') return 'fix-next';
  return 'plan';
}

export function factorsFor(input: PrioritizationInput): string[] {
  const factors = [
    `${input.status === 'REVIEW' ? 'Potential impact if confirmed' : 'Severity'}: ${input.severity}`,
    input.status === 'FAIL' ? 'Collected evidence does not meet this check (FAIL)' : 'Requires administrator review (REVIEW)',
    `Confidence: ${input.confidence}`,
  ];
  for (const tag of input.tags) {
    const label = PRIORITY_TAGS[tag];
    if (label !== undefined) factors.push(input.status === 'REVIEW' ? `Potential concern to verify: ${label}` : label);
  }
  factors.push(`Estimated effort: ${input.effort}`);
  return factors;
}

/** Assign unique ranks (1 = fix first) to all inputs. */
export function prioritize(inputs: readonly PrioritizationInput[]): Map<string, Priority> {
  const scored = inputs.map((input) => ({ input, sortKey: sortKeyFor(input) }));
  scored.sort((a, b) => b.sortKey - a.sortKey || a.input.key.localeCompare(b.input.key));
  const result = new Map<string, Priority>();
  scored.forEach(({ input, sortKey }, index) => {
    result.set(input.key, { rank: index + 1, tier: tierFor(input), sortKey, factors: factorsFor(input) });
  });
  return result;
}
