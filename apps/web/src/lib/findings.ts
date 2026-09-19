import type { Confidence, Severity } from '@adminsecops/core';
import { CONFIDENCES, SEVERITIES } from '@adminsecops/core/vocabulary';
import type { Finding, PriorityTier } from '@adminsecops/schemas';
import { TIER_ORDER } from './labels';
import { isDashboardModuleId, moduleForTechnology, moduleLabel, type DashboardModuleId } from './modules';

export interface FindingFilters {
  module: DashboardModuleId | 'all';
  severity: Severity | 'all';
  status: 'FAIL' | 'REVIEW' | 'all';
  confidence: Confidence | 'all';
  tier: PriorityTier | 'all';
  search: string;
}

export const DEFAULT_FILTERS: FindingFilters = {
  module: 'all',
  severity: 'all',
  status: 'all',
  confidence: 'all',
  tier: 'all',
  search: '',
};

export const SORT_KEYS = ['priority', 'severity', 'title', 'module', 'confidence', 'affected'] as const;
export type FindingSortKey = (typeof SORT_KEYS)[number];
export type SortDirection = 'asc' | 'desc';

export interface FindingSort {
  key: FindingSortKey;
  direction: SortDirection;
}

/** Default: priority rank ascending (rank 1 = fix first). */
export const DEFAULT_SORT: FindingSort = { key: 'priority', direction: 'asc' };

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
const CONFIDENCE_ORDER: Record<Confidence, number> = { high: 0, medium: 1, low: 2 };

function matchesSearch(finding: Finding, search: string): boolean {
  const needle = search.trim().toLowerCase();
  if (needle === '') return true;
  const haystack = [
    finding.title,
    finding.controlId,
    finding.category,
    finding.description,
    moduleLabel(moduleForTechnology(finding.technology)),
    ...finding.tags,
  ]
    .join('\n')
    .toLowerCase();
  return needle.split(/\s+/).every((term) => haystack.includes(term));
}

export function filterFindings(findings: readonly Finding[], filters: FindingFilters): Finding[] {
  return findings.filter(
    (f) =>
      (filters.module === 'all' || moduleForTechnology(f.technology) === filters.module) &&
      (filters.severity === 'all' || f.severity === filters.severity) &&
      (filters.status === 'all' || f.status === filters.status) &&
      (filters.confidence === 'all' || f.confidence === filters.confidence) &&
      (filters.tier === 'all' || f.priority.tier === filters.tier) &&
      matchesSearch(f, filters.search),
  );
}

/**
 * "Ascending" means the natural reading order of each column: rank 1 first,
 * most severe first, highest confidence first, A-Z, most affected objects first.
 */
function compareBy(key: FindingSortKey, a: Finding, b: Finding): number {
  switch (key) {
    case 'priority':
      return a.priority.rank - b.priority.rank;
    case 'severity':
      return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    case 'confidence':
      return CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence];
    case 'title':
      return a.title.localeCompare(b.title);
    case 'module':
      return moduleLabel(moduleForTechnology(a.technology)).localeCompare(moduleLabel(moduleForTechnology(b.technology)));
    case 'affected':
      return b.affectedObjectCount - a.affectedObjectCount;
  }
}

export function sortFindings(findings: readonly Finding[], sort: FindingSort): Finding[] {
  const factor = sort.direction === 'asc' ? 1 : -1;
  return [...findings].sort(
    (a, b) => factor * compareBy(sort.key, a, b) || a.priority.rank - b.priority.rank,
  );
}

export function groupByTier(findings: readonly Finding[]): Record<PriorityTier, Finding[]> {
  const groups: Record<PriorityTier, Finding[]> = { 'fix-now': [], 'fix-next': [], plan: [], review: [] };
  for (const finding of sortFindings(findings, DEFAULT_SORT)) groups[finding.priority.tier].push(finding);
  return groups;
}

function pick<T extends string>(value: string | null, allowed: readonly T[]): T | 'all' {
  return value !== null && (allowed as readonly string[]).includes(value) ? (value as T) : 'all';
}

/** Read filters from URL search parameters (unknown values fall back to "all"). */
export function filtersFromParams(params: URLSearchParams): FindingFilters {
  const module = params.get('module');
  return {
    module: module !== null && isDashboardModuleId(module) ? module : 'all',
    severity: pick(params.get('severity'), SEVERITIES),
    status: pick(params.get('status'), ['FAIL', 'REVIEW'] as const),
    confidence: pick(params.get('confidence'), CONFIDENCES),
    tier: pick(params.get('tier'), TIER_ORDER),
    search: (params.get('q') ?? '').slice(0, 200),
  };
}

export function sortFromParams(params: URLSearchParams): FindingSort {
  const key = params.get('sort');
  const direction = params.get('dir');
  return {
    key: key !== null && (SORT_KEYS as readonly string[]).includes(key) ? (key as FindingSortKey) : DEFAULT_SORT.key,
    direction: direction === 'desc' ? 'desc' : 'asc',
  };
}

/** Serialize filters and sort; defaults are omitted to keep URLs short. */
export function toParams(filters: FindingFilters, sort: FindingSort): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.module !== 'all') params.set('module', filters.module);
  if (filters.severity !== 'all') params.set('severity', filters.severity);
  if (filters.status !== 'all') params.set('status', filters.status);
  if (filters.confidence !== 'all') params.set('confidence', filters.confidence);
  if (filters.tier !== 'all') params.set('tier', filters.tier);
  if (filters.search.trim() !== '') params.set('q', filters.search);
  if (sort.key !== DEFAULT_SORT.key) params.set('sort', sort.key);
  if (sort.direction !== DEFAULT_SORT.direction) params.set('dir', sort.direction);
  return params;
}
