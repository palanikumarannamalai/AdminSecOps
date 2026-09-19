import { describe, expect, it } from 'vitest';
import { sampleFindings } from '../test/sample-result';
import {
  DEFAULT_FILTERS,
  DEFAULT_SORT,
  filterFindings,
  filtersFromParams,
  groupByTier,
  sortFindings,
  sortFromParams,
  toParams,
} from './findings';

const ids = (list: { controlId: string }[]) => list.map((f) => f.controlId);

describe('filterFindings', () => {
  it('returns everything with default filters', () => {
    expect(filterFindings(sampleFindings, DEFAULT_FILTERS)).toHaveLength(sampleFindings.length);
  });

  it('filters by dashboard module (ad includes adcs)', () => {
    expect(ids(filterFindings(sampleFindings, { ...DEFAULT_FILTERS, module: 'ad' })).sort()).toEqual([
      'AD-KRB-001',
      'ADCS-TPL-001',
    ]);
  });

  it('filters by severity, status, confidence and tier', () => {
    expect(ids(filterFindings(sampleFindings, { ...DEFAULT_FILTERS, severity: 'critical' }))).toEqual(['ADCS-TPL-001']);
    expect(ids(filterFindings(sampleFindings, { ...DEFAULT_FILTERS, status: 'REVIEW' }))).toEqual(['ENTRA-APP-002']);
    expect(ids(filterFindings(sampleFindings, { ...DEFAULT_FILTERS, confidence: 'medium' }))).toEqual(['ENTRA-APP-002']);
    expect(ids(filterFindings(sampleFindings, { ...DEFAULT_FILTERS, tier: 'fix-next' })).sort()).toEqual([
      'AD-KRB-001',
      'M365-EXO-004',
    ]);
  });

  it('searches title, control ID and tags case-insensitively with all terms', () => {
    expect(ids(filterFindings(sampleFindings, { ...DEFAULT_FILTERS, search: 'krbtgt' }))).toEqual(['AD-KRB-001']);
    expect(ids(filterFindings(sampleFindings, { ...DEFAULT_FILTERS, search: 'entra-ca' }))).toEqual(['ENTRA-CA-001']);
    expect(ids(filterFindings(sampleFindings, { ...DEFAULT_FILTERS, search: 'LEGACY-AUTHENTICATION' }))).toEqual([
      'ENTRA-CA-001',
    ]);
    expect(filterFindings(sampleFindings, { ...DEFAULT_FILTERS, search: 'krbtgt legacy' })).toHaveLength(0);
  });

  it('combines filters', () => {
    expect(filterFindings(sampleFindings, { ...DEFAULT_FILTERS, module: 'entra', status: 'FAIL' })).toHaveLength(1);
  });
});

describe('sortFindings', () => {
  const shuffled = [...sampleFindings].reverse();

  it('defaults to priority rank ascending', () => {
    expect(sortFindings(shuffled, DEFAULT_SORT).map((f) => f.priority.rank)).toEqual([1, 2, 3, 4, 5]);
  });

  it('sorts by priority descending', () => {
    expect(sortFindings(shuffled, { key: 'priority', direction: 'desc' }).map((f) => f.priority.rank)).toEqual([
      5, 4, 3, 2, 1,
    ]);
  });

  it('sorts by severity with rank as tie-breaker', () => {
    expect(ids(sortFindings(shuffled, { key: 'severity', direction: 'asc' }))).toEqual([
      'ADCS-TPL-001',
      'ENTRA-CA-001',
      'ENTRA-APP-002',
      'M365-EXO-004',
      'AD-KRB-001',
    ]);
  });

  it('sorts by affected objects, most first', () => {
    expect(sortFindings(shuffled, { key: 'affected', direction: 'asc' })[0]?.controlId).toBe('M365-EXO-004');
  });

  it('does not mutate the input', () => {
    const copy = [...shuffled];
    sortFindings(shuffled, DEFAULT_SORT);
    expect(shuffled).toEqual(copy);
  });
});

describe('groupByTier', () => {
  it('groups in rank order', () => {
    const groups = groupByTier(sampleFindings);
    expect(ids(groups['fix-now'])).toEqual(['ADCS-TPL-001', 'ENTRA-CA-001']);
    expect(ids(groups['fix-next'])).toEqual(['M365-EXO-004', 'AD-KRB-001']);
    expect(groups.plan).toHaveLength(0);
    expect(ids(groups.review)).toEqual(['ENTRA-APP-002']);
  });
});

describe('URL parameters', () => {
  it('round-trips filters and sort', () => {
    const filters = { ...DEFAULT_FILTERS, module: 'entra' as const, severity: 'high' as const, search: 'legacy' };
    const sort = { key: 'severity' as const, direction: 'desc' as const };
    const params = toParams(filters, sort);
    expect(filtersFromParams(params)).toEqual(filters);
    expect(sortFromParams(params)).toEqual(sort);
  });

  it('omits defaults and ignores unknown values', () => {
    expect(toParams(DEFAULT_FILTERS, DEFAULT_SORT).toString()).toBe('');
    const parsed = filtersFromParams(new URLSearchParams('module=mainframe&severity=extreme&status=PASS&sort=evil'));
    expect(parsed).toEqual(DEFAULT_FILTERS);
    expect(sortFromParams(new URLSearchParams('sort=evil'))).toEqual(DEFAULT_SORT);
  });
});
