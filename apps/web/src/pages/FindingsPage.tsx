import { CONFIDENCES, SEVERITIES } from '@adminsecops/core/vocabulary';
import type { ChangeEvent } from 'react';
import { Link, useSearchParams } from 'react-router';
import { useAssessment } from '../app/AssessmentLayout';
import { ConfidenceBadge, SeverityBadge, StatusBadge, TierBadge } from '../components/Badges';
import { PageHeader, Panel } from '../components/PageHeader';
import { EmptyState } from '../components/States';
import {
  DEFAULT_FILTERS,
  filterFindings,
  filtersFromParams,
  sortFindings,
  sortFromParams,
  toParams,
  type FindingFilters,
  type FindingSort,
  type FindingSortKey,
} from '../lib/findings';
import { formatCount } from '../lib/format';
import { CONFIDENCE_SHORT_LABELS, SEVERITY_LABELS, TIER_LABELS, TIER_ORDER } from '../lib/labels';
import { DASHBOARD_MODULES, moduleForTechnology, moduleLabel } from '../lib/modules';
import { findingPath } from '../lib/paths';

const COLUMNS: { key: FindingSortKey | null; label: string; className?: string }[] = [
  { key: 'priority', label: 'Rank', className: 'num' },
  { key: 'title', label: 'Finding' },
  { key: 'module', label: 'Module' },
  { key: 'severity', label: 'Severity' },
  { key: null, label: 'Status' },
  { key: 'confidence', label: 'Confidence' },
  { key: null, label: 'Tier' },
  { key: 'affected', label: 'Affected', className: 'num' },
];

function SortHeader({
  column,
  sort,
  onSort,
}: {
  column: (typeof COLUMNS)[number];
  sort: FindingSort;
  onSort: (key: FindingSortKey) => void;
}) {
  if (column.key === null) {
    return (
      <th scope="col" className={column.className}>
        {column.label}
      </th>
    );
  }
  const active = sort.key === column.key;
  const ariaSort = active ? (sort.direction === 'asc' ? 'ascending' : 'descending') : 'none';
  const key = column.key;
  return (
    <th scope="col" className={column.className} aria-sort={ariaSort}>
      <button type="button" className="sort-button" onClick={() => onSort(key)}>
        {column.label}
        <span className="sort-button__indicator" aria-hidden="true">
          {active ? (sort.direction === 'asc' ? ' ▲' : ' ▼') : ''}
        </span>
      </button>
    </th>
  );
}

export function FindingsPage() {
  const result = useAssessment();
  const [params, setParams] = useSearchParams();
  const filters = filtersFromParams(params);
  const sort = sortFromParams(params);
  const visible = sortFindings(filterFindings(result.findings, filters), sort);

  const update = (next: Partial<FindingFilters>, nextSort: FindingSort = sort) =>
    setParams(toParams({ ...filters, ...next }, nextSort), { replace: true });

  // Values are validated again by filtersFromParams when the URL is read back.
  const onSelect = (field: keyof Omit<FindingFilters, 'search'>) => (event: ChangeEvent<HTMLSelectElement>) => {
    const next: Partial<Record<keyof FindingFilters, string>> = { [field]: event.target.value };
    update(next as Partial<FindingFilters>);
  };

  const onSort = (key: FindingSortKey) =>
    update({}, { key, direction: sort.key === key && sort.direction === 'asc' ? 'desc' : 'asc' });

  const filtered = visible.length !== result.findings.length;

  return (
    <div className="page">
      <PageHeader
        eyebrow="Findings"
        title="Findings"
        description={
          <p>
            Controls with a FAIL or REVIEW result. Sorted by priority rank by default: rank 1 is the finding to address
            first.
          </p>
        }
      />
      <Panel>
        <form className="filters" role="search" aria-label="Filter findings" onSubmit={(e) => e.preventDefault()}>
          <div className="field field--wide">
            <label htmlFor="f-search">Search</label>
            <input
              id="f-search"
              className="input"
              type="search"
              placeholder="Title, control ID, category or tag"
              value={filters.search}
              onChange={(e) => update({ search: e.target.value })}
            />
          </div>
          <div className="field">
            <label htmlFor="f-module">Module</label>
            <select id="f-module" className="select" value={filters.module} onChange={onSelect('module')}>
              <option value="all">All modules</option>
              {DASHBOARD_MODULES.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="f-severity">Severity</label>
            <select id="f-severity" className="select" value={filters.severity} onChange={onSelect('severity')}>
              <option value="all">All severities</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {SEVERITY_LABELS[s]}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="f-status">Status</label>
            <select id="f-status" className="select" value={filters.status} onChange={onSelect('status')}>
              <option value="all">FAIL and REVIEW</option>
              <option value="FAIL">Fail</option>
              <option value="REVIEW">Review</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor="f-confidence">Confidence</label>
            <select id="f-confidence" className="select" value={filters.confidence} onChange={onSelect('confidence')}>
              <option value="all">All</option>
              {CONFIDENCES.map((c) => (
                <option key={c} value={c}>
                  {CONFIDENCE_SHORT_LABELS[c]}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="f-tier">Priority tier</label>
            <select id="f-tier" className="select" value={filters.tier} onChange={onSelect('tier')}>
              <option value="all">All tiers</option>
              {TIER_ORDER.map((t) => (
                <option key={t} value={t}>
                  {TIER_LABELS[t]}
                </option>
              ))}
            </select>
          </div>
          <div className="field field--actions">
            <button type="button" className="button" disabled={!filtered && sort.key === 'priority' && sort.direction === 'asc'} onClick={() => setParams(toParams(DEFAULT_FILTERS, { key: 'priority', direction: 'asc' }), { replace: true })}>
              Reset
            </button>
          </div>
        </form>
        <p className="muted small" role="status" aria-live="polite">
          Showing {visible.length} of {formatCount(result.findings.length, 'finding')}.
        </p>

        {result.findings.length === 0 ? (
          <EmptyState title="No findings">
            <p>No control returned FAIL or REVIEW. Review the Controls page for controls that were not assessed.</p>
          </EmptyState>
        ) : visible.length === 0 ? (
          <EmptyState title="No findings match these filters">
            <p>Change or reset the filters to see more findings.</p>
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table table--findings">
              <caption className="visually-hidden">Findings, sortable by column</caption>
              <thead>
                <tr>
                  {COLUMNS.map((c) => (
                    <SortHeader key={c.label} column={c} sort={sort} onSort={onSort} />
                  ))}
                </tr>
              </thead>
              <tbody>
                {visible.map((f) => (
                  <tr key={f.findingId}>
                    <td className="num">{f.priority.rank}</td>
                    <th scope="row" className="table__primary">
                      <Link to={findingPath(result.assessmentId, f.findingId)}>{f.title}</Link>
                      <div className="muted small">
                        {f.controlId} - {f.category}
                      </div>
                    </th>
                    <td>{moduleLabel(moduleForTechnology(f.technology))}</td>
                    <td>
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td>
                      <StatusBadge status={f.status} />
                    </td>
                    <td>
                      <ConfidenceBadge confidence={f.confidence} />
                    </td>
                    <td>
                      <TierBadge tier={f.priority.tier} />
                    </td>
                    <td className="num">{f.affectedObjectCount.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
