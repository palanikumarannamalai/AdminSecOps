import type { ControlStatus } from '@adminsecops/core';
import { CONTROL_STATUSES } from '@adminsecops/core/vocabulary';
import type { ControlResult } from '@adminsecops/schemas';
import { Link, useSearchParams } from 'react-router';
import { useAssessment } from '../app/AssessmentLayout';
import { SeverityBadge, StatusBadge } from '../components/Badges';
import { PageHeader, Panel } from '../components/PageHeader';
import { EmptyState } from '../components/States';
import { formatCount, formatFactValue } from '../lib/format';
import { STATUS_LABELS } from '../lib/labels';
import {
  DASHBOARD_MODULES,
  isDashboardModuleId,
  moduleForTechnology,
  moduleLabel,
  type DashboardModuleId,
} from '../lib/modules';
import { findingPath } from '../lib/paths';

const STATUS_ORDER: Record<ControlStatus, number> = {
  FAIL: 0,
  REVIEW: 1,
  ERROR: 2,
  NOT_ASSESSED: 3,
  PASS: 4,
  NOT_APPLICABLE: 5,
};

export interface ControlFilters {
  module: DashboardModuleId | 'all';
  status: ControlStatus | 'all';
  search: string;
}

export function filterControlResults(results: readonly ControlResult[], filters: ControlFilters): ControlResult[] {
  const needle = filters.search.trim().toLowerCase();
  return results
    .filter(
      (r) =>
        (filters.module === 'all' || moduleForTechnology(r.technology) === filters.module) &&
        (filters.status === 'all' || r.status === filters.status) &&
        (needle === '' ||
          `${r.controlId}\n${r.title}\n${r.category}\n${r.subcategory}\n${r.statusReason}`.toLowerCase().includes(needle)),
    )
    .sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status] || a.controlId.localeCompare(b.controlId));
}

export function ControlsPage() {
  const result = useAssessment();
  const [params, setParams] = useSearchParams();
  const moduleParam = params.get('module') ?? '';
  const statusParam = params.get('status') ?? '';
  const filters: ControlFilters = {
    module: isDashboardModuleId(moduleParam) ? moduleParam : 'all',
    status: (CONTROL_STATUSES as readonly string[]).includes(statusParam) ? (statusParam as ControlStatus) : 'all',
    search: params.get('q') ?? '',
  };
  const visible = filterControlResults(result.results, filters);
  const findingByControl = new Map(result.findings.map((f) => [f.controlId, f.findingId]));

  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value === '' || value === 'all') next.delete(key);
    else next.set(key, value);
    setParams(next, { replace: true });
  };

  const counts = Object.fromEntries(
    CONTROL_STATUSES.map((s) => [s, result.results.filter((r) => r.status === s).length]),
  ) as Record<ControlStatus, number>;

  return (
    <div className="page">
      <PageHeader
        eyebrow="Controls"
        title="Control results"
        description={
          <p>
            Every control evaluated in this assessment, including passed, not applicable and not assessed controls, with
            the reason for each status. See the <Link to="/library">control library</Link> for what each control checks.
          </p>
        }
      />
      <Panel>
        <div className="status-chips" role="group" aria-label="Filter by status">
          <button
            type="button"
            className={`chip${filters.status === 'all' ? ' chip--active' : ''}`}
            aria-pressed={filters.status === 'all'}
            onClick={() => set('status', 'all')}
          >
            All ({result.results.length})
          </button>
          {CONTROL_STATUSES.map((s) => (
            <button
              key={s}
              type="button"
              className={`chip${filters.status === s ? ' chip--active' : ''}`}
              aria-pressed={filters.status === s}
              onClick={() => set('status', s)}
            >
              {STATUS_LABELS[s]} ({counts[s]})
            </button>
          ))}
        </div>
        <div className="filters">
          <div className="field field--wide">
            <label htmlFor="c-search">Search</label>
            <input
              id="c-search"
              className="input"
              type="search"
              value={filters.search}
              placeholder="Control ID, title, category or reason"
              onChange={(e) => set('q', e.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor="c-module">Module</label>
            <select id="c-module" className="select" value={filters.module} onChange={(e) => set('module', e.target.value)}>
              <option value="all">All modules</option>
              {DASHBOARD_MODULES.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}
                </option>
              ))}
            </select>
          </div>
        </div>
        <p className="muted small" role="status" aria-live="polite">
          Showing {visible.length} of {formatCount(result.results.length, 'control result')}.
        </p>
        {visible.length === 0 ? (
          <EmptyState title="No control results match these filters" />
        ) : (
          <div className="table-wrap" tabIndex={0}>
            <table className="table">
              <caption className="visually-hidden">Control results</caption>
              <thead>
                <tr>
                  <th scope="col">Control</th>
                  <th scope="col">Module</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Status</th>
                  <th scope="col">Reason and observation</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((r) => {
                  const findingId = findingByControl.get(r.controlId);
                  return (
                    <tr key={r.controlId} id={`control-${r.controlId}`}>
                      <th scope="row" className="table__primary">
                        <code>{r.controlId}</code>
                        <div>{r.title}</div>
                        <div className="muted small">
                          {r.category} / {r.subcategory} - v{r.controlVersion}
                        </div>
                      </th>
                      <td>{moduleLabel(moduleForTechnology(r.technology))}</td>
                      <td>
                        <SeverityBadge severity={r.severity} />
                      </td>
                      <td>
                        <StatusBadge status={r.status} />
                      </td>
                      <td>
                        <p className="cell-text">{r.statusReason}</p>
                        {r.observed.summary !== '' || r.observed.facts.length > 0 ? (
                          <details className="details">
                            <summary>Observed and expected state</summary>
                            <p>{r.observed.summary}</p>
                            {r.observed.facts.length > 0 ? (
                              <ul className="bullets small">
                                {r.observed.facts.map((fact, i) => (
                                  <li key={i}>
                                    {fact.label}: {formatFactValue(fact.value)}
                                  </li>
                                ))}
                              </ul>
                            ) : null}
                            <p>
                              <strong>Expected:</strong> {r.expected}
                            </p>
                            {r.notes.length > 0 ? (
                              <ul className="bullets small">
                                {r.notes.map((n, i) => (
                                  <li key={i}>{n}</li>
                                ))}
                              </ul>
                            ) : null}
                          </details>
                        ) : null}
                        {findingId !== undefined ? (
                          <Link to={findingPath(result.assessmentId, findingId)} className="small">
                            Open finding<span className="visually-hidden"> for {r.controlId}</span>
                          </Link>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
