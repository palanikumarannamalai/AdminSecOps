import type { ControlStatus } from '@adminsecops/core';
import type { ControlMetadata, ControlResult, Finding, FrameworkMapping } from '@adminsecops/schemas';
import { useState } from 'react';
import { Link } from 'react-router';
import { useAssessment } from '../app/AssessmentLayout';
import { useApi } from '../app/context';
import { SeverityBadge, StatusBadge } from '../components/Badges';
import { PageHeader, Panel } from '../components/PageHeader';
import { EmptyState } from '../components/States';
import { useAsync } from '../hooks/useAsync';
import { formatCount } from '../lib/format';
import { FRAMEWORK_LABELS, frameworkLabel } from '../lib/labels';
import { findingPath } from '../lib/paths';

export interface FrameworkEntry {
  controlId: string;
  title: string;
  status: ControlStatus;
  severity: ControlResult['severity'];
  finding: Finding | undefined;
  note: string | undefined;
}

export interface FrameworkGroup {
  framework: string;
  ids: { id: string; entries: FrameworkEntry[] }[];
}

/**
 * Group control results by framework and framework identifier. Mappings come from the
 * control library when available (so passed controls are included) and otherwise from
 * the findings, which carry their control's mappings.
 */
export function groupByFramework(
  results: readonly ControlResult[],
  findings: readonly Finding[],
  library: readonly ControlMetadata[] | null,
): FrameworkGroup[] {
  const findingByControl = new Map(findings.map((f) => [f.controlId, f]));
  const libraryById = new Map((library ?? []).map((c) => [c.id, c]));
  const map = new Map<string, Map<string, FrameworkEntry[]>>();

  for (const result of results) {
    const finding = findingByControl.get(result.controlId);
    const mappings: readonly FrameworkMapping[] =
      libraryById.get(result.controlId)?.frameworkMappings ?? finding?.frameworkMappings ?? [];
    for (const mapping of mappings) {
      const byId = map.get(mapping.framework) ?? new Map<string, FrameworkEntry[]>();
      map.set(mapping.framework, byId);
      const entries = byId.get(mapping.id) ?? [];
      byId.set(mapping.id, entries);
      entries.push({
        controlId: result.controlId,
        title: result.title,
        status: result.status,
        severity: result.severity,
        finding,
        note: mapping.note,
      });
    }
  }

  const order: string[] = Object.keys(FRAMEWORK_LABELS);
  const rank = (framework: string) => (order.includes(framework) ? order.indexOf(framework) : order.length);
  return [...map.entries()]
    .sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b))
    .map(([framework, byId]) => ({
      framework,
      ids: [...byId.entries()]
        .sort(([a], [b]) => a.localeCompare(b, undefined, { numeric: true }))
        .map(([id, entries]) => ({ id, entries })),
    }));
}

export function FrameworksPage() {
  const result = useAssessment();
  const api = useApi();
  const library = useAsync('controls', (signal) => api.listControls(signal));
  const [selected, setSelected] = useState<string>('all');
  const [findingsOnly, setFindingsOnly] = useState(false);

  const libraryControls = library.status === 'success' ? library.data.controls : null;
  const groups = groupByFramework(
    findingsOnly ? result.results.filter((r) => r.status === 'FAIL' || r.status === 'REVIEW') : result.results,
    result.findings,
    libraryControls,
  );
  const visible = selected === 'all' ? groups : groups.filter((g) => g.framework === selected);

  return (
    <div className="page">
      <PageHeader
        eyebrow="Frameworks"
        title="Results by framework"
        description={
          <p>
            Control results grouped by the framework identifiers their controls map to. Mappings are informational: a
            result mapped to an identifier does not mean the whole requirement is met or failed. Framework text is not
            reproduced; consult the framework publisher.
          </p>
        }
      />
      {library.status === 'error' ? (
        <p className="banner banner--warn" role="status">
          The control library could not be loaded, so only mappings carried by findings are shown.
        </p>
      ) : null}
      <div className="filters filters--bare">
        <div className="field">
          <label htmlFor="fw-select">Framework</label>
          <select id="fw-select" className="select" value={selected} onChange={(e) => setSelected(e.target.value)}>
            <option value="all">All frameworks</option>
            {Object.entries(FRAMEWORK_LABELS).map(([id, label]) => (
              <option key={id} value={id}>
                {label}
              </option>
            ))}
          </select>
        </div>
        <div className="field field--checkbox">
          <input
            id="fw-findings-only"
            type="checkbox"
            checked={findingsOnly}
            onChange={(e) => setFindingsOnly(e.target.checked)}
          />
          <label htmlFor="fw-findings-only">Only FAIL and REVIEW</label>
        </div>
      </div>
      {library.status === 'loading' ? <p className="muted small">Loading control library mappings...</p> : null}
      {visible.length === 0 ? (
        <EmptyState title="No framework mappings">
          <p>No control results in this selection are mapped to a framework.</p>
        </EmptyState>
      ) : (
        visible.map((group) => (
          <Panel key={group.framework} title={frameworkLabel(group.framework)} id={`fw-${group.framework}`}>
            <p className="muted small">{formatCount(group.ids.length, 'identifier')}.</p>
            <div className="table-wrap">
              <table className="table table--compact">
                <caption className="visually-hidden">{frameworkLabel(group.framework)} identifiers and control results</caption>
                <thead>
                  <tr>
                    <th scope="col">Identifier</th>
                    <th scope="col">Control</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {group.ids.flatMap(({ id, entries }) =>
                    entries.map((entry, index) => (
                      <tr key={`${id}-${entry.controlId}`}>
                        {index === 0 ? (
                          <th scope="rowgroup" rowSpan={entries.length}>
                            <code>{id}</code>
                          </th>
                        ) : null}
                        <td>
                          {entry.finding !== undefined ? (
                            <Link to={findingPath(result.assessmentId, entry.finding.findingId)}>{entry.title}</Link>
                          ) : (
                            entry.title
                          )}
                          <div className="muted small">
                            {entry.controlId}
                            {entry.note !== undefined ? ` - ${entry.note}` : ''}
                          </div>
                        </td>
                        <td>
                          <SeverityBadge severity={entry.severity} />
                        </td>
                        <td>
                          <StatusBadge status={entry.status} />
                        </td>
                      </tr>
                    )),
                  )}
                </tbody>
              </table>
            </div>
          </Panel>
        ))
      )}
    </div>
  );
}
