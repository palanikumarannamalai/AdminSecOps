import type { ControlStatus } from '@adminsecops/core';
import { useSearchParams } from 'react-router';
import type { AssessmentComparison, AssessmentListItem } from '../api/types';
import { useApi, useAssessmentList } from '../app/context';
import { SeverityBadge, StatusBadge, ToneBadge, type Tone } from '../components/Badges';
import { PageHeader, Panel } from '../components/PageHeader';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { useAsync } from '../hooks/useAsync';
import { environmentName, formatCount, formatDateTime } from '../lib/format';
import { DIRECTION_DESCRIPTIONS, DIRECTION_LABELS, type ComparisonDirection } from '../lib/labels';

const DIRECTION_TONE: Record<ComparisonDirection, Tone> = {
  improved: 'ok',
  regressed: 'bad',
  mixed: 'warn',
  unchanged: 'muted',
};

const FIELD_LABELS: Record<AssessmentComparison['changedFindings'][number]['changes'][number]['field'], string> = {
  status: 'Status',
  severity: 'Severity',
  affectedObjectCount: 'Affected objects',
  affectedObjects: 'Affected object list',
  controlVersion: 'Control version',
};

function StatusOrNone({ status }: { status: ControlStatus | null }) {
  return status === null ? <span className="muted">Not evaluated</span> : <StatusBadge status={status} />;
}

function FindingRefTable({ items, caption }: { items: AssessmentComparison['newFindings']; caption: string }) {
  return (
    <div className="table-wrap">
      <table className="table table--compact">
        <caption className="visually-hidden">{caption}</caption>
        <thead>
          <tr>
            <th scope="col">Control</th>
            <th scope="col">Finding</th>
            <th scope="col">Severity</th>
            <th scope="col">Status</th>
          </tr>
        </thead>
        <tbody>
          {items.map((f) => (
            <tr key={f.findingKey}>
              <td>
                <code>{f.controlId}</code>
              </td>
              <th scope="row">{f.title}</th>
              <td>
                <SeverityBadge severity={f.severity} />
              </td>
              <td>
                <StatusBadge status={f.status} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Presentation of a comparison result; separate from data loading so it can be tested directly. */
export function ComparisonView({
  comparison,
  baselineName,
  currentName,
}: {
  comparison: AssessmentComparison;
  baselineName: string;
  currentName: string;
}) {
  const c = comparison;
  return (
    <div className="compare">
      {!c.sameEnvironment ? (
        <div className="banner banner--warn" role="alert">
          <strong>These assessments are from different environments.</strong> The baseline ({baselineName}) and the
          current assessment ({currentName}) do not identify the same tenant or forest, so new and resolved findings may
          reflect the difference between environments rather than changes over time.
        </div>
      ) : null}

      <Panel title="Summary" id="compare-summary">
        <p className="compare__direction">
          <ToneBadge tone={DIRECTION_TONE[c.direction]}>{DIRECTION_LABELS[c.direction]}</ToneBadge>{' '}
          <span>{DIRECTION_DESCRIPTIONS[c.direction]}</span>
        </p>
        <p className="muted small">
          Baseline: {baselineName}, evidence collected {formatDateTime(c.baseline.assessedAt)}. Current: {currentName},
          evidence collected {formatDateTime(c.current.assessedAt)}.
        </p>
        <dl className="stat-row">
          <div className="stat">
            <dt>New findings</dt>
            <dd>{c.newFindings.length}</dd>
          </div>
          <div className="stat">
            <dt>Resolved findings</dt>
            <dd>{c.resolvedFindings.length}</dd>
          </div>
          <div className="stat">
            <dt>Changed findings</dt>
            <dd>{c.changedFindings.length}</dd>
          </div>
          <div className="stat">
            <dt>Unchanged findings</dt>
            <dd>{c.unchangedFindingCount}</dd>
          </div>
          <div className="stat">
            <dt>Control status changes</dt>
            <dd>{c.controlStatusChanges.length}</dd>
          </div>
        </dl>
      </Panel>

      <Panel title={`New findings (${c.newFindings.length})`} id="compare-new">
        {c.newFindings.length === 0 ? (
          <p>No new findings.</p>
        ) : (
          <FindingRefTable items={c.newFindings} caption="New findings" />
        )}
      </Panel>

      <Panel title={`Resolved findings (${c.resolvedFindings.length})`} id="compare-resolved">
        {c.resolvedFindings.length === 0 ? (
          <p>No findings were resolved.</p>
        ) : (
          <FindingRefTable items={c.resolvedFindings} caption="Resolved findings" />
        )}
      </Panel>

      <Panel title={`Changed findings (${c.changedFindings.length})`} id="compare-changed">
        {c.changedFindings.length === 0 ? (
          <p>No findings changed.</p>
        ) : (
          <ul className="change-list">
            {c.changedFindings.map((f) => (
              <li key={f.findingKey} className="change-list__item">
                <p className="change-list__title">
                  <code>{f.controlId}</code> {f.title} <SeverityBadge severity={f.severity} />
                </p>
                <ul className="bullets small">
                  {f.changes.map((change, i) => (
                    <li key={i}>
                      {FIELD_LABELS[change.field]}: {String(change.from)} to {String(change.to)}
                    </li>
                  ))}
                </ul>
                {f.addedObjects.length > 0 ? (
                  <p className="small">
                    <strong>Newly affected:</strong> {f.addedObjects.join(', ')}
                  </p>
                ) : null}
                {f.removedObjects.length > 0 ? (
                  <p className="small">
                    <strong>No longer affected:</strong> {f.removedObjects.join(', ')}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title={`Control status changes (${c.controlStatusChanges.length})`} id="compare-controls">
        {c.controlStatusChanges.length === 0 ? (
          <p>No control changed status.</p>
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <caption className="visually-hidden">Control status changes</caption>
              <thead>
                <tr>
                  <th scope="col">Control</th>
                  <th scope="col">Baseline</th>
                  <th scope="col">Current</th>
                </tr>
              </thead>
              <tbody>
                {c.controlStatusChanges.map((change) => (
                  <tr key={change.controlId}>
                    <th scope="row">
                      <code>{change.controlId}</code> {change.title}
                    </th>
                    <td>
                      <StatusOrNone status={change.from} />
                    </td>
                    <td>
                      <StatusOrNone status={change.to} />
                    </td>
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

function optionLabel(a: AssessmentListItem): string {
  return `${environmentName(a)} - ${formatDateTime(a.assessedAt)}${a.source === 'sample' ? ' (sample)' : ''}`;
}

export function ComparePage() {
  const api = useApi();
  const list = useAssessmentList();
  const [params, setParams] = useSearchParams();
  const items = list.status === 'success' ? [...list.data].sort((a, b) => b.assessedAt.localeCompare(a.assessedAt)) : [];

  const exists = (id: string | null) => id !== null && items.some((a) => a.assessmentId === id);
  const currentId = exists(params.get('current')) ? params.get('current') : (items[0]?.assessmentId ?? null);
  const baselineId = exists(params.get('baseline'))
    ? params.get('baseline')
    : (items.find((a) => a.assessmentId !== currentId)?.assessmentId ?? null);
  const same = baselineId !== null && baselineId === currentId;
  const ready = baselineId !== null && currentId !== null && !same;

  const comparison = useAsync(ready ? `compare:${baselineId}:${currentId}` : null, (signal) =>
    api.compare(baselineId ?? '', currentId ?? '', signal),
  );

  const choose = (key: 'baseline' | 'current', value: string) => {
    const next = new URLSearchParams(params);
    next.set(key, value);
    if (key === 'current' && !next.has('baseline') && baselineId !== null) next.set('baseline', baselineId);
    if (key === 'baseline' && !next.has('current') && currentId !== null) next.set('current', currentId);
    setParams(next, { replace: true });
  };

  const nameOf = (id: string | null) => {
    const item = items.find((a) => a.assessmentId === id);
    return item !== undefined ? environmentName(item) : 'Unknown assessment';
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="Compare"
        title="Compare assessments"
        description={
          <p>
            Compare a baseline assessment with a later one of the same environment to see which findings are new,
            resolved or changed.
          </p>
        }
      />
      {list.status === 'loading' ? <LoadingState label="Loading assessments" /> : null}
      {list.status === 'error' ? <ErrorState error={list.error} onRetry={list.reload} /> : null}
      {list.status === 'success' && items.length < 2 ? (
        <EmptyState title="At least two assessments are needed">
          <p>
            Process a later evidence package of the same environment (or load the Contoso follow-up sample) to compare
            assessments.
          </p>
        </EmptyState>
      ) : null}
      {items.length >= 2 ? (
        <>
          <Panel>
            <div className="filters">
              <div className="field field--wide">
                <label htmlFor="cmp-baseline">Baseline (earlier)</label>
                <select
                  id="cmp-baseline"
                  className="select"
                  value={baselineId ?? ''}
                  onChange={(e) => choose('baseline', e.target.value)}
                >
                  {items.map((a) => (
                    <option key={a.assessmentId} value={a.assessmentId}>
                      {optionLabel(a)}
                    </option>
                  ))}
                </select>
              </div>
              <div className="field field--wide">
                <label htmlFor="cmp-current">Current (later)</label>
                <select
                  id="cmp-current"
                  className="select"
                  value={currentId ?? ''}
                  onChange={(e) => choose('current', e.target.value)}
                >
                  {items.map((a) => (
                    <option key={a.assessmentId} value={a.assessmentId}>
                      {optionLabel(a)}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            {same ? (
              <p className="error-text" role="alert">
                Select two different assessments.
              </p>
            ) : null}
          </Panel>
          {ready && comparison.status === 'loading' ? <LoadingState label="Comparing assessments" /> : null}
          {ready && comparison.status === 'error' ? (
            <ErrorState title="The comparison failed" error={comparison.error} onRetry={comparison.reload} />
          ) : null}
          {ready && comparison.status === 'success' ? (
            <ComparisonView comparison={comparison.data} baselineName={nameOf(baselineId)} currentName={nameOf(currentId)} />
          ) : null}
          <p className="muted small">
            {formatCount(items.length, 'assessment')} available. Only results are compared; evidence is not reprocessed.
          </p>
        </>
      ) : null}
    </div>
  );
}
