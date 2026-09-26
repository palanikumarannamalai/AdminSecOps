import { useAssessment } from '../app/AssessmentLayout';
import { ToneBadge, type Tone } from '../components/Badges';
import { PageHeader, Panel } from '../components/PageHeader';
import { GAP_LABELS, computeCoverage, type GapReason, type WorkloadCoverage } from '../lib/coverage';

const STATE: Record<WorkloadCoverage['state'], { label: string; tone: Tone }> = {
  assessed: { label: 'Assessed', tone: 'ok' },
  partial: { label: 'Partially assessed', tone: 'warn' },
  'not-assessed': { label: 'Not assessed', tone: 'bad' },
};

/** Why a workload without usable evidence was not assessed. None of these ever counts as passing. */
const BLOCKER: Record<GapReason, string> = {
  'not-connected': 'not connected',
  permission: 'consent or permission required',
  unsupported: 'unsupported online',
  failed: 'collection failed',
  licence: 'not licensed',
  'not-collected': 'not collected',
};

function stateOf(w: WorkloadCoverage): { label: string; detail: string | null; tone: Tone } {
  const base = STATE[w.state];
  return { ...base, detail: w.state === 'not-assessed' && w.blocker !== null ? BLOCKER[w.blocker] : null };
}

export function CoveragePage() {
  const result = useAssessment();
  const workloads = computeCoverage(result);
  const withGaps = workloads.filter((w) => w.gaps.length > 0 || w.skippedReasons.length > 0);

  return (
    <div className="page">
      <PageHeader
        eyebrow="Coverage"
        title="Assessment coverage by workload"
        description={
          <p>
            Which Microsoft services this assessment actually examined. Catalogue controls are the checks AdminSecOps has
            for a workload; only controls with a Pass, Fail or Review result were assessed. Workloads without usable
            evidence are not assessed and never count as passing, whether the connector was not connected, consent was
            missing, the source is unsupported online or collection failed.
          </p>
        }
      />

      <Panel title="Workloads" id="workloads">
        <div className="table-wrap" tabIndex={0}>
          <table className="table table--compact">
            <caption className="visually-hidden">Coverage per workload</caption>
            <thead>
              <tr>
                <th scope="col">Workload</th>
                <th scope="col">Coverage</th>
                <th scope="col" className="num">Datasets collected</th>
                <th scope="col" className="num">Catalogue controls</th>
                <th scope="col" className="num">Assessed</th>
                <th scope="col" className="num">Not assessed</th>
                <th scope="col" className="num">Not applicable</th>
              </tr>
            </thead>
            <tbody>
              {workloads.map((w) => (
                <tr key={w.key}>
                  <th scope="row">{w.label}</th>
                  <td>
                    <ToneBadge tone={stateOf(w).tone}>{stateOf(w).label}</ToneBadge>
                    {stateOf(w).detail !== null ? <div className="muted small">{stateOf(w).detail}</div> : null}
                  </td>
                  <td className="num">
                    {w.collected.length} of {w.collected.length + w.gaps.length}
                    {w.partial.length > 0 ? <div className="muted small">{w.partial.length} partial</div> : null}
                  </td>
                  <td className="num">{w.catalogueControls}</td>
                  <td className="num">{w.assessed}</td>
                  <td className="num">{w.notAssessed + w.errors}</td>
                  <td className="num">{w.notApplicable}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="What was not collected and why" id="gaps">
        {withGaps.length === 0 ? (
          <p>Every dataset for the listed workloads was collected.</p>
        ) : (
          withGaps.map((w) => (
            <section key={w.key} className="coverage-gap" aria-labelledby={`gap-${w.key}`}>
              <h3 id={`gap-${w.key}`}>{w.label}</h3>
              {w.skippedReasons.map((reason) => (
                <p key={reason} className="notice" role="note">
                  {reason}
                </p>
              ))}
              {w.gaps.length > 0 ? (
                <ul className="bullets small">
                  {w.gaps.map((gap) => (
                    <li key={gap.datasetId}>
                      <strong>{gap.title}</strong> (<code>{gap.datasetId}</code>): {GAP_LABELS[gap.reason]}. {gap.detail}
                    </li>
                  ))}
                </ul>
              ) : null}
            </section>
          ))
        )}
      </Panel>
    </div>
  );
}
