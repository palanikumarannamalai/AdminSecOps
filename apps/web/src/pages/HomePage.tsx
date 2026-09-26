import { PRODUCT_DESCRIPTION, PRODUCT_TAGLINE } from '@adminsecops/core/version';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { errorMessage } from '../api/client';
import type { AssessmentListItem, SampleName } from '../api/types';
import { useApi, useAssessmentList } from '../app/context';
import { IntegrityBadge, ToneBadge } from '../components/Badges';
import { PageHeader, Panel } from '../components/PageHeader';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { UploadPanel } from '../components/UploadPanel';
import { useAsync } from '../hooks/useAsync';
import { environmentName, formatDateTime } from '../lib/format';
import { IS_HOSTED } from '../mode';

const STEPS = [
  {
    title: 'Collect',
    text: 'Run the read-only AdminSecOps Collector (PowerShell) with an account that has the documented read permissions.',
  },
  { title: 'Package', text: 'The collector writes an evidence package: a ZIP with a manifest of SHA-256 hashes and one JSON file per dataset.' },
  { title: 'Assess locally', text: 'Upload the package here. The local engine verifies integrity and evaluates the control library.' },
  { title: 'Review', text: 'Work through prioritized findings with evidence, remediation, rollback and verification steps.' },
  { title: 'Report', text: 'Download HTML and JSON reports to share with your team or keep as a baseline.' },
];

function SamplesPanel({ onLoaded }: { onLoaded: (id: string) => void }) {
  const api = useApi();
  const samples = useAsync('samples', (signal) => api.listSamples(signal));
  const [loading, setLoading] = useState<SampleName | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = async (name: SampleName) => {
    setLoading(name);
    setError(null);
    try {
      const created = await api.loadSample(name);
      onLoaded(created.assessmentId);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(null);
    }
  };

  return (
    <Panel title="Explore with sample data" id="samples">
      <p className="muted">
        Sanitized sample assessments of fictional organizations. Use them to learn the dashboard before you collect your
        own evidence.
      </p>
      {samples.status === 'loading' ? <LoadingState label="Loading samples" /> : null}
      {samples.status === 'error' ? (
        <ErrorState title="Samples are unavailable" error={samples.error} onRetry={samples.reload} />
      ) : null}
      {samples.status === 'success' && samples.data.length === 0 ? (
        <p className="muted">No samples are bundled with this installation.</p>
      ) : null}
      {samples.status === 'success' && samples.data.length > 0 ? (
        <ul className="sample-list">
          {samples.data.map((sample) => (
            <li key={sample.name} className="sample-list__item">
              <div>
                <p className="sample-list__title">{sample.title}</p>
                <p className="muted small">{sample.description}</p>
              </div>
              <button
                type="button"
                className="button"
                disabled={loading !== null}
                onClick={() => void load(sample.name)}
              >
                {loading === sample.name ? 'Loading...' : 'Load sample'}
              </button>
            </li>
          ))}
        </ul>
      ) : null}
      <p className="upload__status upload__status--error" role="status" aria-live="polite">
        {error !== null ? `The sample could not be loaded: ${error}` : ''}
      </p>
    </Panel>
  );
}

function AssessmentRow({ item, onDeleted }: { item: AssessmentListItem; onDeleted: () => void }) {
  const api = useApi();
  const [confirming, setConfirming] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const name = environmentName(item);
  const { byStatus, assessmentCoverage } = item.summary;

  const remove = async () => {
    setDeleting(true);
    setError(null);
    try {
      await api.deleteAssessment(item.assessmentId);
      onDeleted();
    } catch (e) {
      setError(errorMessage(e));
      setDeleting(false);
      setConfirming(false);
    }
  };

  return (
    <tr>
      <th scope="row">
        <Link to={`/assessments/${encodeURIComponent(item.assessmentId)}`}>{name}</Link>
        <div className="muted small">
          {[item.primaryDomain, item.adForestName].filter((v): v is string => v !== null && v !== name).join(' / ')}
        </div>
        {item.source === 'sample' ? <ToneBadge tone="info">Fictional sample</ToneBadge> : null}
      </th>
      <td>{formatDateTime(item.assessedAt)}</td>
      <td>
        <IntegrityBadge verified={item.integrityVerified} />
      </td>
      <td className="num">{byStatus.FAIL}</td>
      <td className="num">{byStatus.REVIEW}</td>
      <td className="num">
        {assessmentCoverage.assessed} of {assessmentCoverage.applicable}
      </td>
      <td>
        {confirming ? (
          <span className="inline-actions">
            <button type="button" className="button button--danger button--small" disabled={deleting} onClick={() => void remove()}>
              {deleting ? 'Clearing...' : IS_HOSTED ? 'Confirm clear' : 'Confirm delete'}
            </button>
            <button type="button" className="button button--small" disabled={deleting} onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </span>
        ) : (
          <button
            type="button"
            className="button button--small"
            aria-label={`${IS_HOSTED ? 'Clear' : 'Delete'} assessment ${name} from ${formatDateTime(item.assessedAt)}`}
            onClick={() => setConfirming(true)}
          >
            {IS_HOSTED ? 'Clear assessment' : 'Delete'}
          </button>
        )}
        {error !== null ? (
          <p className="error-text small" role="alert">
            {error}
          </p>
        ) : null}
      </td>
    </tr>
  );
}

export function AssessmentsPanel() {
  const list = useAssessmentList();
  return (
    <Panel title={IS_HOSTED ? 'Assessments in this browser' : 'Processed assessments'} id="assessments">
      {list.status === 'loading' ? <LoadingState label="Loading assessments" /> : null}
      {list.status === 'error' ? (
        <ErrorState title="Assessments could not be loaded" error={list.error} onRetry={list.reload} />
      ) : null}
      {list.status === 'success' && list.data.length === 0 ? (
        <EmptyState title="No assessments yet">
          <p>{IS_HOSTED ? 'Load a sample or import an evidence package to create an assessment.' : 'Upload an evidence package or load a sample to create the first assessment.'}</p>
        </EmptyState>
      ) : null}
      {list.status === 'success' && list.data.length > 0 ? (
        <div className="table-wrap" tabIndex={0}>
          <table className="table">
            <caption className="visually-hidden">{IS_HOSTED ? 'Assessments held in this browser' : 'Processed assessments stored on this machine'}</caption>
            <thead>
              <tr>
                <th scope="col">Environment</th>
                <th scope="col">Assessed</th>
                <th scope="col">Evidence</th>
                <th scope="col" className="num">
                  Fail
                </th>
                <th scope="col" className="num">
                  Review
                </th>
                <th scope="col" className="num">
                  Coverage
                </th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {list.data.map((item) => (
                <AssessmentRow key={item.assessmentId} item={item} onDeleted={list.reload} />
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </Panel>
  );
}

export function HomePage() {
  const api = useApi();
  const list = useAssessmentList();
  const navigate = useNavigate();
  const openAssessment = (id: string) => {
    list.reload();
    void navigate(`/assessments/${encodeURIComponent(id)}`);
  };

  return (
    <div className="page">
      <PageHeader title={PRODUCT_TAGLINE} eyebrow="AdminSecOps" description={<p>{PRODUCT_DESCRIPTION}</p>} />

      <section className="panel how" aria-labelledby="how-heading">
        <h2 id="how-heading" className="panel__title">
          How it works
        </h2>
        <ol className="how__steps">
          {STEPS.map((step, index) => (
            <li key={step.title} className="how__step">
              <span className="how__number" aria-hidden="true">
                {index + 1}
              </span>
              <span className="how__title">{step.title}</span>
              <span className="how__text">{step.text}</span>
            </li>
          ))}
        </ol>
        <p className="how__note">
          Evidence never leaves this machine. Processing, storage and reports are local; the local application makes no
          changes to your environment and sends no telemetry.
        </p>
      </section>

      <div className="grid grid--2">
        <Panel title="Upload an evidence package" id="upload">
          <UploadPanel api={api} onUploaded={openAssessment} />
        </Panel>
        <SamplesPanel onLoaded={openAssessment} />
      </div>

      <AssessmentsPanel />
    </div>
  );
}
