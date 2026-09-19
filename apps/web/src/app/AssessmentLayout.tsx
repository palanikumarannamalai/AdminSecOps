import { useState } from 'react';
import { Link, Outlet, useNavigate, useOutletContext, useParams } from 'react-router';
import { reportFileName } from '@adminsecops/reporting';
import { errorMessage, isApiError } from '../api/client';
import type { AssessmentResult } from '../api/types';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { useAsync } from '../hooks/useAsync';
import { IS_HOSTED } from '../mode';
import { useApi, useAssessmentList } from './context';

/** Hosted mode: export, clear and sample-data notice for the open assessment. */
function HostedAssessmentBar({ result }: { result: AssessmentResult }) {
  const api = useApi();
  const list = useAssessmentList();
  const navigate = useNavigate();
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isSample = list.status === 'success' && list.data.some((a) => a.assessmentId === result.assessmentId && a.source === 'sample');

  const clear = async () => {
    try {
      await api.deleteAssessment(result.assessmentId);
      list.reload();
      void navigate('/');
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <div className="assessment-bar">
      {isSample ? (
        <p className="notice notice--sample" role="note">
          Fictional sample data. Contoso and Fabrikam are invented organisations used to demonstrate AdminSecOps.
        </p>
      ) : null}
      <div className="assessment-bar__actions" role="group" aria-label="Assessment actions">
        <a className="button button--small" href={api.reportUrl(result.assessmentId, 'json')} download={reportFileName(result, 'json')}>
          Export JSON report
        </a>
        <a className="button button--small" href={api.reportUrl(result.assessmentId, 'html')} download={reportFileName(result, 'html')}>
          Export HTML report
        </a>
        {confirming ? (
          <>
            <button type="button" className="button button--small button--danger" onClick={() => void clear()}>
              Confirm clear assessment
            </button>
            <button type="button" className="button button--small" onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </>
        ) : (
          <button type="button" className="button button--small" onClick={() => setConfirming(true)}>
            Clear assessment
          </button>
        )}
      </div>
      {error !== null ? (
        <p className="error-text small" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

/** Loads the selected assessment once and shares it with all assessment pages. */
export function AssessmentLayout() {
  const { assessmentId = '' } = useParams();
  const api = useApi();
  const result = useAsync(assessmentId === '' ? null : `assessment:${assessmentId}`, (signal) =>
    api.getAssessment(assessmentId, signal),
  );

  if (result.status === 'loading') return <LoadingState label="Loading assessment" />;
  if (result.status === 'error') {
    if (isApiError(result.error) && result.error.status === 404) {
      return (
        <EmptyState title="Assessment not found">
          <p>
            {IS_HOSTED
              ? 'This assessment is not held in this browser. Assessments are kept in memory unless you chose to keep them on this device, so they disappear when the page is refreshed.'
              : 'This assessment does not exist on this machine. It may have been deleted.'}
          </p>
          <p>
            <Link to="/">{IS_HOSTED ? 'Go to start' : 'Go to assessments'}</Link>
          </p>
        </EmptyState>
      );
    }
    return <ErrorState title="The assessment could not be loaded" error={result.error} onRetry={result.reload} />;
  }
  return (
    <>
      {IS_HOSTED ? <HostedAssessmentBar result={result.data} /> : null}
      <Outlet context={result.data satisfies AssessmentResult} />
    </>
  );
}

export function useAssessment(): AssessmentResult {
  return useOutletContext<AssessmentResult>();
}
