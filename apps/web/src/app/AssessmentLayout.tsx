import { Link, Outlet, useOutletContext, useParams } from 'react-router';
import { isApiError } from '../api/client';
import type { AssessmentResult } from '../api/types';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { useAsync } from '../hooks/useAsync';
import { useApi } from './context';

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
          <p>This assessment does not exist on this machine. It may have been deleted.</p>
          <p>
            <Link to="/">Go to assessments</Link>
          </p>
        </EmptyState>
      );
    }
    return <ErrorState title="The assessment could not be loaded" error={result.error} onRetry={result.reload} />;
  }
  return <Outlet context={result.data satisfies AssessmentResult} />;
}

export function useAssessment(): AssessmentResult {
  return useOutletContext<AssessmentResult>();
}
