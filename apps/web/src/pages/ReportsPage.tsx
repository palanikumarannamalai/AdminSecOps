import { useAssessment } from '../app/AssessmentLayout';
import { useApi } from '../app/context';
import { PageHeader, Panel } from '../components/PageHeader';
import { reportFileName } from '@adminsecops/reporting';
import { environmentName, formatDateTime } from '../lib/format';
import { IS_HOSTED } from '../mode';

export function ReportsPage() {
  const result = useAssessment();
  const api = useApi();
  const name = environmentName(result.collection.environment);

  return (
    <div className="page">
      <PageHeader
        eyebrow="Reports"
        title="Download reports"
        description={
          <p>
            Reports for {name}, evidence collected {formatDateTime(result.assessedAt)}. Reports are generated{' '}
            {IS_HOSTED ? 'in this browser' : 'on this machine'} and contain identifiers from your environment (object names, IDs, domains). Store and share them as
            you would other sensitive administrative documents.
          </p>
        }
      />
      <div className="grid grid--2">
        <Panel title="HTML report" id="report-html">
          <p>
            A self-contained report for administrators and management: summary, prioritized findings with remediation,
            rollback and verification steps, evidence integrity and coverage. Opens in any browser without network access.
          </p>
          <a className="button button--primary" href={api.reportUrl(result.assessmentId, 'html')} download={reportFileName(result, 'html')}>
            Download HTML report
          </a>
        </Panel>
        <Panel title="JSON report" id="report-json">
          <p>
            The complete machine-readable assessment result (result schema {result.resultSchemaVersion}), including all
            control results and affected objects. Use it for automation, archiving or comparison.
          </p>
          <a className="button" href={api.reportUrl(result.assessmentId, 'json')} download={reportFileName(result, 'json')}>
            Download JSON report
          </a>
        </Panel>
      </div>
    </div>
  );
}
