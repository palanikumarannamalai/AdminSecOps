import { remediationCsv } from '../lib/remediation-csv';
import { useAssessment } from '../app/AssessmentLayout';
import { useApi } from '../app/context';
import { PageHeader, Panel } from '../components/PageHeader';
import { renderHtmlReport, reportFileName } from '@adminsecops/reporting';
import { environmentName, formatDateTime } from '../lib/format';
import { IS_HOSTED, IS_ONLINE } from '../mode';

export function ReportsPage() {
  const result = useAssessment();
  const api = useApi();
  const name = environmentName(result.collection.environment);
  const downloadTracker = () => {
    const url = URL.createObjectURL(new Blob([remediationCsv(result)], { type: 'text/csv;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `configreview-remediation-${result.assessedAt.slice(0, 10)}.csv`;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  };


  return (
    <div className="page">
      <PageHeader
        eyebrow="Reports"
        title="Download reports"
        description={
          <p>
            Reports for {name}, evidence collected {formatDateTime(result.assessedAt)}. Reports are generated{' '}
            {IS_ONLINE ? 'by the hosted service' : IS_HOSTED ? 'in this browser' : 'on this machine'} and contain identifiers from your environment (object names, IDs, domains). Store and share them as
            you would other sensitive administrative documents.
          </p>
        }
      />
      <div className="grid grid--2">
        <Panel title="Executive summary" id="report-executive"><p>A concise management report with coverage, priorities, evidence dates and library version. The full HTML report includes the technical appendix.</p><button className="button button--primary" onClick={()=>{const url=URL.createObjectURL(new Blob([renderHtmlReport(result,{executiveOnly:true})],{type:'text/html'}));const a=document.createElement('a');a.href=url;a.download='configreview-executive-summary.html';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}}>Download executive summary</button></Panel>
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
        <Panel title="Remediation tracker" id="report-tracker">
          <p>Download failures, review decisions and evidence gaps with columns for owner, target date, status, exception expiry and verification evidence. Edit it in your spreadsheet app; changes are not saved back to ConfigReview and do not change assessment verdicts.</p>
          <button className="button" onClick={downloadTracker}>Download remediation tracker (CSV)</button>
        </Panel>
      </div>
    </div>
  );
}
