import type { AssessmentResult } from '../api/types';

function cell(value: string): string {
  const safe = /^[\s]*[=+\-@]/u.test(value) ? `'${value}` : value;
  return `"${safe.replaceAll('"', '""')}"`;
}

/** Editable follow-up tracker; does not change assessment verdicts or upload edits. */
export function remediationCsv(result: AssessmentResult): string {
  const header = ['Control', 'Title', 'Assessment status', 'Severity', 'Reason', 'Next step', 'Owner', 'Target date', 'Tracking status', 'Exception expiry', 'Verification evidence'];
  const rows = result.results.filter((r) => r.status !== 'PASS' && r.status !== 'NOT_APPLICABLE').map((r) => [
    r.controlId, r.title, r.status, r.severity, r.statusReason,
    r.status === 'NOT_ASSESSED' || r.status === 'ERROR' ? 'Resolve evidence gap and reassess' : r.status === 'REVIEW' ? 'Validate evidence and document decision' : 'Review remediation and test the change',
    '', '', 'Open', '', '',
  ]);
  return '\uFEFF' + [header, ...rows].map((row) => row.map(cell).join(',')).join('\r\n') + '\r\n';
}
