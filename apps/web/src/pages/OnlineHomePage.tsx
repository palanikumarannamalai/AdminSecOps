import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router';
import { z } from 'zod';
import { errorMessage } from '../api/client';
import { useAssessmentList } from '../app/context';
import { onlineRequest, useOnlineSession } from '../app/OnlineSession';
import { PageHeader, Panel } from '../components/PageHeader';
import { formatDateTime, environmentName } from '../lib/format';

const jobsSchema = z.object({ jobs: z.array(z.object({
  id: z.string(), status: z.string(), createdAt: z.string(),
  completedAt: z.string().nullable().optional(), error: z.string().nullable().optional(),
  assessmentId: z.string().nullable().optional(),
})) });
type Job = z.infer<typeof jobsSchema>['jobs'][number];

export function OnlineHomePage() {
  const session = useOnlineSession();
  const history = useAssessmentList();
  const reloadHistory = history.reload;
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [revision, setRevision] = useState(0);
  const completed = useRef('');
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const result = jobsSchema.parse(await onlineRequest('/api/jobs', controller.signal));
        if (controller.signal.aborted) return;
        setJobs(result.jobs);
        setError(null);
        const ids = result.jobs.filter((job) => job.assessmentId).map((job) => job.assessmentId).join(',');
        if (ids !== completed.current) { completed.current = ids; reloadHistory(); }
      } catch (cause) {
        if (!controller.signal.aborted) setError(errorMessage(cause));
      } finally {
        if (!controller.signal.aborted) timer = setTimeout(() => { void poll(); }, 5000);
      }
    };
    void poll();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [revision, reloadHistory]);

  const run = async () => {
    setStarting(true); setError(null);
    try { await onlineRequest('/api/jobs', undefined, 'POST'); setRevision((value) => value + 1); }
    catch (cause) { setError(errorMessage(cause)); }
    finally { setStarting(false); }
  };
  const logout = async () => {
    try { await onlineRequest('/auth/logout', undefined, 'POST'); window.location.assign('/'); }
    catch (cause) { setError(errorMessage(cause)); }
  };
  const active = jobs.some((job) => ['queued', 'running', 'collecting', 'processing'].includes(job.status));
  return <div className="page">
    <PageHeader title="Your tenant assessments" eyebrow="AdminSecOps online · Test release"
      description={<p>Read-only Entra assessment for your Microsoft organization. Other Microsoft workloads and remediation are not enabled in this release.</p>} />
    <Panel title="Microsoft tenant connection" id="connection">
      <p>Signed in as <strong>{session.user.displayName}</strong></p>
      <p><strong>Current directory (tenant) ID:</strong> <code>{session.user.tenantId}</code></p>
      <p>{session.connection.connected ? 'Connected for read-only collection.' : 'The tenant connection is unavailable. Contact the test administrator to configure consent.'}</p>
      <div className="inline-actions"><button className="button" disabled={starting || active || !session.connection.connected} onClick={() => void run()}>
        {starting ? 'Submitting…' : active ? 'Assessment in progress' : 'Run assessment'}</button>
        <button className="button" onClick={() => void logout()}>Sign out / switch tenant</button></div>
      <p className="muted">To switch organizations, sign out first, then sign in with the other organization's account or enter its directory ID. Each assessment uses the current signed-in tenant.</p>
      <p className="muted">Raw evidence is processed in memory. Assessment results are stored for 30 days and audit events for 90 days. Missing permissions or unavailable datasets remain unknown; they are never treated as passing.</p>
    </Panel>
    {error !== null ? <p role="alert" className="error-text">{error}</p> : null}
    <Panel title="Assessment jobs" id="jobs">
      <p className="muted">Status refreshes every five seconds.</p>
      {jobs.length === 0 ? <p>No jobs to display yet.</p> : <ul className="sample-list">{jobs.map((job) => <li key={job.id} className="sample-list__item"><div>
        <p><strong>{job.status}</strong> · {formatDateTime(job.createdAt)}</p>
        {job.error ? <p className="error-text">{job.error}</p> : null}
        {job.assessmentId ? <Link to={`/assessments/${encodeURIComponent(job.assessmentId)}`}>View assessment</Link> : null}
      </div></li>)}</ul>}
    </Panel>
    <Panel title="Saved assessments" id="history">
      {history.status === 'loading' ? <p>Loading assessment history…</p> : null}
      {history.status === 'error' ? <p role="alert">{errorMessage(history.error)} <button className="button" onClick={history.reload}>Retry history</button></p> : null}
      {history.status === 'success' && history.data.length === 0 ? <p>Run your first assessment to save results here.</p> : null}
      {history.status === 'success' ? <ul className="sample-list">{history.data.map((item) => <li key={item.assessmentId} className="sample-list__item"><div>
        <Link to={`/assessments/${encodeURIComponent(item.assessmentId)}`}>{environmentName(item)}</Link>
        <p className="muted">{formatDateTime(item.assessedAt)} · {item.summary.byStatus.FAIL} failed controls · {item.summary.assessmentCoverage.assessed} of {item.summary.assessmentCoverage.applicable} applicable controls assessed</p>
      </div></li>)}</ul> : null}
    </Panel>
  </div>;
}

export function OnlineAboutPage() {
  return <div className="page"><PageHeader title="About this online test release" /><Panel title="Read-only Entra assessment" id="privacy">
    <p>AdminSecOps collects supported Microsoft Graph evidence from your signed-in Microsoft organization. Sign-in requires a supported administrator or reader role, and a tenant administrator must consent on Microsoft's screen to the read-only Graph permissions. The hosted backend evaluates the existing control library and stores assessment results in PostgreSQL.</p>
    <p>Evidence can contain user names, object identifiers and security configuration. Access requires Microsoft sign-in. Downloaded reports also contain this information; share them only with authorized recipients.</p>
    <p>This release does not modify tenant settings. It does not assess every Microsoft workload, provide a security certification, or treat uncollected evidence as a passing check.</p>
  </Panel></div>;
}
