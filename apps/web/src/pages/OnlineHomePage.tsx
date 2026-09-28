import { OnPremPanel } from '../components/OnPremPanel';
import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router';
import { z } from 'zod';
import { errorMessage } from '../api/client';
import { useAssessmentList } from '../app/context';
import { onlineRequest, useOnlineSession, type OnlineConnector } from '../app/OnlineSession';
import { ToneBadge, type Tone } from '../components/Badges';
import { PageHeader, Panel } from '../components/PageHeader';
import { formatDateTime, environmentName } from '../lib/format';

const CONNECTOR_STATE: Record<OnlineConnector['state'], { label: string; tone: Tone }> = {
  connected: { label: 'Connected', tone: 'ok' },
  'not-connected': { label: 'Not connected', tone: 'warn' },
  expired: { label: 'Connection expired', tone: 'warn' },
  disabled: { label: 'Not available on this deployment', tone: 'bad' },
  'runtime-unavailable': { label: 'Not available on this server', tone: 'bad' },
  unsupported: { label: 'Not supported online', tone: 'bad' },
};

/** One row per data source. Connect buttons exist only for connectors the server can actually use. */
function ConnectorList({ connectors, onError }: { connectors: readonly OnlineConnector[]; onError: (message: string) => void }) {
  const disconnect = async (id: string) => {
    try { await onlineRequest(`/api/connectors/${encodeURIComponent(id)}/disconnect`, undefined, 'POST'); window.location.assign('/'); }
    catch (cause) { onError(errorMessage(cause)); }
  };
  return <ul className="sample-list connector-grid" aria-label="Data sources">{connectors.map((c) => <li key={c.id} className="sample-list__item"><div>
    <p><strong>{c.label}</strong> <ToneBadge tone={CONNECTOR_STATE[c.state].tone}>{CONNECTOR_STATE[c.state].label}</ToneBadge></p>
    <p>{c.reason}</p>
    {c.id === 'exchange' ? <p className="muted small">Exchange consent uses a management-scoped permission and can carry your account's write authority. ConfigReview runs fixed read operations only. Use an account with the least Exchange access needed.</p> : null}
    {c.id !== 'onPremises' ? <details className="connector-permissions"><summary>Permissions and required role</summary><p className="muted small">Permission: {c.permission}. Role: {c.role}.</p></details> : null}
    {c.connectedAt !== null ? <p className="muted small">Connected {formatDateTime(c.connectedAt)}</p> : null}
    <div className="inline-actions">
      {c.state === 'not-connected' && c.connectUrl !== null ? <a className="button" href={c.connectUrl}>Connect {c.label}</a> : null}
      {(c.state === 'connected' || c.state === 'expired') && c.reconnectUrl !== null ? <a className="button" href={c.reconnectUrl}>Reconnect {c.label}</a> : null}
      {c.state === 'connected' || c.state === 'expired' ? <button className="button" onClick={() => void disconnect(c.id)}>Disconnect</button> : null}
    </div>
  </div></li>)}</ul>;
}

const jobsSchema = z.object({ jobs: z.array(z.object({
  id: z.string(), status: z.string(), createdAt: z.string(),
  completedAt: z.string().nullable().optional(), error: z.string().nullable().optional(),
  assessmentId: z.string().nullable().optional(), modules:z.array(z.string()).nullable().optional(), progress:z.record(z.string(),z.string()).optional(),
})) });
type Job = z.infer<typeof jobsSchema>['jobs'][number];

export function OnlineHomePage() {
  const session = useOnlineSession();
  const history = useAssessmentList();
  const reloadHistory = history.reload;
  const [jobs, setJobs] = useState<Job[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [modules,setModules]=useState(['Entra','M365','Intune','Exchange','Azure']);
  const [step,setStep]=useState(1);
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

  const run = async (selected=modules) => {
    setStarting(true); setError(null);
    try { await onlineRequest('/api/jobs', undefined, 'POST', {modules:selected}); setRevision((value) => value + 1); }
    catch (cause) { setError(errorMessage(cause)); }
    finally { setStarting(false); }
  };
  const logout = async () => {
    try { await onlineRequest('/auth/logout', undefined, 'POST'); window.location.assign('/'); }
    catch (cause) { setError(errorMessage(cause)); }
  };
  const missingScopes = session.connection.missingScopes ?? [];
  const connectors = session.connectors ?? [];
  const justConnected = new URLSearchParams(window.location.search).get('connected');
  const connectedLabel = connectors.find((c) => c.id === justConnected)?.label;
  const active = jobs.some((job) => ['queued', 'running', 'collecting', 'processing'].includes(job.status));
  return <div className="page">
    <PageHeader title="Your security workspace" eyebrow="ConfigReview online · Test release"
      description={<p>Connect your workloads, run an assessment, and understand your next priorities. Open Coverage in any assessment to see exactly what was tested.</p>} />
    {connectedLabel !== undefined ? <p className="notice" role="status">{connectedLabel} is connected. It is included in the next assessment you run.</p> : null}
    <section className="assessment-launch" aria-label="New assessment">
      <div className="launch-heading"><div><p className="eyebrow">New assessment</p><h2>Start with the right scope.</h2></div><span className="badge">Read-only · Preview</span></div>
      <ol className="setup-steps"><li aria-current={step===1?'step':undefined}>1. Choose workloads</li><li aria-current={step===2?'step':undefined}>2. Review readiness</li><li>3. Run and review</li></ol>
      <fieldset className="workload-picker"><legend>Workloads to assess</legend>{['Entra','M365','Intune','Exchange','Azure'].map(m=><label key={m}><input type="checkbox" checked={modules.includes(m)} disabled={active||starting} onChange={()=>{setModules(old=>old.includes(m)?old.filter(x=>x!==m):[...old,m]);setStep(1);}}/>{m==='M365'?'Microsoft 365':m==='Entra'?'Entra ID':m}</label>)}</fieldset>
      <p className="muted small">Tenant identity is always verified. Unselected workloads stay untested; permissions and licences may limit selected checks.</p>
      {step===1?<button className="button button--primary" disabled={!modules.length} onClick={()=>setStep(2)}>Review readiness</button>:<p role="status">Review connection access below, then run your assessment. {modules.length} workloads selected.</p>}
    </section>
    <Panel title="Microsoft tenant connection" id="connection">
      <p>Signed in as <strong>{session.user.displayName}</strong></p>
      <p><strong>Current directory (tenant) ID:</strong> <code>{session.user.tenantId}</code></p>
      <p>{session.connection.connected ? 'Connected for read-only collection.' : 'The tenant connection is unavailable. Contact the test administrator to configure consent.'}</p>
      <details open={step===2} className="readiness-details"><summary>Connection readiness and collection scope</summary><section aria-labelledby="readiness-heading" className="notice">
        <h3 id="readiness-heading">Before you run</h3>
        <p>Microsoft Graph checks cover Entra, SharePoint, limited Teams settings and Intune compliance. Licences and readable evidence are checked during collection; a connection does not guarantee full coverage.</p>
        <ul className="bullets">{connectors.map((c) => <li key={c.id}><strong>{c.label}:</strong> {CONNECTOR_STATE[c.state].label}. {c.state === 'connected' ? 'Collection will be attempted.' : c.reason}</li>)}</ul>
        <p>AD, AD CS, Group Policy and Windows host checks use a collector inside your network. {session.onPremEnabled ? 'Use On-premises collection below for manual or scheduled uploads. Results are saved as a separate snapshot.' : 'On-premises uploads are not enabled on this deployment.'} Missing evidence remains untested.</p>
        <p>{missingScopes.length > 0 ? `${missingScopes.length} required permissions are missing. ` : ''}You can run a partial assessment. Review Coverage afterwards for the exact checks, licence decisions and collection failures.</p>
      </section></details>
      <div className="inline-actions"><button className="button button--primary" disabled={starting || active || !session.connection.connected || modules.length===0 || step!==2} onClick={() => void run()}>
        {starting ? 'Submitting…' : active ? 'Assessment in progress' : 'Run assessment'}</button>
        <button className="button" onClick={() => void logout()}>Sign out / switch tenant</button></div>
      {missingScopes.length > 0 ? <div className="notice" role="note" aria-labelledby="consent-heading">
        <p id="consent-heading"><strong>Some read-only permissions are not granted.</strong> Datasets that need them will be reported as not assessed:</p>
        <ul className="bullets small">{missingScopes.map((scope) => <li key={scope}><code>{scope}</code></li>)}</ul>
        <p>An administrator who can grant tenant-wide consent (for example a Global Administrator or Privileged Role Administrator) can review and grant them on Microsoft's consent screen, then run the assessment again.</p>
        <a className="button" href="/auth/login?consent=true">Reconnect and review Microsoft consent</a>
      </div> : null}
      <details className="readiness-details"><summary>Switch tenant and data retention</summary><p className="muted">To switch organizations, sign out first, then sign in with the other organization's account or enter its directory ID. Each assessment uses the current signed-in tenant.</p>
      <p className="muted">Raw evidence is processed in memory. Assessment results are retained in the live database for 30 days and audit events for 90 days. Remediation tracking is retained for 90 days after its last update. Database backups may retain deleted records for up to seven additional days. Downloaded reports remain under your control. Missing permissions or unavailable datasets remain unknown; they are never treated as passing.</p></details>
    </Panel>
    {connectors.length > 0 ? <Panel title="Additional data sources" id="connectors">
      <p>Each source needs its own Microsoft sign-in and consent, uses your signed-in permissions, and only reads configuration. Sources that are not connected are reported as not assessed; they never count as passing.</p>
      <ConnectorList connectors={connectors} onError={setError} />
    </Panel> : null}
    {error !== null ? <p role="alert" className="error-text">{error}</p> : null}
    {session.onPremEnabled ? <details className="environment-details"><summary>On-premises collection · manual or scheduled</summary><OnPremPanel tenantId={session.user.tenantId} /></details> : null}
    <Panel title="Assessment jobs" id="jobs">
      <p className="muted">Status refreshes every five seconds.</p>
      {jobs.length === 0 ? <p>No jobs to display yet.</p> : <ul className="sample-list">{jobs.map((job) => <li key={job.id} className="sample-list__item"><div>
        <p><strong>{job.status}</strong> · {formatDateTime(job.createdAt)}</p>
        {job.progress && Object.keys(job.progress).length>0 ? <details open={job.status==='running'}><summary>{Object.values(job.progress).filter(s=>s!=='collecting').length} datasets processed</summary><ul className="progress-list">{Object.entries(job.progress).map(([id,status])=><li key={id}><span>{id}</span><span className="badge">{status}</span></li>)}</ul></details>:null}
        {job.status==='completed' && Object.values(job.progress??{}).some(s=>!['Success','NotApplicable'].includes(s))?<button className="button button--small" disabled={active||starting} onClick={()=>{const names:Record<string,string>={entra:'Entra',m365:'M365',intune:'Intune',exchange:'Exchange',azure:'Azure'};const failed=[...new Set(Object.entries(job.progress??{}).filter(([,s])=>!['Success','NotApplicable'].includes(s)).map(([id])=>names[id.split('.')[0]??'']).filter((m):m is string=>!!m))];if(failed.length)void run(failed);}}>Retry incomplete workloads</button>:null}
        {job.status==='failed'?<button className="button button--small" disabled={active||starting} onClick={()=>{setModules(job.modules??modules);setStep(2);document.getElementById('connection')?.scrollIntoView();}}>Review scope and retry</button>:null}
        {job.error ? <p className="error-text">{job.error}</p> : null}
        {job.assessmentId ? <Link to={`/assessments/${encodeURIComponent(job.assessmentId)}`}>View assessment</Link> : null}
      </div></li>)}</ul>}
    </Panel>
    <Panel title="Recent assessments" id="history">
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
  return <div className="page"><PageHeader title="About this online test release" /><Panel title="Read-only Microsoft 365 assessment" id="privacy">
    <p>ConfigReview collects supported Microsoft Graph evidence (Microsoft Entra ID, SharePoint and OneDrive tenant settings, Teams app and per-team settings, and Intune compliance configuration) from your signed-in Microsoft organization, and public SPF and DMARC DNS records of its mail domains. Azure subscriptions and Exchange Online are read only after you connect them separately. Sign-in requires a supported administrator or reader role, and a tenant administrator must consent on Microsoft's screen to the permissions. The hosted backend evaluates the existing control library and stores assessment results in PostgreSQL.</p>
    <p>Evidence can contain user names, object identifiers and security configuration. Access requires Microsoft sign-in. Downloaded reports also contain this information; share them only with authorized recipients.</p>
    <p>Assessment results are retained in the live database for 30 days and audit events for 90 days. Remediation tracking is retained for 90 days after its last update. Database backups may retain deleted records for up to seven additional days. Downloaded reports remain under your control.</p>
    <p>This release does not modify tenant settings. It does not assess every Microsoft workload, provide a security certification, or treat uncollected evidence as a passing check.</p>
  </Panel></div>;
}
