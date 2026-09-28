import { useEffect, useState } from 'react';
import { z } from 'zod';
import { Panel } from './PageHeader';
import { errorMessage } from '../api/client';
const agentSchema = z.object({
  id: z.string(),
  name: z.string(),
  expiresAt: z.string(),
  revoked: z.boolean(),
});
const agentList = z.object({ agents: z.array(agentSchema) });
type Agent = z.infer<typeof agentSchema>;
async function request(path: string, body?: BodyInit, type = 'application/json') {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST',
    credentials: 'same-origin',
    headers: { 'x-adminsecops-client': 'web', 'Content-Type': type },
    ...(body === undefined ? {} : { body }),
  });
  if (response.status === 204) return null;
  const data: unknown = await response.json();
  if (!response.ok) {
    const parsed = z.object({ error: z.object({ message: z.string() }) }).safeParse(data);
    throw new Error(parsed.success ? parsed.data.error.message : 'Request failed');
  }
  return data;
}
export function OnPremPanel({ tenantId }: { tenantId: string }) {
  const [now] = useState(() => Date.now());
  const [agents, setAgents] = useState<Agent[]>([]);
  const [name, setName] = useState('');
  const [credential, setCredential] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const refresh = async () =>
    setAgents(agentList.parse(await request('/api/onprem/agents')).agents);
  useEffect(() => {
    let active = true;
    void request('/api/onprem/agents')
      .then((data) => {
        if (active) setAgents(agentList.parse(data).agents);
      })
      .catch((e) => {
        if (active) setError(errorMessage(e));
      });
    return () => {
      active = false;
    };
  }, []);
  const enroll = async () => {
    setBusy(true);
    setError(null);
    try {
      const data = z
        .object({ token: z.string(), agent: agentSchema })
        .parse(await request('/api/onprem/agents', JSON.stringify({ name })));
      setCredential(data.token);
      await refresh();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const upload = async (file: File) => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      if (file.size > 20 * 1024 * 1024)
        throw new Error('Choose an evidence ZIP no larger than 20 MB.');
      const data = z
        .object({ assessmentId: z.string() })
        .parse(await request('/api/onprem/upload', file, 'application/zip'));
      setResult(data.assessmentId);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Panel title="On-premises collection" id="onprem">
      <p>
        Run the read-only collector inside the network to assess AD, AD CS, Group Policy and the
        Windows host it runs on. The website cannot reach private servers directly.
      </p>
      <p>
        <a className="button" href="/downloads/configreview-onprem.zip" download>
          Download collector and agent
        </a>{' '}
        <a href="/downloads/configreview-onprem-guide.txt">Setup instructions</a>
      </p>
      <p>
        Use tenant ID <code>{tenantId}</code>. Review the generated evidence before uploading. It
        includes directory and host configuration and identifiers. Uploading sends it to this
        workspace; results follow the existing 30-day retention. Packages are not signed, and tenant
        association is declared by the uploader.
      </p>
      <label>
        Upload an on-premises evidence ZIP (maximum 20 MB)
        <input
          type="file"
          accept=".zip"
          disabled={busy}
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void upload(file);
            event.target.value = '';
          }}
        />
      </label>
      {result ? (
        <p role="status">
          Assessment saved.{' '}
          <a href={`#/assessments/${encodeURIComponent(result)}`}>Open on-premises results</a>
        </p>
      ) : null}
      <h3>Scheduled agent</h3>
      <p>
        The agent runs locally under your chosen Windows account and sends evidence over outbound
        HTTPS. It cannot receive commands or change configuration. Credentials expire after 30 days
        and allow uploads only. Install it using the included instructions; no software is installed
        by this page.
      </p>
      <label>
        Agent name
        <input value={name} maxLength={80} onChange={(event) => setName(event.target.value)} />
      </label>
      <button className="button" disabled={busy || !name.trim()} onClick={() => void enroll()}>
        Create upload credential
      </button>
      {credential ? (
        <div className="notice">
          <p>
            Copy this credential into the local setup prompt. It is shown once and is not saved in
            your browser. Do not share it in reports or support messages.
          </p>
          <textarea aria-label="Agent upload credential" readOnly value={credential} />
          <button className="button" onClick={() => setCredential(null)}>
            Hide credential
          </button>
        </div>
      ) : null}
      <ul>
        {agents.map((a) => (
          <li key={a.id}>
            {a.name} — expires {new Date(a.expiresAt).toLocaleDateString()} —{' '}
            {a.revoked ? 'Revoked' : new Date(a.expiresAt).getTime() < now ? 'Expired' : 'Active'}{' '}
            {!a.revoked ? (
              <button
                className="button"
                disabled={busy}
                onClick={() => {
                  void request(`/api/onprem/agents/${encodeURIComponent(a.id)}/revoke`, '{}')
                    .then(refresh)
                    .catch((e) => setError(errorMessage(e)));
                }}
              >
                Revoke
              </button>
            ) : null}
          </li>
        ))}
      </ul>
      <p>
        Cloud and on-premises snapshots remain separate. A scheduled task stops uploading after its
        credential expires or is revoked; renew through this workspace.
      </p>
      {error ? (
        <p role="alert" className="error-text">
          {error}
        </p>
      ) : null}
    </Panel>
  );
}
