import { createContext, use, useEffect, useState, type ReactNode } from 'react';
import { z } from 'zod';
import { ApiError, CLIENT_HEADER, toApiError } from '../api/client';
import { LoadingState, ErrorState } from '../components/States';
import { useAsync } from '../hooks/useAsync';

const sessionSchema = z.object({
  authenticated: z.literal(true),
  user: z.object({ displayName: z.string(), tenantId: z.string(), userId: z.string() }),
  connection: z.object({ connected: z.boolean() }),
});
type Session = z.infer<typeof sessionSchema>;
const SessionContext = createContext<Session | null>(null);

function SignInPage() {
  const [tenant, setTenant] = useState('');
  const tenantId = tenant.trim();
  const validTenant = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenantId);
  return <main className="main"><section className="panel"><h1>AdminSecOps online</h1>
    <p>Connect your Microsoft organization to run read-only Entra assessments. Sign in with a supported administrator or security-reader role.</p>
    <a href="/auth/login" className="button">Sign in with Microsoft</a>
    <p className="muted">Sign in with your Microsoft work account, or optionally enter a specific organization's directory ID below.</p>
    <label htmlFor="login-tenant-id">Directory (tenant) ID</label>
    <input id="login-tenant-id" className="input" type="text" value={tenant} autoComplete="off" spellCheck={false}
      aria-describedby="tenant-help tenant-validation" aria-invalid={tenantId !== '' && !validTenant}
      onChange={(event) => setTenant(event.target.value)} />
    <p id="tenant-help" className="muted">Use the directory ID from your organization's Microsoft Entra overview. Customer directories are not publicly listed.</p>
    <p id="tenant-validation" className="error-text" role="status">{tenantId !== '' && !validTenant ? 'Enter a valid directory ID in UUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).' : ''}</p>
    {validTenant ? <a className="button" href={`/auth/login?tenantId=${encodeURIComponent(tenantId.toLowerCase())}`}>Sign in to customer tenant</a>
      : <button className="button" disabled>Sign in to customer tenant</button>}
    <p>Supported roles: Global Administrator, Security Administrator, Global Reader, Security Reader, or Privileged Role Administrator.</p>
    <p>A tenant administrator must grant consent on Microsoft's screen for the application's read-only Microsoft Graph permissions before collection can work. A supported sign-in role does not automatically grant permission to consent. No scripts need to be downloaded or run.</p>
    <p className="muted">Test release. Raw evidence is processed in memory by the hosted service. Assessment results are stored for 30 days and audit events for 90 days.</p>
  </section></main>;
}

export async function onlineRequest(path: string, signal?: AbortSignal, method = 'GET'): Promise<unknown> {
  const response = await fetch(path, {
    method, credentials: 'same-origin', signal,
    headers: { [CLIENT_HEADER]: 'web', Accept: 'application/json', ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}) },
    ...(method === 'POST' ? { body: '{}' } : {}),
  });
  const body = await response.text();
  if (!response.ok) {
    if (response.status === 401 && path !== '/api/me') window.dispatchEvent(new Event('adminsecops-session-expired'));
    throw toApiError(response.status, body);
  }
  return body === '' ? null : JSON.parse(body) as unknown;
}

export function OnlineSession({ children }: { children: ReactNode }) {
  const session = useAsync('session', async (signal) => sessionSchema.parse(await onlineRequest('/api/me', signal)));
  const reload = session.reload;
  useEffect(() => {
    window.addEventListener('adminsecops-session-expired', reload);
    return () => window.removeEventListener('adminsecops-session-expired', reload);
  }, [reload]);
  if (session.status === 'loading') return <LoadingState label="Checking your session" />;
  if (session.status === 'error') {
    if (session.error instanceof ApiError && session.error.status === 401) {
      return <SignInPage />;
    }
    return <ErrorState title="Sign-in service unavailable" error={session.error} onRetry={session.reload} />;
  }
  return <SessionContext value={session.data}>{children}</SessionContext>;
}

export function useOnlineSession(): Session {
  const session = use(SessionContext);
  if (session === null) throw new Error('OnlineSession is missing');
  return session;
}
