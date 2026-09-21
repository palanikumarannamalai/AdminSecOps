import { createContext, use, useEffect, type ReactNode } from 'react';
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
      return <main className="main"><section className="panel"><h1>AdminSecOps online</h1>
        <p>Sign in with your Palani Lab Microsoft account to run read-only Entra assessments.</p>
        <a href="/auth/login" className="button">Sign in with Microsoft</a>
        <p className="muted">Test release. Evidence is collected and processed by the hosted service and saved in its database.</p>
      </section></main>;
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
