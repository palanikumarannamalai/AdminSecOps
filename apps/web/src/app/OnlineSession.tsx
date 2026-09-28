import { createContext, use, useEffect, type ReactNode } from 'react';
import { z } from 'zod';
import { ApiError, CLIENT_HEADER, toApiError } from '../api/client';
import { LoadingState, ErrorState } from '../components/States';
import { SignInPage } from '../pages/SignInPage';
import { useAsync } from '../hooks/useAsync';

const sessionSchema = z.object({
  authenticated: z.literal(true),
  onPremEnabled: z.boolean().optional(),
  user: z.object({ displayName: z.string(), tenantId: z.string(), userId: z.string() }),
  connection: z.object({
    connected: z.boolean(),
    /** Read-only Graph scopes the online collector uses. */
    requiredScopes: z.array(z.string().max(100)).max(50).optional(),
    /** Scopes Microsoft reported as granted at sign-in; null when not reported. */
    grantedScopes: z.array(z.string().max(100)).max(100).nullable().optional(),
    /** Required scopes that were not granted (or not requested by this deployment). */
    missingScopes: z.array(z.string().max(100)).max(50).optional(),
  }),
  /** Optional per-resource connectors (Azure, Exchange Online) and on-premises availability. */
  connectors: z.array(z.object({
    id: z.enum(['azure', 'exchange', 'onPremises']),
    label: z.string().max(200),
    state: z.enum(['connected', 'not-connected', 'expired', 'disabled', 'runtime-unavailable', 'unsupported']),
    reason: z.string().max(1000),
    permission: z.string().max(1000),
    role: z.string().max(1000),
    connectUrl: z.string().regex(/^\/auth\/connect\/(azure|exchange)$/).nullable(),
    reconnectUrl: z.string().regex(/^\/auth\/connect\/(azure|exchange)\?consent=true$/).nullable(),
    connectedAt: z.string().max(50).nullable(),
  })).max(10).optional(),
});
export type OnlineConnector = NonNullable<Session['connectors']>[number];
type Session = z.infer<typeof sessionSchema>;
const SessionContext = createContext<Session | null>(null);


export async function onlineRequest(path: string, signal?: AbortSignal, method = 'GET', payload: unknown = {}): Promise<unknown> {
  const response = await fetch(path, {
    method, credentials: 'same-origin', signal,
    headers: { [CLIENT_HEADER]: 'web', Accept: 'application/json', ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}) },
    ...(method === 'POST' ? { body: JSON.stringify(payload) } : {}),
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
