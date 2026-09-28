import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppProvider } from '../app/context';
import { OnlineSession } from '../app/OnlineSession';
import { createFakeApi } from '../test/render';
import { OnlineHomePage } from './OnlineHomePage';

const session = { authenticated: true, user: { displayName: 'Test administrator', userId: 'user', tenantId: 'tenant' }, connection: { connected: true } };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
function mount() {
  const api = createFakeApi({ listAssessments: vi.fn(() => Promise.resolve([])) });
  const view = render(<MemoryRouter><OnlineSession><AppProvider api={api}><OnlineHomePage /></AppProvider></OnlineSession></MemoryRouter>);
  return { ...view, api };
}
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe('online assessment flow', () => {
  it('requires sign-in before fetching assessment data and does not loop on 401', async () => {
    const fetcher = vi.fn(() => Promise.resolve(json({ error: { message: 'Sign in' } }, 401)));
    vi.stubGlobal('fetch', fetcher);
    const { api } = mount();
    expect((await screen.findByRole('link', { name: 'Sign in with Microsoft' })).getAttribute('href')).toBe('/auth/login');
    expect(api.listAssessments).not.toHaveBeenCalled();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('button', { name: 'Run assessment' })).toBeNull();
  });

  it('shows failed jobs and submission errors without claiming success', async () => {
    const fetcher = vi.fn((path: string, init?: RequestInit) => {
      if (path === '/api/me') return Promise.resolve(json(session));
      if (init?.method === 'POST') return Promise.resolve(json({ error: { message: 'Consent is missing', code: 'consent_required' } }, 403));
      return Promise.resolve(json({ jobs: [{ id: 'job', status: 'failed', createdAt: '2026-09-21T00:00:00Z', error: 'Graph permission denied', assessmentId: null }] }));
    });
    vi.stubGlobal('fetch', fetcher);
    const { unmount } = mount();
    expect(await screen.findByText('Graph permission denied')).toBeTruthy();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Run assessment' }));
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Consent is missing');
    const post = fetcher.mock.calls.find(([, init]) => init?.method === 'POST');
    expect(post?.[1]?.headers).toMatchObject({ 'X-AdminSecOps-Client': 'web' });
    expect(screen.queryByText('View assessment')).toBeNull();
    unmount();
  });

  it('validates customer directory IDs and preserves the default organization login', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(json({}, 401))));
    mount();
    const user = userEvent.setup();
    const input = await screen.findByLabelText('Directory (tenant) ID');
    expect(screen.getByRole('button', { name: 'Sign in to customer tenant' })).toHaveProperty('disabled', true);
    await user.type(input, 'https://untrusted.example');
    expect(input.getAttribute('aria-invalid')).toBe('true');
    expect(screen.queryByRole('link', { name: 'Sign in to customer tenant' })).toBeNull();
    await user.clear(input);
    await user.type(input, ' AAAAAAAA-0000-4000-8000-000000000002 ');
    expect(screen.getByRole('link', { name: 'Sign in to customer tenant' }).getAttribute('href')).toBe('/auth/login?tenantId=aaaaaaaa-0000-4000-8000-000000000002');
    expect(screen.getByRole('link', { name: 'Sign in with Microsoft' }).getAttribute('href')).toBe('/auth/login');
  });

  it('shows the current tenant and sends a protected logout request when switching', async () => {
    const fetcher = vi.fn((path: string) => {
      if (path === '/api/me') return Promise.resolve(json(session));
      if (path === '/auth/logout') return Promise.resolve(json({ error: { message: 'Sign-out unavailable' } }, 503));
      return Promise.resolve(json({ jobs: [] }));
    });
    vi.stubGlobal('fetch', fetcher);
    mount();
    expect(await screen.findByText('tenant', { selector: 'code' })).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Before you run' })).toBeTruthy();
    expect(screen.getByText(/You can run a partial assessment/)).toBeTruthy();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Sign out / switch tenant' }));
    expect(fetcher).toHaveBeenCalledWith('/auth/logout', expect.objectContaining({ method: 'POST', credentials: 'same-origin', headers: expect.objectContaining({ 'X-AdminSecOps-Client': 'web' }) }));
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Sign-out unavailable');
  });

  it('lists missing read-only permissions with a re-consent path', async () => {
    const withMissing = { ...session, connection: { connected: true, requiredScopes: ['Policy.Read.All', 'SharePointTenantSettings.Read.All'], grantedScopes: ['Policy.Read.All'], missingScopes: ['SharePointTenantSettings.Read.All'] } };
    vi.stubGlobal('fetch', vi.fn((path: string) => Promise.resolve(json(path === '/api/me' ? withMissing : { jobs: [] }))));
    mount();
    expect(await screen.findByText('SharePointTenantSettings.Read.All')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Reconnect and review Microsoft consent' }).getAttribute('href')).toBe('/auth/login?consent=true');
  });

  it('does not show the consent notice when every scope is granted', async () => {
    vi.stubGlobal('fetch', vi.fn((path: string) => Promise.resolve(json(path === '/api/me' ? { ...session, connection: { connected: true, missingScopes: [] } } : { jobs: [] }))));
    mount();
    await screen.findByRole('button', { name: 'Run assessment' });
    expect(screen.queryByRole('link', { name: 'Reconnect and review Microsoft consent' })).toBeNull();
  });

  it('shows each data source with honest connect, reconnect and unavailable states', async () => {
    const connector = (id: string, state: string, links: boolean) => ({
      id, label: id === 'azure' ? 'Azure Resource Manager' : id === 'exchange' ? 'Exchange Online' : 'On-premises Active Directory, AD CS, Group Policy and Windows',
      state, reason: `${id} ${state} reason`, permission: 'perm', role: 'role',
      connectUrl: links ? `/auth/connect/${id}` : null, reconnectUrl: links ? `/auth/connect/${id}?consent=true` : null,
      connectedAt: state === 'connected' ? '2026-09-22T08:00:00Z' : null,
    });
    const withConnectors = { ...session, connectors: [connector('azure', 'not-connected', true), connector('exchange', 'runtime-unavailable', false), connector('onPremises', 'unsupported', false)] };
    vi.stubGlobal('fetch', vi.fn((path: string) => Promise.resolve(json(path === '/api/me' ? withConnectors : { jobs: [] }))));
    const first = mount();
    expect((await screen.findByRole('link', { name: 'Connect Azure Resource Manager' })).getAttribute('href')).toBe('/auth/connect/azure');
    // No fake ready button for sources the server cannot use.
    expect(screen.queryByRole('link', { name: 'Connect Exchange Online' })).toBeNull();
    expect(screen.getByText('Not available on this server')).toBeTruthy();
    expect(screen.getByText('Not supported online')).toBeTruthy();
    first.unmount();

    const connected = { ...session, connectors: [connector('azure', 'connected', true)] };
    const fetcher = vi.fn((path: string, init?: RequestInit) => {
      if (path === '/api/me') return Promise.resolve(json(connected));
      if (init?.method === 'POST') return Promise.resolve(json({ error: { message: 'Could not disconnect' } }, 500));
      return Promise.resolve(json({ jobs: [] }));
    });
    vi.stubGlobal('fetch', fetcher);
    mount();
    expect((await screen.findByRole('link', { name: 'Reconnect Azure Resource Manager' })).getAttribute('href')).toBe('/auth/connect/azure?consent=true');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Disconnect' }));
    expect(fetcher).toHaveBeenCalledWith('/api/connectors/azure/disconnect', expect.objectContaining({ method: 'POST', headers: expect.objectContaining({ 'X-AdminSecOps-Client': 'web' }) }));
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Could not disconnect');
  });

  it('rejects connector links that do not point at the connect endpoints', async () => {
    const bad = { ...session, connectors: [{ id: 'azure', label: 'Azure', state: 'not-connected', reason: 'r', permission: 'p', role: 'r', connectUrl: 'https://attacker.example/', reconnectUrl: null, connectedAt: null }] };
    vi.stubGlobal('fetch', vi.fn((path: string) => Promise.resolve(json(path === '/api/me' ? bad : { jobs: [] }))));
    mount();
    expect(await screen.findByText('Sign-in service unavailable')).toBeTruthy();
    expect(screen.queryByRole('link', { name: /Connect Azure/ })).toBeNull();
  });

  it('refreshes completed history and cancels polling when unmounted', async () => {
    let calls = 0;
    let signal: AbortSignal | null | undefined;
    vi.stubGlobal('fetch', vi.fn((path: string, init?: RequestInit) => {
      if (path === '/api/me') return Promise.resolve(json(session));
      calls += 1; signal = init?.signal;
      return Promise.resolve(json({ jobs: [{ id: 'job', status: 'completed', createdAt: '2026-09-21T00:00:00Z', assessmentId: 'assessment' }] }));
    }));
    const { api, unmount } = mount();
    await screen.findByText('View assessment');
    await waitFor(() => expect(api.listAssessments).toHaveBeenCalledTimes(2));
    vi.useFakeTimers();
    unmount();
    expect(signal?.aborted).toBe(true);
    await act(async () => { await vi.advanceTimersByTimeAsync(10000); });
    expect(calls).toBe(1);
  });
});
