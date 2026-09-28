/* eslint-disable @typescript-eslint/unbound-method -- Store methods are Vitest spies, never detached calls. */
import { describe, expect, it, vi } from 'vitest';
import { UnsecuredJWT } from 'jose';
import { buildServer } from './server.js';
import { encryptConnectorTokens, encryptTokens, hashToken, type ConnectorTokens } from './auth.js';
import type { ExchangeRunner } from './collector/index.js';
import { loadConfig } from './config.js';
import type { Store, StoredSession } from './store.js';
import type { OnPremStore } from './onprem-store.js';

const config = loadConfig({ PUBLIC_URL: 'https://admin.example.com', AZURE_TENANT_ID: '11111111-1111-1111-1111-111111111111', AZURE_CLIENT_ID: '22222222-2222-2222-2222-222222222222', AZURE_CLIENT_SECRET: 'test-only-secret', ALLOWED_USER_IDS: '33333333-3333-3333-3333-333333333333', TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 1).toString('base64'), DATABASE_URL: 'postgresql://localhost/test', GRAPH_SCOPES: 'https://graph.microsoft.com/User.Read' });
const token = 'a'.repeat(43);
function fixture(overrides: Partial<StoredSession> = {}) {
  const current: StoredSession = { idHash: hashToken(token), tenantId: config.tenantId, userId: config.allowedUserIds[0]!, displayName: 'Test Admin', expiresAt: new Date(Date.now() + 60_000), encryptedTokens: encryptTokens({ accessToken: 'test-only', expiresAt: Date.now() + 600_000 }, config.tokenEncryptionKey), ...overrides };
  const store: Store = { putSession: vi.fn(() => Promise.resolve()), getSession: vi.fn(() => Promise.resolve(current)), deleteSession: vi.fn(() => Promise.resolve()), createJob: vi.fn(() => Promise.resolve({ id: 'job', status: 'queued' })), listJobs: vi.fn(() => Promise.resolve([])), listAssessments: vi.fn(() => Promise.resolve([])), getAssessment: vi.fn(() => Promise.resolve(null)) };
  return store;
}
const headers = { cookie: `__Host-adminsecops=${token}`, origin: config.publicUrl, 'x-adminsecops-client': 'web' };

describe('hosted HTTP boundary', () => {
  it('keeps upload credentials out of session-only APIs and protects browser enrollment from CSRF', async () => {
    const onPremStore: OnPremStore = {
      enroll: vi.fn(), agents: vi.fn(() => Promise.resolve([])), revoke: vi.fn(),
      authenticate: vi.fn(() => Promise.resolve(null)), save: vi.fn(),
    };
    const app = await buildServer({ config, store: fixture(), onPremStore });
    const bearer = { authorization: `Bearer ${token}` };
    for (const url of ['/api/onprem/agents', '/api/assessments']) {
      expect((await app.inject({ url, headers: bearer })).statusCode).toBe(401);
    }
    expect((await app.inject({ method: 'POST', url: '/api/onprem/agents', headers: { ...headers, origin: 'https://attacker.example' }, payload: { name: 'test' } })).statusCode).toBe(403);
    expect(onPremStore.enroll).not.toHaveBeenCalled();
    expect((await app.inject({ method: 'POST', url: '/api/onprem/ingest', headers: { ...bearer, 'content-type': 'application/zip' }, payload: Buffer.from('invalid') })).statusCode).toBe(401);
    expect(onPremStore.authenticate).toHaveBeenCalled();
    expect((await app.inject({ url: '/api/me', headers })).json()).toMatchObject({ onPremEnabled: true });
    await app.close();
  });
  it('handles declined Microsoft consent without reflecting provider errors', async () => {
    const app = await buildServer({ config, store: fixture() });
    const response = await app.inject({ url: '/auth/callback?error=access_denied&error_description=PRIVATE-DETAIL' });
    expect(response.statusCode).toBe(401);
    expect(response.body).toContain('Restart sign-in');
    expect(response.body).not.toContain('PRIVATE-DETAIL');
    await app.close();
  });
  it('routes open sign-in without exposing a tenant directory and requires fresh role authorization', async () => {
    const open = { ...config, openTenantOnboarding: true };
    const app = await buildServer({ config: open, store: fixture() });
    expect((await app.inject({ url: '/auth/login' })).headers.location).toContain('/organizations/');
    expect((await app.inject({ url: '/auth/login?tenantId=common' })).statusCode).toBe(403);
    expect((await app.inject({ url: '/api/me', headers })).statusCode).toBe(401);
    await app.close();
  });
  it('scopes open customer sessions to their own tenant and never query input', async () => {
    const open = { ...config, openTenantOnboarding: true };
    const tenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    const store = fixture({ tenantId: tenant, userId: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', encryptedTokens: encryptTokens({ accessToken: 'customer', expiresAt: Date.now() + 600_000, authorizationExpiresAt: Date.now() + 60_000 }, config.tokenEncryptionKey) });
    const app = await buildServer({ config: open, store });
    expect((await app.inject({ url: '/api/me', headers })).json().user.tenantId).toBe(tenant);
    await app.inject({ url: `/api/jobs?tenantId=${config.tenantId}`, headers });
    expect(store.listJobs).toHaveBeenCalledWith(tenant);
    await app.inject({ url: `/api/assessments?tenantId=${config.tenantId}`, headers });
    expect(store.listAssessments).toHaveBeenCalledWith(tenant);
    const id = '44444444-4444-4444-4444-444444444444';
    expect((await app.inject({ url: `/api/assessments/${id}/report.json`, headers })).statusCode).toBe(404);
    expect((await app.inject({ url: `/api/assessments/${id}/report.html`, headers })).statusCode).toBe(404);
    expect((await app.inject({ url: `/api/assessments/${id}`, headers })).statusCode).toBe(404);
    expect((await app.inject({ url: `/api/compare?baseline=${id}&current=${id}`, headers })).statusCode).toBe(404);
    expect(store.getAssessment).toHaveBeenCalledWith(tenant, id);
    expect((await app.inject({ method: 'POST', url: '/api/jobs', headers, payload: {} })).statusCode).toBe(202);
    expect(store.createJob).toHaveBeenCalledWith(tenant, 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', expect.any(String), null);
    await app.close();
  });
  it('rejects expired administrator authorization even with an unexpired session', async () => {
    const app = await buildServer({ config: { ...config, openTenantOnboarding: true }, store: fixture({ encryptedTokens: encryptTokens({ accessToken: 'customer', expiresAt: Date.now() + 600_000, authorizationExpiresAt: 0 }, config.tokenEncryptionKey) }) });
    expect((await app.inject({ url: '/api/me', headers })).statusCode).toBe(401);
    await app.close();
  });
  it('requires a session for all sensitive endpoints', async () => {
    const app = await buildServer({ config, store: fixture() });
    for (const url of ['/api/me', '/api/jobs', '/api/assessments', '/api/controls']) expect((await app.inject({ url })).statusCode).toBe(401);
    expect((await app.inject({ url: '/api/health' })).json()).toEqual({ status: 'ok' });
    await app.close();
  });
  it('rejects expired sessions and users/tenants outside the test allowlist', async () => {
    for (const overrides of [{ expiresAt: new Date(0) }, { tenantId: 'foreign' }, { userId: 'foreign' }]) {
      const app = await buildServer({ config, store: fixture(overrides) });
      expect((await app.inject({ url: '/api/me', headers })).statusCode).toBe(401);
      await app.close();
    }
  });
  it('enforces CSRF and server-owned identity on job creation', async () => {
    const store = fixture();
    const app = await buildServer({ config, store });
    expect((await app.inject({ method: 'POST', url: '/api/jobs', headers: { cookie: headers.cookie }, payload: {} })).statusCode).toBe(403);
    expect((await app.inject({ method: 'POST', url: '/api/jobs', headers: { ...headers, origin: 'https://attacker.example' }, payload: {} })).statusCode).toBe(403);
    expect((await app.inject({ method: 'POST', url: '/api/jobs', headers, payload: { tenantId: 'foreign' } })).statusCode).toBe(400);
    expect((await app.inject({ method: 'POST', url: '/api/jobs', headers, payload: {} })).statusCode).toBe(202);
    expect(store.createJob).toHaveBeenCalledWith(config.tenantId, config.allowedUserIds[0], expect.any(String), null);
    await app.close();
  });
  it('scopes assessment reads and clears session on logout', async () => {
    const store = fixture();
    const app = await buildServer({ config, store });
    const id = '44444444-4444-4444-4444-444444444444';
    expect((await app.inject({ url: `/api/assessments/${id}`, headers })).statusCode).toBe(404);
    expect(store.getAssessment).toHaveBeenCalledWith(config.tenantId, id);
    const logout = await app.inject({ method: 'POST', url: '/auth/logout', headers });
    expect(logout.statusCode).toBe(204);
    expect(logout.headers['set-cookie']).toContain('Max-Age=0');
    expect(store.deleteSession).toHaveBeenCalledWith(hashToken(token));
    await app.close();
  });
  it('reports active job conflicts and rate limits repeated assessment requests', async () => {
    const store = fixture();
    vi.mocked(store.createJob).mockRejectedValue(Object.assign(new Error('database constraint'), { code: '23505' }));
    const app = await buildServer({ config, store });
    for (let count = 0; count < 3; count++) expect((await app.inject({ method: 'POST', url: '/api/jobs', headers, payload: {} })).statusCode).toBe(409);
    expect((await app.inject({ method: 'POST', url: '/api/jobs', headers, payload: {} })).statusCode).toBe(429);
    await app.close();
  });
  it('offers an explicit re-consent sign-in and rejects other consent values', async () => {
    const app = await buildServer({ config, store: fixture() });
    const consent = new URL((await app.inject({ url: '/auth/login?consent=true' })).headers.location as string);
    expect(consent.searchParams.get('prompt')).toBe('consent');
    const normal = new URL((await app.inject({ url: '/auth/login' })).headers.location as string);
    expect(normal.searchParams.get('prompt')).toBe('select_account');
    expect((await app.inject({ url: '/auth/login?consent=admin' })).statusCode).toBe(400);
    await app.close();
  });
  it('reports online scopes that were not granted without exposing tokens', async () => {
    const store = fixture({ encryptedTokens: encryptTokens({ accessToken: 'secret-access', expiresAt: Date.now() + 600_000, scopes: ['Policy.Read.All', 'Organization.Read.All'] }, config.tokenEncryptionKey) });
    const app = await buildServer({ config, store });
    const response = await app.inject({ url: '/api/me', headers });
    const body = response.json<{ connection: { grantedScopes: string[]; missingScopes: string[]; requiredScopes: string[] } }>();
    expect(body.connection.grantedScopes).toEqual(['Policy.Read.All', 'Organization.Read.All']);
    expect(body.connection.missingScopes).toContain('SharePointTenantSettings.Read.All');
    expect(body.connection.missingScopes).toContain('DeviceManagementConfiguration.Read.All');
    expect(body.connection.missingScopes).not.toContain('Policy.Read.All');
    expect(response.body).not.toContain('secret-access');
    await app.close();
  });
  describe('resource connectors', () => {
    const enabled = { ...config, connectors: { azure: true, exchange: true }, exchangePwshPath: '/usr/bin/pwsh' };
    const armToken = (claims: Record<string, unknown> = {}) => new UnsecuredJWT({ aud: 'https://management.azure.com', tid: config.tenantId, oid: config.allowedUserIds[0], scp: 'user_impersonation', ...claims }).setExpirationTime('1h').encode();
    const sealedArm = (overrides: Partial<ConnectorTokens> = {}) =>
      encryptConnectorTokens({ connector: 'azure', tenantId: config.tenantId, userId: config.allowedUserIds[0]!, accessToken: armToken(), refreshToken: 'arm-refresh-secret', expiresAt: Date.now() + 600_000, connectedAt: Date.UTC(2026, 8, 22), ...overrides }, config.tokenEncryptionKey);
    const runner = (available: boolean): ExchangeRunner => ({ status: () => Promise.resolve({ available, reason: available ? 'ready' : 'PowerShell is not installed or could not be started on this server.' }), run: vi.fn() });

    it('requires a session and an enabled connector, and starts tenant-specific consent with only the resource scope', async () => {
      const app = await buildServer({ config: enabled, store: fixture() });
      expect((await app.inject({ url: '/auth/connect/azure' })).statusCode).toBe(401);
      expect((await app.inject({ url: '/auth/connect/shell', headers })).statusCode).toBe(404);
      expect((await app.inject({ url: '/auth/connect/azure?consent=admin', headers })).statusCode).toBe(400);
      const response = await app.inject({ url: '/auth/connect/azure', headers });
      expect(response.statusCode).toBe(302);
      const location = new URL(response.headers.location as string);
      expect(location.pathname).toBe(`/${config.tenantId}/oauth2/v2.0/authorize`);
      expect(location.searchParams.get('scope')).toBe('https://management.azure.com/user_impersonation openid profile offline_access');
      expect(String(response.headers['set-cookie'])).toContain('__Host-adminsecops-login=');
      expect(new URL((await app.inject({ url: '/auth/connect/exchange?consent=true', headers })).headers.location as string).searchParams.get('prompt')).toBe('consent');
      // Another site cannot start a connection for the signed-in administrator.
      for (const site of ['cross-site', 'same-site']) expect((await app.inject({ url: '/auth/connect/azure', headers: { ...headers, 'sec-fetch-site': site } })).statusCode).toBe(403);
      expect((await app.inject({ url: '/auth/connect/azure', headers: { ...headers, 'sec-fetch-site': 'same-origin' } })).statusCode).toBe(302);
      await app.close();
      const disabled = await buildServer({ config, store: fixture() });
      expect((await disabled.inject({ url: '/auth/connect/azure', headers })).statusCode).toBe(404);
      await disabled.close();
    });

    it('refuses connector sign-in when the one-hour administrator authorization has expired', async () => {
      const app = await buildServer({ config: { ...enabled, openTenantOnboarding: true }, store: fixture({ encryptedTokens: encryptTokens({ accessToken: 'x', expiresAt: Date.now() + 600_000, authorizationExpiresAt: 0 }, config.tokenEncryptionKey) }) });
      expect((await app.inject({ url: '/auth/connect/azure', headers })).statusCode).toBe(401);
      await app.close();
    });

    it('does not attach a connector callback without the session that started it', async () => {
      const app = await buildServer({ config: enabled, store: fixture() });
      const start = await app.inject({ url: '/auth/connect/azure', headers });
      const transaction = /__Host-adminsecops-login=([^;]+)/.exec(String(start.headers['set-cookie']))![1]!;
      const state = new URL(start.headers.location as string).searchParams.get('state')!;
      const noSession = await app.inject({ url: `/auth/callback?state=${state}&code=c`, headers: { cookie: `__Host-adminsecops-login=${transaction}` } });
      expect(noSession.statusCode).toBe(401);
      const declined = await app.inject({ url: '/auth/callback?error=consent_required&error_description=PRIVATE-DETAIL', headers: { cookie: `__Host-adminsecops-login=${transaction}; ${headers.cookie}` } });
      expect(declined.statusCode).toBe(401);
      expect(declined.body).toContain('connector');
      expect(declined.body).not.toContain('PRIVATE-DETAIL');
      const invalidScope = await app.inject({ url: '/auth/callback?' + new URLSearchParams({ error: 'invalid_scope', error_description: 'AADSTS70011: PRIVATE-TOKEN-DETAIL' }).toString(), headers: { cookie: `__Host-adminsecops-login=${transaction}; ${headers.cookie}` } });
      expect(invalidScope.statusCode).toBe(401);
      expect(invalidScope.body).toContain('AADSTS70011, invalid_scope');
      expect(invalidScope.body).not.toContain('PRIVATE-TOKEN-DETAIL');
      const untrusted = await app.inject({ url: '/auth/callback?' + new URLSearchParams({ error: 'SECRET-IN-ERROR', error_description: 'AADSTS70011 ' + 'x'.repeat(8192) }).toString(), headers: { cookie: `__Host-adminsecops-login=${transaction}; ${headers.cookie}` } });
      expect(untrusted.body).not.toContain('SECRET-IN-ERROR');
      expect(untrusted.body).not.toContain('AADSTS70011');
      await app.close();
    });

    it('reports each connector state without exposing tokens', async () => {
      const store = fixture({ encryptedConnectors: JSON.stringify({ azure: sealedArm() }) });
      const app = await buildServer({ config: enabled, store, exchangeRunner: runner(false) });
      const response = await app.inject({ url: '/api/me', headers });
      const body = response.json<{ connectors: { id: string; state: string; connectUrl: string | null }[] }>();
      expect(body.connectors.map((c) => [c.id, c.state])).toEqual([['azure', 'connected'], ['exchange', 'runtime-unavailable'], ['onPremises', 'unsupported']]);
      expect(body.connectors.find((c) => c.id === 'exchange')?.connectUrl).toBeNull();
      expect(response.body).not.toContain('arm-refresh-secret');
      expect(response.body).not.toContain(armToken().split('.')[1]!);
      await app.close();

      const plain = await buildServer({ config, store: fixture() });
      const states = (await plain.inject({ url: '/api/me', headers })).json<{ connectors: { id: string; state: string }[] }>().connectors.map((c) => c.state);
      expect(states).toEqual(['disabled', 'disabled', 'unsupported']);
      await plain.close();

      // A connector sealed for another user of the tenant is ignored.
      const foreign = encryptConnectorTokens({ connector: 'azure', tenantId: config.tenantId, userId: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', accessToken: armToken(), expiresAt: Date.now() + 600_000, connectedAt: 1 }, config.tokenEncryptionKey);
      const swapped = await buildServer({ config: enabled, store: fixture({ encryptedConnectors: JSON.stringify({ azure: foreign }) }), exchangeRunner: runner(true) });
      const view = (await swapped.inject({ url: '/api/me', headers })).json<{ connectors: { id: string; state: string }[] }>().connectors;
      expect(view.map((c) => c.state)).toEqual(['not-connected', 'not-connected', 'unsupported']);
      await swapped.close();
    });

    it('disconnects a connector only with the CSRF-protected POST', async () => {
      const store = fixture({ encryptedConnectors: JSON.stringify({ azure: sealedArm() }) });
      const app = await buildServer({ config: enabled, store });
      expect((await app.inject({ method: 'POST', url: '/api/connectors/azure/disconnect', headers: { cookie: headers.cookie } })).statusCode).toBe(403);
      expect((await app.inject({ method: 'POST', url: '/api/connectors/azure/disconnect', headers, payload: {} })).statusCode).toBe(204);
      expect(store.putSession).toHaveBeenCalledWith(expect.objectContaining({ encryptedConnectors: null }));
      await app.close();
    });

    it('passes separately sealed connector tokens to the job and records unusable connectors', async () => {
      const store = fixture({ encryptedConnectors: JSON.stringify({ azure: sealedArm() }) });
      const app = await buildServer({ config: enabled, store });
      expect((await app.inject({ method: 'POST', url: '/api/jobs', headers, payload: {} })).statusCode).toBe(202);
      const jobConnectors = vi.mocked(store.createJob).mock.calls[0]?.[3];
      expect(typeof jobConnectors).toBe('string');
      expect(Object.keys(JSON.parse(jobConnectors as string) as object)).toEqual(['azure']);
      expect(jobConnectors).not.toContain('arm-refresh-secret');
      await app.close();

      // An expired connector without a refresh token is recorded as expired, and the job still runs.
      const expiredStore = fixture({ encryptedConnectors: JSON.stringify({ azure: sealedArm({ refreshToken: undefined, expiresAt: 0 }) }) });
      const expiredApp = await buildServer({ config: enabled, store: expiredStore });
      expect((await expiredApp.inject({ method: 'POST', url: '/api/jobs', headers, payload: {} })).statusCode).toBe(202);
      expect(JSON.parse(vi.mocked(expiredStore.createJob).mock.calls[0]?.[3] as string)).toEqual({ gaps: { azure: 'expired' } });
      await expiredApp.close();
    });
  });

  it('asks for reconnection when Graph credentials have expired', async () => {
    const store = fixture({ encryptedTokens: encryptTokens({ accessToken: 'expired', expiresAt: 0 }, config.tokenEncryptionKey) });
    const app = await buildServer({ config, store });
    const response = await app.inject({ method: 'POST', url: '/api/jobs', headers, payload: {} });
    expect(response.statusCode).toBe(401);
    expect(store.createJob).not.toHaveBeenCalled();
    await app.close();
  });
});
