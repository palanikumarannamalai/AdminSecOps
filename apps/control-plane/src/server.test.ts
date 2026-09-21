/* eslint-disable @typescript-eslint/unbound-method -- Store methods are Vitest spies, never detached calls. */
import { describe, expect, it, vi } from 'vitest';
import { buildServer } from './server.js';
import { encryptTokens, hashToken } from './auth.js';
import { loadConfig } from './config.js';
import type { Store, StoredSession } from './store.js';

const config = loadConfig({ PUBLIC_URL: 'https://admin.example.com', AZURE_TENANT_ID: '11111111-1111-1111-1111-111111111111', AZURE_CLIENT_ID: '22222222-2222-2222-2222-222222222222', AZURE_CLIENT_SECRET: 'test-only-secret', ALLOWED_USER_IDS: '33333333-3333-3333-3333-333333333333', TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 1).toString('base64'), DATABASE_URL: 'postgresql://localhost/test', GRAPH_SCOPES: 'https://graph.microsoft.com/User.Read' });
const token = 'a'.repeat(43);
function fixture(overrides: Partial<StoredSession> = {}) {
  const current: StoredSession = { idHash: hashToken(token), tenantId: config.tenantId, userId: config.allowedUserIds[0]!, displayName: 'Test Admin', expiresAt: new Date(Date.now() + 60_000), encryptedTokens: encryptTokens({ accessToken: 'test-only', expiresAt: Date.now() + 600_000 }, config.tokenEncryptionKey), ...overrides };
  const store: Store = { putSession: vi.fn(() => Promise.resolve()), getSession: vi.fn(() => Promise.resolve(current)), deleteSession: vi.fn(() => Promise.resolve()), createJob: vi.fn(() => Promise.resolve({ id: 'job', status: 'queued' })), listJobs: vi.fn(() => Promise.resolve([])), listAssessments: vi.fn(() => Promise.resolve([])), getAssessment: vi.fn(() => Promise.resolve(null)) };
  return store;
}
const headers = { cookie: `__Host-adminsecops=${token}`, origin: config.publicUrl, 'x-adminsecops-client': 'web' };

describe('hosted HTTP boundary', () => {
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
    expect(store.createJob).toHaveBeenCalledWith(config.tenantId, config.allowedUserIds[0], expect.any(String));
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
  it('asks for reconnection when Graph credentials have expired', async () => {
    const store = fixture({ encryptedTokens: encryptTokens({ accessToken: 'expired', expiresAt: 0 }, config.tokenEncryptionKey) });
    const app = await buildServer({ config, store });
    const response = await app.inject({ method: 'POST', url: '/api/jobs', headers, payload: {} });
    expect(response.statusCode).toBe(401);
    expect(store.createJob).not.toHaveBeenCalled();
    await app.close();
  });
});
