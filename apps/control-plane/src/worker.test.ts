import { describe, expect, it, vi } from 'vitest';
import { UnsecuredJWT } from 'jose';
import { loadConfig } from './config.js';
import { encryptConnectorTokens, encryptTokens } from './auth.js';
import { processNext } from './worker.js';
import { collectOnline } from './collector/index.js';
import { runAssessment } from '@adminsecops/engine';
import type { PostgresStore } from './store.js';

vi.mock('./collector/index.js', () => ({ collectOnline: vi.fn(() => Promise.resolve({})) }));
vi.mock('@adminsecops/engine', () => ({ runAssessment: vi.fn(() => ({ assessmentId: 'result' })) }));
const tenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const user = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const config = loadConfig({ PUBLIC_URL: 'https://test.example', AZURE_TENANT_ID: tenant, AZURE_CLIENT_ID: tenant, AZURE_CLIENT_SECRET: 'test-only', TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 1).toString('base64'), DATABASE_URL: 'postgresql://localhost/test', GRAPH_SCOPES: 'User.Read', OPEN_TENANT_ONBOARDING: 'true' });

describe('worker authorization', () => {
  it('refuses legacy/expired role authorization before accessing Graph', async () => {
    for (const authorizationExpiresAt of [undefined, 0]) {
      vi.mocked(collectOnline).mockClear();
      const fail = vi.fn(() => Promise.resolve());
      const store = { claim: () => Promise.resolve({ id: 'job', tenantId: tenant, userId: user, encryptedTokens: encryptTokens({ accessToken: 'secret', expiresAt: Date.now() + 600_000, authorizationExpiresAt }, config.tokenEncryptionKey) }), fail } as unknown as PostgresStore;
      expect(await processNext(store, config)).toBe(true);
      expect(fail).toHaveBeenCalled();
      expect(collectOnline).not.toHaveBeenCalled();
    }
  });
  it('passes each connector to the collector only when it is enabled, bound to the job user and usable', async () => {
    const armToken = new UnsecuredJWT({ aud: 'https://management.azure.com', tid: tenant, oid: user, scp: 'user_impersonation' }).setExpirationTime('1h').encode();
    const sealed = (userId: string) => encryptConnectorTokens({ connector: 'azure', tenantId: tenant, userId, accessToken: armToken, refreshToken: 'r', expiresAt: Date.now() + 600_000, connectedAt: 1 }, config.tokenEncryptionKey);
    const graph = encryptTokens({ accessToken: 'secret', expiresAt: Date.now() + 600_000, authorizationExpiresAt: Date.now() + 60_000 }, config.tokenEncryptionKey);
    const cases: [typeof config, string | null, Record<string, unknown>][] = [
      [{ ...config, connectors: { azure: true, exchange: false } }, JSON.stringify({ azure: sealed(user) }), { state: 'connected', accessToken: armToken }],
      [{ ...config, connectors: { azure: true, exchange: false } }, JSON.stringify({ azure: sealed('cccccccc-cccc-cccc-cccc-cccccccccccc') }), { state: 'not-connected' }],
      [{ ...config, connectors: { azure: true, exchange: false } }, JSON.stringify({ gaps: { azure: 'consent-required' } }), { state: 'consent-required' }],
      [{ ...config, connectors: { azure: true, exchange: false } }, null, { state: 'not-connected' }],
      [config, JSON.stringify({ azure: sealed(user) }), { state: 'unavailable' }],
    ];
    for (const [cfg, encryptedConnectors, expected] of cases) {
      vi.mocked(collectOnline).mockClear();
      const store = { claim: () => Promise.resolve({ id: 'job', tenantId: tenant, userId: user, encryptedTokens: graph, encryptedConnectors }), complete: vi.fn(() => Promise.resolve()), fail: vi.fn(() => Promise.resolve()) } as unknown as PostgresStore;
      await processNext(store, cfg);
      const call = vi.mocked(collectOnline).mock.calls[0]?.[0];
      expect(call?.azure, JSON.stringify(expected)).toMatchObject(expected);
      expect(call?.exchange).toMatchObject({ state: 'unavailable' });
      expect(call?.accessToken).toBe('secret');
    }
  });

  it('collects using the authenticated job tenant after verifying authorization', async () => {
    vi.mocked(collectOnline).mockClear();
    const complete = vi.fn(() => Promise.resolve());
    const fail = vi.fn(() => Promise.resolve());
    const store = { claim: () => Promise.resolve({ id: 'job', tenantId: tenant, userId: user, encryptedTokens: encryptTokens({ accessToken: 'secret', expiresAt: Date.now() + 600_000, authorizationExpiresAt: Date.now() + 60_000, scopes: ['Policy.Read.All'] }, config.tokenEncryptionKey) }), complete, fail } as unknown as PostgresStore;
    await processNext(store, config);
    expect(collectOnline).toHaveBeenCalledWith(expect.objectContaining({ tenantId: tenant, grantedScopes: ['Policy.Read.All'] }));
    expect(complete).toHaveBeenCalled();
    expect(fail).not.toHaveBeenCalled();
  });

  const fresh = () => encryptTokens({ accessToken: 'secret', expiresAt: Date.now() + 600_000, authorizationExpiresAt: Date.now() + 60_000 }, config.tokenEncryptionKey);
  it('completes the assessment when the usage write fails', async () => {
    vi.mocked(runAssessment).mockReturnValueOnce({ assessmentId: 'result', summary: { controlsEvaluated: 3 }, evidence: { datasets: [{ datasetId: 'entra.users', module: 'Entra', state: 'available' }] } } as never);
    const recordUsage = vi.fn(() => Promise.reject(new Error('database down')));
    const complete = vi.fn(() => Promise.resolve());
    const fail = vi.fn(() => Promise.resolve(true));
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const store = { claim: () => Promise.resolve({ id: 'job', tenantId: tenant, userId: user, encryptedTokens: fresh() }), complete, fail, recordUsage } as unknown as PostgresStore;
    expect(await processNext(store, config)).toBe(true);
    await vi.waitFor(() => expect(error).toHaveBeenCalledWith('Usage counter update failed.'));
    expect(recordUsage).toHaveBeenCalledWith({ assessments_completed: 1, controls_evaluated: 3, collector_entra: 1 }, null);
    expect(complete).toHaveBeenCalled();
    expect(fail).not.toHaveBeenCalled();
    expect(error.mock.calls.flat().join(' ')).not.toContain(tenant);
    error.mockRestore();
  });

  it('counts failures by a fixed code and never the error text', async () => {
    const cases: [typeof config, string, () => void, string][] = [
      [{ ...config, openTenantOnboarding: false, allowedTenantUsers: {} }, fresh(), () => undefined, 'failed_NOT_APPROVED'],
      [config, encryptTokens({ accessToken: 'secret', expiresAt: Date.now() + 600_000, authorizationExpiresAt: 0 }, config.tokenEncryptionKey), () => undefined, 'failed_CONSENT_OR_TOKEN'],
      [config, fresh(), () => { vi.mocked(collectOnline).mockRejectedValueOnce(new Error('Graph returned PRIVATE-DETAIL')); }, 'failed_COLLECTION_FAILED'],
      [config, fresh(), () => { vi.mocked(collectOnline).mockRejectedValueOnce(Object.assign(new Error('cancelled'), { name: 'CollectionCancelledError' })); }, 'failed_TIMEOUT'],
    ];
    for (const [cfg, encryptedTokens, arrange, counter] of cases) {
      arrange();
      const recordUsage = vi.fn(() => Promise.resolve());
      const store = { claim: () => Promise.resolve({ id: 'job', tenantId: tenant, userId: user, encryptedTokens }), complete: vi.fn(() => Promise.resolve()), fail: vi.fn(() => Promise.resolve(true)), recordUsage } as unknown as PostgresStore;
      await processNext(store, cfg);
      await vi.waitFor(() => expect(recordUsage).toHaveBeenCalledWith({ assessments_failed: 1, [counter]: 1 }, null));
      expect(JSON.stringify(recordUsage.mock.calls)).not.toContain('PRIVATE-DETAIL');
    }
    // A job that cleanup already failed is not counted twice.
    const recordUsage = vi.fn(() => Promise.resolve());
    await processNext({ claim: () => Promise.resolve({ id: 'job', tenantId: tenant, userId: user, encryptedTokens: 'x' }), fail: vi.fn(() => Promise.resolve(false)), recordUsage } as unknown as PostgresStore, config);
    expect(recordUsage).not.toHaveBeenCalled();
  });
});
