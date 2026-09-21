import { describe, expect, it, vi } from 'vitest';
import { loadConfig } from './config.js';
import { encryptTokens } from './auth.js';
import { processNext } from './worker.js';
import { collectEntra } from './collector/index.js';
import type { PostgresStore } from './store.js';

vi.mock('./collector/index.js', () => ({ collectEntra: vi.fn(() => Promise.resolve({})) }));
vi.mock('@adminsecops/engine', () => ({ runAssessment: vi.fn(() => ({ assessmentId: 'result' })) }));
const tenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const user = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
const config = loadConfig({ PUBLIC_URL: 'https://test.example', AZURE_TENANT_ID: tenant, AZURE_CLIENT_ID: tenant, AZURE_CLIENT_SECRET: 'test-only', TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 1).toString('base64'), DATABASE_URL: 'postgresql://localhost/test', GRAPH_SCOPES: 'User.Read', OPEN_TENANT_ONBOARDING: 'true' });

describe('worker authorization', () => {
  it('refuses legacy/expired role authorization before accessing Graph', async () => {
    for (const authorizationExpiresAt of [undefined, 0]) {
      vi.mocked(collectEntra).mockClear();
      const fail = vi.fn(() => Promise.resolve());
      const store = { claim: () => Promise.resolve({ id: 'job', tenantId: tenant, userId: user, encryptedTokens: encryptTokens({ accessToken: 'secret', expiresAt: Date.now() + 600_000, authorizationExpiresAt }, config.tokenEncryptionKey) }), fail } as unknown as PostgresStore;
      expect(await processNext(store, config)).toBe(true);
      expect(fail).toHaveBeenCalled();
      expect(collectEntra).not.toHaveBeenCalled();
    }
  });
  it('collects using the authenticated job tenant after verifying authorization', async () => {
    vi.mocked(collectEntra).mockClear();
    const complete = vi.fn(() => Promise.resolve());
    const fail = vi.fn(() => Promise.resolve());
    const store = { claim: () => Promise.resolve({ id: 'job', tenantId: tenant, userId: user, encryptedTokens: encryptTokens({ accessToken: 'secret', expiresAt: Date.now() + 600_000, authorizationExpiresAt: Date.now() + 60_000 }, config.tokenEncryptionKey) }), complete, fail } as unknown as PostgresStore;
    await processNext(store, config);
    expect(collectEntra).toHaveBeenCalledWith(expect.objectContaining({ tenantId: tenant }));
    expect(complete).toHaveBeenCalled();
    expect(fail).not.toHaveBeenCalled();
  });
});
