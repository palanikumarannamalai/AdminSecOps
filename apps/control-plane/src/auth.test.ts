import { describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createAuth, decryptTokens, encryptTokens, hashToken } from './auth.js';
import { loadConfig } from './config.js';

export const testConfig = (extra: NodeJS.ProcessEnv = {}) => loadConfig({ PUBLIC_URL: 'https://admin.example.com', AZURE_TENANT_ID: '11111111-1111-1111-1111-111111111111', AZURE_CLIENT_ID: '22222222-2222-2222-2222-222222222222', AZURE_CLIENT_SECRET: 'test-only-secret', ALLOWED_USER_IDS: '33333333-3333-3333-3333-333333333333', TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 1).toString('base64'), DATABASE_URL: 'postgresql://localhost/test', GRAPH_SCOPES: 'https://graph.microsoft.com/User.Read', ...extra });

describe('hosted authentication', () => {
  it('encrypts credentials with a different nonce and rejects modifications', () => {
    const key = testConfig().tokenEncryptionKey;
    const tokens = { accessToken: 'sensitive-token', refreshToken: 'sensitive-refresh', expiresAt: Date.now() + 60_000 };
    const sealed = encryptTokens(tokens, key);
    expect(sealed).not.toContain(tokens.accessToken);
    expect(encryptTokens(tokens, key)).not.toBe(sealed);
    expect(decryptTokens(sealed, key)).toEqual(tokens);
    const damaged = Buffer.from(sealed, 'base64url');
    damaged[20] = damaged[20]! ^ 1;
    expect(() => decryptTokens(damaged.toString('base64url'), key)).toThrow();
    expect(() => decryptTokens(sealed, Buffer.alloc(32, 2).toString('base64'))).toThrow();
    expect(hashToken('session')).toHaveLength(64);
  });
  it('creates tenant-specific PKCE requests with nonce and protected state', async () => {
    const config = testConfig();
    const auth = createAuth(config);
    const login = auth.begin();
    const url = new URL(login.url);
    expect(url.pathname).toContain(config.tenantId);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('nonce')).toBeTruthy();
    expect(url.searchParams.get('redirect_uri')).toBe(`${config.publicUrl}/auth/callback`);
    await expect(auth.complete(login.cookie, 'wrong-state', 'code')).rejects.toThrow('Invalid authentication transaction');
  });
  it('refuses insecure origins and missing allowlists', () => {
    expect(() => loadConfig({ PUBLIC_URL: 'http://example.com' })).toThrow('HTTPS');
    expect(() => loadConfig({ PUBLIC_URL: 'https://example.com', AZURE_TENANT_ID: 'x', AZURE_CLIENT_ID: 'x' })).toThrow('ALLOWED_USER_IDS');
  });
  it('verifies genuine signed OIDC tokens and rejects invalid claims and signatures', async () => {
    const config = testConfig();
    const keys = await generateKeyPair('RS256');
    const wrongKeys = await generateKeyPair('RS256');
    const publicKey = { ...await exportJWK(keys.publicKey), kid: 'test-key', alg: 'RS256', use: 'sig' };
    for (const invalid of ['none', 'nonce', 'tenant', 'issuer', 'audience', 'user', 'signature', 'expired']) {
      const auth = createAuth(config);
      const login = auth.begin();
      const url = new URL(login.url);
      const signed = await new SignJWT({ nonce: invalid === 'nonce' ? 'wrong' : url.searchParams.get('nonce'), tid: invalid === 'tenant' ? 'wrong' : config.tenantId, oid: invalid === 'user' ? 'wrong' : config.allowedUserIds[0], name: 'Admin' })
        .setProtectedHeader({ alg: 'RS256', kid: 'test-key' }).setIssuedAt().setSubject('subject')
        .setIssuer(invalid === 'issuer' ? 'https://wrong.example' : `https://login.microsoftonline.com/${config.tenantId}/v2.0`)
        .setAudience(invalid === 'audience' ? 'wrong' : config.clientId)
        .setExpirationTime(invalid === 'expired' ? 1 : '5m').sign(invalid === 'signature' ? wrongKeys.privateKey : keys.privateKey);
      vi.stubGlobal('fetch', vi.fn((input: string | URL) => Promise.resolve(new Response(JSON.stringify(String(input).includes('/discovery/') ? { keys: [publicKey] } : { id_token: signed, access_token: 'graph-access', expires_in: 3600 }), { status: 200, headers: { 'content-type': 'application/json' } }))));
      try {
        const result = auth.complete(login.cookie, url.searchParams.get('state')!, 'code');
        if (invalid === 'none') expect((await result).userId).toBe(config.allowedUserIds[0]);
        else await expect(result).rejects.toThrow();
      } finally { vi.unstubAllGlobals(); }
    }
  });
  it('routes open onboarding through organizations and accepts only verified administrative roles', async () => {
    const config = testConfig({ OPEN_TENANT_ONBOARDING: 'true' });
    const tenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    const user = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
    const keys = await generateKeyPair('RS256');
    const wrongKeys = await generateKeyPair('RS256');
    const publicKey = { ...await exportJWK(keys.publicKey), kid: 'open-key', alg: 'RS256', use: 'sig' };
    for (const invalid of ['none', 'role', 'nonce', 'issuer', 'audience', 'signature', 'tid', 'oid']) {
      const auth = createAuth(config);
      const login = auth.begin();
      const url = new URL(login.url);
      expect(url.pathname).toContain('/organizations/');
      const signed = await new SignJWT({ tid: invalid === 'tid' ? '../common' : tenant, oid: invalid === 'oid' ? 'invalid' : user, nonce: invalid === 'nonce' ? 'wrong' : url.searchParams.get('nonce'), wids: invalid === 'role' ? ['ordinary-user'] : ['62e90394-69f5-4237-9190-012177145e10'] })
        .setProtectedHeader({ alg: 'RS256', kid: 'open-key' }).setIssuedAt().setSubject('subject').setExpirationTime('5m')
        .setIssuer(`https://login.microsoftonline.com/${invalid === 'issuer' ? config.tenantId : tenant}/v2.0`)
        .setAudience(invalid === 'audience' ? 'other-app' : config.clientId).sign(invalid === 'signature' ? wrongKeys.privateKey : keys.privateKey);
      const fetched: string[] = [];
      vi.stubGlobal('fetch', vi.fn((input: string | URL) => {
        fetched.push(String(input));
        return Promise.resolve(new Response(JSON.stringify(String(input).includes('/discovery/') ? { keys: [publicKey] } : { id_token: signed, access_token: 'graph-token', expires_in: 3600 }), { status: 200, headers: { 'content-type': 'application/json' } }));
      }));
      try {
        const result = auth.complete(login.cookie, url.searchParams.get('state')!, 'code');
        if (invalid === 'none') {
          const identity = await result;
          expect(identity).toMatchObject({ tenantId: tenant, userId: user });
          expect(identity.tokens.authorizationExpiresAt).toBeGreaterThan(Date.now());
          expect(fetched).toContain(`https://login.microsoftonline.com/${tenant}/discovery/v2.0/keys`);
        } else await expect(result).rejects.toThrow();
        expect(fetched[0]).toBe('https://login.microsoftonline.com/organizations/oauth2/v2.0/token');
      } finally { vi.unstubAllGlobals(); }
    }
  });
  it('refreshes only against the session tenant and never extends role authorization', async () => {
    const config = testConfig({ OPEN_TENANT_ONBOARDING: 'true' });
    const tenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    const authorizationExpiresAt = Date.now() + 60_000;
    const auth = createAuth(config);
    const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify({ access_token: 'new-token', expires_in: 3600 }))));
    vi.stubGlobal('fetch', fetchMock);
    try {
      const result = await auth.refresh({ accessToken: 'old', refreshToken: 'refresh', expiresAt: 0, authorizationExpiresAt }, tenant);
      expect(fetchMock).toHaveBeenCalledWith(`https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`, expect.any(Object));
      expect(result.authorizationExpiresAt).toBe(authorizationExpiresAt);
      await expect(auth.refresh({ accessToken: 'old', expiresAt: Date.now() + 600_000 }, tenant)).rejects.toThrow('administrator');
      await expect(auth.refresh({ accessToken: 'old', expiresAt: 0, authorizationExpiresAt }, 'organizations')).rejects.toThrow('administrator');
    } finally { vi.unstubAllGlobals(); }
  });
  it('treats the tenant map as authoritative with strict UUID pairs', () => {
    const tenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    const user = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
    const config = testConfig({ ALLOWED_TENANT_USERS: JSON.stringify({ [tenant]: [user] }) });
    expect(config.allowedUserIds).toEqual([]);
    expect(createAuth(config).begin(tenant).url).toContain(tenant);
    expect(() => createAuth(config).begin()).toThrow('not approved');
    expect(() => testConfig({ ALLOWED_TENANT_USERS: JSON.stringify({ [tenant]: [] }) })).toThrow();
    expect(() => testConfig({ OPEN_TENANT_ONBOARDING: 'true', ALLOWED_TENANT_USERS: JSON.stringify({ [tenant]: [user] }) })).toThrow('combined');
    expect(() => testConfig({ GRAPH_SCOPES: 'Directory.ReadWrite.All' })).toThrow('read-only');
    expect(() => testConfig({ GRAPH_SCOPES: 'https://attacker.example/User.Read' })).toThrow('read-only');
    expect(() => testConfig({ GRAPH_SCOPES: 'https://graph.microsoft.com/Directory.Read.All User.Read' })).not.toThrow();
  });
});
