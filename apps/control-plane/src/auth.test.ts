import { describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, UnsecuredJWT } from 'jose';
import { checkConnectorAccessToken, ConsentRequiredError, createAuth, decryptConnectorTokens, decryptTokens, encryptConnectorTokens, encryptTokens, grantedScopes, hashToken, parseConnectorMap, serializeConnectorMap, type ConnectorTokens } from './auth.js';
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
  it('accepts the read-only workload scopes and still rejects write scopes', () => {
    expect(() => testConfig({ GRAPH_SCOPES: 'DeviceManagementConfiguration.Read.All DeviceManagementManagedDevices.Read.All SharePointTenantSettings.Read.All TeamworkAppSettings.Read.All Team.ReadBasic.All' })).not.toThrow();
    for (const scope of ['DeviceManagementConfiguration.ReadWrite.All', 'SharePointTenantSettings.ReadWrite.All', 'TeamSettings.ReadWrite.All', 'TeamworkAppSettings.ReadWrite.All', 'Sites.FullControl.All']) {
      expect(() => testConfig({ GRAPH_SCOPES: scope })).toThrow('read-only');
    }
  });
  it('records only well-formed granted scopes from the token response', () => {
    expect(grantedScopes('openid profile https://graph.microsoft.com/Policy.Read.All Team.ReadBasic.All bad/scope')).toEqual(['Policy.Read.All', 'Team.ReadBasic.All']);
    expect(grantedScopes(undefined)).toBeUndefined();
    expect(grantedScopes(42)).toBeUndefined();
  });
});

describe('resource connector authentication', () => {
  const tenant = '11111111-1111-1111-1111-111111111111';
  const user = '33333333-3333-3333-3333-333333333333';
  const other = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
  const armToken = (claims: Record<string, unknown> = {}) =>
    new UnsecuredJWT({ aud: 'https://management.azure.com', tid: tenant, oid: user, scp: 'user_impersonation', ...claims }).setExpirationTime('1h').encode();
  const exoToken = () => new UnsecuredJWT({ aud: 'https://outlook.office365.com', tid: tenant, oid: user, scp: 'Exchange.Manage' }).setExpirationTime('1h').encode();
  const tokens = (overrides: Partial<ConnectorTokens> = {}): ConnectorTokens => ({ connector: 'azure', tenantId: tenant, userId: user, accessToken: armToken(), refreshToken: 'arm-refresh', expiresAt: Date.now() + 600_000, connectedAt: 1, ...overrides });
  const jsonResponse = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

  it('seals connector tokens separately and binds them to connector, tenant and user', () => {
    const key = testConfig().tokenEncryptionKey;
    const sealed = encryptConnectorTokens(tokens(), key);
    expect(sealed).not.toContain('arm-refresh');
    expect(decryptConnectorTokens(sealed, key, { connector: 'azure', tenantId: tenant, userId: user }).refreshToken).toBe('arm-refresh');
    for (const binding of [{ connector: 'exchange' as const, tenantId: tenant, userId: user }, { connector: 'azure' as const, tenantId: other, userId: user }, { connector: 'azure' as const, tenantId: tenant, userId: other }]) {
      expect(() => decryptConnectorTokens(sealed, key, binding)).toThrow();
    }
    // A connector blob is not a Graph token blob, and the reverse.
    expect(() => decryptTokens(sealed, key)).toThrow();
    expect(() => decryptConnectorTokens(encryptTokens({ accessToken: 'graph', expiresAt: 1 }, key), key, { connector: 'azure', tenantId: tenant, userId: user })).toThrow();
    const map = serializeConnectorMap({ azure: sealed });
    expect(parseConnectorMap(map)).toEqual({ azure: sealed });
    expect(parseConnectorMap(JSON.stringify({ azure: 'x', other: sealed }))).toEqual({});
    expect(parseConnectorMap('not json')).toEqual({});
  });

  it('accepts only delegated tokens for the connector resource, tenant and user', () => {
    expect(() => checkConnectorAccessToken(armToken(), 'azure', tenant, user)).not.toThrow();
    expect(() => checkConnectorAccessToken(armToken({ aud: 'https://management.core.windows.net/' }), 'azure', tenant, user)).not.toThrow();
    const cases: [string, string][] = [
      [armToken({ aud: 'https://graph.microsoft.com' }), 'audience'],
      [armToken({ aud: '00000002-0000-0ff1-ce00-000000000000' }), 'audience'],
      [armToken({ tid: other }), 'tenant'],
      [armToken({ oid: other }), 'user'],
      [armToken({ scp: undefined, roles: ['Reader'] }), 'delegated'],
      [new UnsecuredJWT({ aud: 'https://management.azure.com', tid: tenant, oid: user, scp: 'user_impersonation', exp: 1 }).encode(), 'expired'],
      ['opaque-token', 'format'],
    ];
    for (const [token, reason] of cases) expect(() => checkConnectorAccessToken(token, 'azure', tenant, user), reason).toThrow(reason);
    // An Exchange token is not accepted as an ARM token.
    expect(() => checkConnectorAccessToken(exoToken(), 'exchange', tenant, user)).not.toThrow();
    expect(() => checkConnectorAccessToken(armToken({ aud: 'https://outlook.office.com', scp: 'Exchange.Manage' }), 'exchange', tenant, user)).not.toThrow();
    expect(() => checkConnectorAccessToken(armToken({ aud: 'https://graph.microsoft.com', scp: 'Exchange.Manage' }), 'exchange', tenant, user)).toThrow('audience');
    expect(() => checkConnectorAccessToken(exoToken(), 'azure', tenant, user)).toThrow('audience');
  });

  it('starts connector consent at the session tenant with only that resource scope', () => {
    for (const config of [testConfig(), testConfig({ OPEN_TENANT_ONBOARDING: 'true' })]) {
      const auth = createAuth(config);
      const begin = auth.beginConnect('azure', { tenantId: tenant, userId: user, sessionHash: 'h' });
      const url = new URL(begin.url);
      expect(url.pathname).toBe(`/${tenant}/oauth2/v2.0/authorize`);
      expect(url.searchParams.get('scope')).toBe('https://management.azure.com/user_impersonation openid profile offline_access');
      expect(url.searchParams.get('prompt')).toBeNull();
      expect(new URL(auth.beginConnect('exchange', { tenantId: tenant, userId: user, sessionHash: 'h' }).url).searchParams.get('scope')).toBe('https://outlook.office.com/Exchange.Manage openid profile offline_access');
      expect(url.searchParams.get('code_challenge_method')).toBe('S256');
      expect(auth.purposeOf(begin.cookie)).toBe('connect');
      expect(new URL(auth.beginConnect('exchange', { tenantId: tenant, userId: user, sessionHash: 'h' }, { consent: true }).url).searchParams.get('prompt')).toBe('consent');
      expect(() => auth.beginConnect('azure', { tenantId: 'organizations', userId: user, sessionHash: 'h' })).toThrow();
    }
  });

  it('completes a connection only for the session that started it, with a verified ID token and a matching access token', async () => {
    const config = testConfig();
    const keys = await generateKeyPair('RS256');
    const publicKey = { ...await exportJWK(keys.publicKey), kid: 'k', alg: 'RS256', use: 'sig' };
    const session = { tenantId: tenant, userId: user, sessionHash: 'session-hash' };
    for (const invalid of ['none', 'session', 'oid', 'audience', 'login-transaction', 'exchange-upn']) {
      const auth = createAuth(config);
      const connector = invalid === 'exchange-upn' ? 'exchange' : 'azure';
      const begin = invalid === 'login-transaction' ? auth.begin() : auth.beginConnect(connector, session);
      const url = new URL(begin.url);
      const idToken = await new SignJWT({ nonce: url.searchParams.get('nonce'), tid: tenant, oid: invalid === 'oid' ? other : user, ...(invalid === 'exchange-upn' ? {} : { preferred_username: 'admin@contoso.example' }) })
        .setProtectedHeader({ alg: 'RS256', kid: 'k' }).setIssuedAt().setSubject('s').setIssuer(`https://login.microsoftonline.com/${tenant}/v2.0`).setAudience(config.clientId).setExpirationTime('5m').sign(keys.privateKey);
      const access = invalid === 'audience' ? armToken({ aud: 'https://graph.microsoft.com' }) : connector === 'exchange' ? exoToken() : armToken();
      const requests: { url: string; body: string }[] = [];
      vi.stubGlobal('fetch', vi.fn((input: string | URL, init?: RequestInit) => {
        requests.push({ url: String(input), body: init?.body instanceof URLSearchParams ? init.body.toString() : '' });
        return Promise.resolve(jsonResponse(String(input).includes('/discovery/') ? { keys: [publicKey] } : { id_token: idToken, access_token: access, refresh_token: 'r', expires_in: 3600, scope: 'https://management.azure.com/user_impersonation' }));
      }));
      try {
        const result = auth.completeConnect(begin.cookie, url.searchParams.get('state')!, 'code', invalid === 'session' ? { ...session, sessionHash: 'other-session' } : session);
        if (invalid === 'none') {
          const connected = await result;
          expect(connected).toMatchObject({ connector: 'azure', tenantId: tenant, userId: user, refreshToken: 'r' });
          expect(requests[0]?.url).toBe(`https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`);
          expect(new URLSearchParams(requests[0]?.body).get('scope')).toBe('https://management.azure.com/user_impersonation openid profile offline_access');
        } else await expect(result, invalid).rejects.toThrow();
      } finally { vi.unstubAllGlobals(); }
    }
    // A connector transaction can never complete a normal sign-in.
    const auth = createAuth(config);
    const begin = auth.beginConnect('azure', session);
    await expect(auth.complete(begin.cookie, new URL(begin.url).searchParams.get('state')!, 'code')).rejects.toThrow('Invalid authentication transaction');
  });

  it('refreshes connector tokens against the session tenant, re-checks them and reports missing consent', async () => {
    const auth = createAuth(testConfig());
    const fresh = tokens();
    expect(await auth.refreshConnector(fresh, { tenantId: tenant, userId: user })).toBe(fresh);
    await expect(auth.refreshConnector(fresh, { tenantId: other, userId: user })).rejects.toThrow();
    await expect(auth.refreshConnector(tokens({ refreshToken: undefined, expiresAt: 0 }), { tenantId: tenant, userId: user })).rejects.toThrow('Reconnect');

    const calls: { url: string; body: string }[] = [];
    vi.stubGlobal('fetch', vi.fn((input: string | URL, init?: RequestInit) => {
      calls.push({ url: String(input), body: init?.body instanceof URLSearchParams ? init.body.toString() : '' });
      return Promise.resolve(jsonResponse({ access_token: armToken(), expires_in: 3600 }));
    }));
    try {
      const next = await auth.refreshConnector(tokens({ expiresAt: 0 }), { tenantId: tenant, userId: user });
      expect(next.refreshToken).toBe('arm-refresh');
      expect(calls[0]?.url).toBe(`https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`);
      expect(new URLSearchParams(calls[0]?.body).get('scope')).toBe('https://management.azure.com/user_impersonation offline_access');
    } finally { vi.unstubAllGlobals(); }

    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(jsonResponse({ access_token: armToken({ tid: other }), expires_in: 3600 }))));
    try { await expect(auth.refreshConnector(tokens({ expiresAt: 0 }), { tenantId: tenant, userId: user })).rejects.toThrow('tenant'); }
    finally { vi.unstubAllGlobals(); }

    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(jsonResponse({ error: 'invalid_grant', suberror: 'consent_required', error_description: 'PRIVATE-DETAIL', error_codes: [65001] }, 400))));
    try { await expect(auth.refreshConnector(tokens({ expiresAt: 0 }), { tenantId: tenant, userId: user })).rejects.toBeInstanceOf(ConsentRequiredError); }
    finally { vi.unstubAllGlobals(); }
  });

  it('validates the connector deployment configuration', () => {
    expect(testConfig().connectors).toEqual({ azure: false, exchange: false });
    expect(testConfig({ ONLINE_CONNECTORS: 'azure' }).connectors).toEqual({ azure: true, exchange: false });
    expect(() => testConfig({ ONLINE_CONNECTORS: 'azure shell' })).toThrow('ONLINE_CONNECTORS');
    expect(() => testConfig({ ONLINE_CONNECTORS: 'exchange' })).toThrow('EXCHANGE_PWSH_PATH');
    expect(() => testConfig({ ONLINE_CONNECTORS: 'exchange', EXCHANGE_PWSH_PATH: 'pwsh' })).toThrow('absolute');
    expect(() => testConfig({ ONLINE_CONNECTORS: 'exchange', EXCHANGE_PWSH_PATH: '/usr/bin/pwsh; rm -rf /' })).toThrow('absolute');
    expect(testConfig({ ONLINE_CONNECTORS: 'azure,exchange', EXCHANGE_PWSH_PATH: '/opt/microsoft/powershell/7/pwsh' }).exchangePwshPath).toBe('/opt/microsoft/powershell/7/pwsh');
    expect(() => testConfig({ GRAPH_SCOPES: 'OnPremDirectorySynchronization.Read.All' })).not.toThrow();
    expect(() => testConfig({ GRAPH_SCOPES: 'OnPremDirectorySynchronization.ReadWrite.All' })).toThrow('read-only');
  });
});
