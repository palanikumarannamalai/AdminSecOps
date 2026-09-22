import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { createRemoteJWKSet, decodeJwt, jwtVerify } from 'jose';
import { isApprovedUser, isTenantId, type Config } from './config.js';

/** scopes: delegated Graph scopes the identity platform reported as granted (short names), when reported. */
export interface GraphTokens { accessToken: string; refreshToken?: string; expiresAt: number; authorizationExpiresAt?: number; scopes?: string[] }
/** Parses the token response `scope` value into short Graph scope names; unknown formats are dropped. */
export function grantedScopes(value: unknown): string[] | undefined {
  if (typeof value !== 'string' || value.length > 8192) return undefined;
  const scopes = value.split(/\s+/).map(scope => scope.replace(/^https:\/\/graph\.microsoft\.com\//i, '')).filter(scope => /^[A-Za-z]+(?:\.[A-Za-z]+){1,5}$/.test(scope));
  return [...new Set(scopes)].slice(0, 100);
}
// Microsoft built-in directory role template IDs; roles must be in the verified ID token's wids.
// https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
const assessmentRoles = new Set(['62e90394-69f5-4237-9190-012177145e10', '194ae4cb-b126-40b2-bd5b-6091b380977d', 'f2ef992c-3afb-46b9-b7cf-a126ee74c451', '5d6b6bb7-de71-4623-b4af-96380a352509', 'e8611ab8-c189-46e8-94e1-60213ab1f814']);
export function hasFreshAuthorization(tokens: GraphTokens): boolean { return typeof tokens.authorizationExpiresAt === 'number' && tokens.authorizationExpiresAt > Date.now(); }
interface Transaction { state: string; nonce: string; verifier: string; expiresAt: number; tenantId: string }
export const randomToken = (): string => randomBytes(32).toString('base64url');
export const hashToken = (value: string): string => createHash('sha256').update(value).digest('hex');

function seal(value: unknown, key: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(key, 'base64'), iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64url');
}
function unseal(value: string, key: string): unknown {
  const data = Buffer.from(value, 'base64url');
  if (data.length < 29) throw new Error('Invalid encrypted value');
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key, 'base64'), data.subarray(0, 12));
  decipher.setAuthTag(data.subarray(12, 28));
  return JSON.parse(Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString('utf8')) as unknown;
}
export function encryptTokens(tokens: GraphTokens, key: string): string { return seal(tokens, key); }
export function decryptTokens(value: string, key: string): GraphTokens {
  const tokens = unseal(value, key) as GraphTokens;
  if (typeof tokens.accessToken !== 'string' || typeof tokens.expiresAt !== 'number') throw new Error('Invalid token payload');
  return tokens;
}

export function createAuth(config: Config) {
  function authorityFor(tenantId: string): string {
    if (config.openTenantOnboarding ? tenantId !== 'organizations' && !isTenantId(tenantId) : !Object.hasOwn(config.allowedTenantUsers, tenantId)) throw new Error('Tenant is not approved');
    return `https://login.microsoftonline.com/${tenantId}`;
  }
  const keySets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
  const redirectUri = `${config.publicUrl}/auth/callback`;
  const scopes = [...new Set(['openid', 'profile', 'offline_access', ...config.graphScopes])].join(' ');
  async function exchange(tenantId: string, parameters: Record<string, string>): Promise<Record<string, unknown>> {
    const authority = authorityFor(tenantId);
    const response = await fetch(`${authority}/oauth2/v2.0/token`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: config.clientId, client_secret: config.clientSecret, scope: scopes, ...parameters }),
      signal: AbortSignal.timeout(20_000),
    });
    if (!response.ok) throw new Error('Identity provider rejected the token exchange');
    return await response.json() as Record<string, unknown>;
  }
  function tokensFrom(response: Record<string, unknown>): GraphTokens {
    if (typeof response.access_token !== 'string' || typeof response.expires_in !== 'number' || response.expires_in <= 0) throw new Error('Invalid token response');
    const scopes = grantedScopes(response.scope);
    return { accessToken: response.access_token, refreshToken: typeof response.refresh_token === 'string' ? response.refresh_token : undefined, expiresAt: Date.now() + response.expires_in * 1000, ...(scopes ? { scopes } : {}) };
  }
  return {
    /** consent: show Microsoft's consent screen again (re-consent after new read-only scopes were added). */
    begin(tenantId = config.openTenantOnboarding ? 'organizations' : config.tenantId, options: { consent?: boolean } = {}) {
      const authority = authorityFor(tenantId);
      const transaction: Transaction = { state: randomToken(), nonce: randomToken(), verifier: randomToken(), expiresAt: Date.now() + 600_000, tenantId };
      const url = new URL(`${authority}/oauth2/v2.0/authorize`);
      url.search = new URLSearchParams({ client_id: config.clientId, response_type: 'code', response_mode: 'query', redirect_uri: redirectUri, scope: scopes, state: transaction.state, nonce: transaction.nonce, code_challenge: createHash('sha256').update(transaction.verifier).digest('base64url'), code_challenge_method: 'S256', prompt: options.consent === true ? 'consent' : 'select_account' }).toString();
      return { url: url.toString(), cookie: seal(transaction, config.tokenEncryptionKey) };
    },
    async complete(cookie: string, state: string, code: string) {
      const transaction = unseal(cookie, config.tokenEncryptionKey) as Transaction;
      if (!state || transaction.state !== state || transaction.expiresAt < Date.now() || !transaction.nonce || !transaction.verifier) throw new Error('Invalid authentication transaction');
      const response = await exchange(transaction.tenantId, { grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: transaction.verifier });
      if (typeof response.id_token !== 'string') throw new Error('Missing ID token');
      // Only a constrained routing candidate: no identity/authorization is trusted before jwtVerify.
      const candidate = transaction.tenantId === 'organizations' ? decodeJwt(response.id_token).tid : transaction.tenantId;
      if (!isTenantId(candidate)) throw new Error('Invalid tenant identity');
      const authority = authorityFor(candidate);
      let keys = keySets.get(candidate);
      if (!keys) {
        if (keySets.size >= 100) keySets.delete(keySets.keys().next().value!);
        keys = createRemoteJWKSet(new URL(`${authority}/discovery/v2.0/keys`)); keySets.set(candidate, keys);
      }
      const { payload } = await jwtVerify(response.id_token, keys, { issuer: `${authority}/v2.0`, audience: config.clientId, algorithms: ['RS256'], requiredClaims: ['exp', 'iat', 'sub', 'nonce', 'tid', 'oid'] });
      if (payload.tid !== candidate || payload.nonce !== transaction.nonce || typeof payload.oid !== 'string' || !isApprovedUser(config, candidate, payload.oid)) throw new Error('Account is not permitted');
      if (config.openTenantOnboarding && (!Array.isArray(payload.wids) || !payload.wids.some((role: unknown) => typeof role === 'string' && assessmentRoles.has(role)))) throw new Error('A supported directory administrator or security reader role is required');
      return { tenantId: candidate, userId: payload.oid, displayName: typeof payload.name === 'string' ? payload.name : 'Administrator', tokens: { ...tokensFrom(response), ...(config.openTenantOnboarding ? { authorizationExpiresAt: Date.now() + config.sessionTtlSeconds * 1000 } : {}) } };
    },
    async refresh(tokens: GraphTokens, tenantId: string): Promise<GraphTokens> {
      authorityFor(tenantId);
      if (!isTenantId(tenantId) || config.openTenantOnboarding && !hasFreshAuthorization(tokens)) throw new Error('Sign in again to verify administrator access');
      if (tokens.expiresAt > Date.now() + 120_000) return tokens;
      if (!tokens.refreshToken) throw new Error('Sign in again to reconnect Microsoft Graph');
      const response = await exchange(tenantId, { grant_type: 'refresh_token', refresh_token: tokens.refreshToken });
      const next = tokensFrom(response);
      return { ...next, refreshToken: next.refreshToken ?? tokens.refreshToken, authorizationExpiresAt: tokens.authorizationExpiresAt, ...((next.scopes ?? tokens.scopes) ? { scopes: next.scopes ?? tokens.scopes } : {}) };
    },
  };
}
