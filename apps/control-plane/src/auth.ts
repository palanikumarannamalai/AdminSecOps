import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { Config } from './config.js';

export interface GraphTokens { accessToken: string; refreshToken?: string; expiresAt: number }
interface Transaction { state: string; nonce: string; verifier: string; expiresAt: number }
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
  const authority = `https://login.microsoftonline.com/${config.tenantId}`;
  const keys = createRemoteJWKSet(new URL(`${authority}/discovery/v2.0/keys`));
  const redirectUri = `${config.publicUrl}/auth/callback`;
  const scopes = [...new Set(['openid', 'profile', 'offline_access', ...config.graphScopes])].join(' ');
  async function exchange(parameters: Record<string, string>): Promise<Record<string, unknown>> {
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
    return { accessToken: response.access_token, refreshToken: typeof response.refresh_token === 'string' ? response.refresh_token : undefined, expiresAt: Date.now() + response.expires_in * 1000 };
  }
  return {
    begin() {
      const transaction: Transaction = { state: randomToken(), nonce: randomToken(), verifier: randomToken(), expiresAt: Date.now() + 600_000 };
      const url = new URL(`${authority}/oauth2/v2.0/authorize`);
      url.search = new URLSearchParams({ client_id: config.clientId, response_type: 'code', response_mode: 'query', redirect_uri: redirectUri, scope: scopes, state: transaction.state, nonce: transaction.nonce, code_challenge: createHash('sha256').update(transaction.verifier).digest('base64url'), code_challenge_method: 'S256', prompt: 'select_account' }).toString();
      return { url: url.toString(), cookie: seal(transaction, config.tokenEncryptionKey) };
    },
    async complete(cookie: string, state: string, code: string) {
      const transaction = unseal(cookie, config.tokenEncryptionKey) as Transaction;
      if (!state || transaction.state !== state || transaction.expiresAt < Date.now() || !transaction.nonce || !transaction.verifier) throw new Error('Invalid authentication transaction');
      const response = await exchange({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: transaction.verifier });
      if (typeof response.id_token !== 'string') throw new Error('Missing ID token');
      const { payload } = await jwtVerify(response.id_token, keys, { issuer: `${authority}/v2.0`, audience: config.clientId, algorithms: ['RS256'], requiredClaims: ['exp', 'iat', 'sub', 'nonce', 'tid', 'oid'] });
      if (payload.tid !== config.tenantId || payload.nonce !== transaction.nonce || typeof payload.oid !== 'string' || !config.allowedUserIds.includes(payload.oid)) throw new Error('Account is not permitted');
      return { tenantId: config.tenantId, userId: payload.oid, displayName: typeof payload.name === 'string' ? payload.name : 'Administrator', tokens: tokensFrom(response) };
    },
    async refresh(tokens: GraphTokens): Promise<GraphTokens> {
      if (tokens.expiresAt > Date.now() + 120_000) return tokens;
      if (!tokens.refreshToken) throw new Error('Sign in again to reconnect Microsoft Graph');
      const response = await exchange({ grant_type: 'refresh_token', refresh_token: tokens.refreshToken });
      const next = tokensFrom(response);
      return { ...next, refreshToken: next.refreshToken ?? tokens.refreshToken };
    },
  };
}
