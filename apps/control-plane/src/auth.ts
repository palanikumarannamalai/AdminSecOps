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
interface Transaction { state: string; nonce: string; verifier: string; expiresAt: number; tenantId: string; purpose?: 'login' | 'connect' }
export const randomToken = (): string => randomBytes(32).toString('base64url');
export const hashToken = (value: string): string => createHash('sha256').update(value).digest('hex');

/** Fixed labels only; never expose provider text, credentials or account identifiers. */
export function connectorFailureCode(error: unknown): string {
  const labels: Record<string, string> = {
    'Invalid connector transaction': 'TRANSACTION_INVALID',
    'The connector sign-in does not belong to this session': 'SESSION_CHANGED',
    'Identity provider rejected the token exchange': 'TOKEN_EXCHANGE_REJECTED',
    'Consent is required': 'CONSENT_REQUIRED',
    'Missing ID token': 'ID_TOKEN_MISSING',
    'Account is not permitted': 'ID_TOKEN_IDENTITY',
    'Sign in with the same account that started the assessment session': 'ACCOUNT_MISMATCH',
    'A supported directory administrator or security reader role is required': 'DIRECTORY_ROLE_MISSING',
    'The account user principal name is required for Exchange Online': 'UPN_MISSING',
    'Invalid token response': 'TOKEN_RESPONSE_INVALID',
    'The connector access token is not in the expected format': 'ACCESS_TOKEN_FORMAT',
    'The connector access token has the wrong audience': 'ACCESS_TOKEN_AUDIENCE',
    'The connector access token belongs to another tenant': 'ACCESS_TOKEN_TENANT',
    'The connector access token belongs to another user': 'ACCESS_TOKEN_USER',
    'The connector access token is not a delegated token for this connector': 'ACCESS_TOKEN_SCOPE',
    'The connector access token has expired': 'ACCESS_TOKEN_EXPIRED',
  };
  if (!(error instanceof Error)) return 'CONNECTOR_INTERNAL';
  if (Object.hasOwn(labels, error.message)) return labels[error.message]!;
  const code = (error as Error & { code?: unknown }).code;
  if (typeof code === 'string' && ['ERR_JWT_EXPIRED', 'ERR_JWT_CLAIM_VALIDATION_FAILED', 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED', 'ERR_JWKS_TIMEOUT', 'ERR_JWKS_NO_MATCHING_KEY'].includes(code)) return code;
  return 'CONNECTOR_INTERNAL';
}

/** aad binds a sealed value to its purpose (for example connector, tenant and user) so it cannot be swapped. */
function seal(value: unknown, key: string, aad?: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(key, 'base64'), iv);
  if (aad !== undefined) cipher.setAAD(Buffer.from(aad, 'utf8'));
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64url');
}
function unseal(value: string, key: string, aad?: string): unknown {
  const data = Buffer.from(value, 'base64url');
  if (data.length < 29) throw new Error('Invalid encrypted value');
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key, 'base64'), data.subarray(0, 12));
  if (aad !== undefined) decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(data.subarray(12, 28));
  return JSON.parse(Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString('utf8')) as unknown;
}

// ---------------------------------------------------------------------------------------------
// Resource connectors (Azure Resource Manager, Exchange Online)
// ---------------------------------------------------------------------------------------------

export type ConnectorId = 'azure' | 'exchange';
export const CONNECTOR_IDS: readonly ConnectorId[] = ['azure', 'exchange'];

/**
 * Delegated resource scopes of the optional connectors. Each connector has its own consent,
 * its own token (one resource per token) and its own encrypted storage; a token is only
 * accepted when its audience, tenant, user and delegated scope match the connector.
 */
export const CONNECTOR_RESOURCES: Readonly<Record<ConnectorId, { label: string; scope: string; scopeClaim: string; audiences: readonly string[] }>> = {
  azure: {
    label: 'Azure Resource Manager',
    scope: 'https://management.azure.com/user_impersonation',
    scopeClaim: 'user_impersonation',
    audiences: ['https://management.azure.com', 'https://management.azure.com/', 'https://management.core.windows.net', 'https://management.core.windows.net/'],
  },
  exchange: {
    label: 'Exchange Online',
    // Resolve the token resource explicitly from the registered Exchange permissions.
    // Dynamic Exchange.Manage consent was rejected as a Graph scope (AADSTS650053).
    // Keep Exchange.Manage as the required claim; .default is a request, not a grant.
    scope: 'https://outlook.office365.com/.default',
    scopeClaim: 'Exchange.Manage',
    audiences: ['https://outlook.office.com', 'https://outlook.office.com/', 'https://outlook.office365.com', 'https://outlook.office365.com/', '00000002-0000-0ff1-ce00-000000000000'],
  },
};

/** Tokens of one connector, bound to the tenant and user that connected it. */
export interface ConnectorTokens {
  connector: ConnectorId;
  tenantId: string;
  userId: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
  scopes?: string[];
  /** Signed-in user's UPN from the verified ID token; needed by Exchange Online PowerShell. */
  userPrincipalName?: string;
  connectedAt: number;
}

const connectorAad = (connector: ConnectorId, tenantId: string, userId: string): string => `adminsecops:connector:${connector}:${tenantId}:${userId}`;

export function encryptConnectorTokens(tokens: ConnectorTokens, key: string): string {
  return seal(tokens, key, connectorAad(tokens.connector, tokens.tenantId, tokens.userId));
}

/** Decrypts connector tokens; fails unless they were sealed for exactly this connector, tenant and user. */
export function decryptConnectorTokens(value: string, key: string, binding: { connector: ConnectorId; tenantId: string; userId: string }): ConnectorTokens {
  const tokens = unseal(value, key, connectorAad(binding.connector, binding.tenantId, binding.userId)) as ConnectorTokens;
  if (tokens.connector !== binding.connector || tokens.tenantId !== binding.tenantId || tokens.userId !== binding.userId || typeof tokens.accessToken !== 'string' || typeof tokens.expiresAt !== 'number') {
    throw new Error('Invalid connector token payload');
  }
  return tokens;
}

/** Encrypted connector tokens of a session or job, per connector (each value sealed separately). */
export type ConnectorMap = Partial<Record<ConnectorId, string>>;

export function parseConnectorMap(value: string | null | undefined): ConnectorMap {
  if (value === null || value === undefined || value === '') return {};
  try {
    const raw = JSON.parse(value) as unknown;
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return {};
    const out: ConnectorMap = {};
    for (const id of CONNECTOR_IDS) {
      const sealed = (raw as Record<string, unknown>)[id];
      if (typeof sealed === 'string' && /^[\w-]{40,65536}$/.test(sealed)) out[id] = sealed;
    }
    return out;
  } catch {
    return {};
  }
}

export function serializeConnectorMap(map: ConnectorMap): string | null {
  const entries = CONNECTOR_IDS.flatMap((id) => (map[id] !== undefined ? [[id, map[id]] as const] : []));
  return entries.length === 0 ? null : JSON.stringify(Object.fromEntries(entries));
}

/**
 * Defence in depth before a connector token is stored or used: the (unverified) access token
 * claims must name the connector's resource, the session tenant and user, and a delegated
 * scope. Access tokens are validated by the resource itself; this check only guarantees the
 * service never sends a token meant for one resource, tenant or user to another.
 */
export function checkConnectorAccessToken(accessToken: string, connector: ConnectorId, tenantId: string, userId: string, now = Date.now()): void {
  let claims: Record<string, unknown>;
  try {
    claims = decodeJwt(accessToken);
  } catch {
    throw new Error('The connector access token is not in the expected format');
  }
  const resource = CONNECTOR_RESOURCES[connector];
  if (typeof claims['aud'] !== 'string' || !resource.audiences.includes(claims['aud'])) throw new Error('The connector access token has the wrong audience');
  if (claims['tid'] !== tenantId) throw new Error('The connector access token belongs to another tenant');
  if (claims['oid'] !== userId) throw new Error('The connector access token belongs to another user');
  if (typeof claims['scp'] !== 'string' || !claims['scp'].split(' ').includes(resource.scopeClaim)) throw new Error('The connector access token is not a delegated token for this connector');
  if (typeof claims['exp'] === 'number' && claims['exp'] * 1000 <= now) throw new Error('The connector access token has expired');
}

/** The identity platform reported that consent is missing (never contains provider text). */
export class ConsentRequiredError extends Error {
  constructor() {
    super('Consent is required');
    this.name = 'ConsentRequiredError';
  }
}

interface ConnectTransaction extends Transaction { purpose: 'connect'; connector: ConnectorId; userId: string; sessionHash: string }
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
  const connectorScopes = (connector: ConnectorId): string => `${CONNECTOR_RESOURCES[connector].scope} openid profile offline_access`;
  async function exchange(tenantId: string, parameters: Record<string, string>, scope = scopes): Promise<Record<string, unknown>> {
    const authority = authorityFor(tenantId);
    const response = await fetch(`${authority}/oauth2/v2.0/token`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: config.clientId, client_secret: config.clientSecret, scope, ...parameters }),
      signal: AbortSignal.timeout(20_000),
    });
    if (!response.ok) {
      // Only the machine-readable consent signal is used; provider descriptions are never kept.
      const body = await response.json().catch(() => null) as { error?: unknown; suberror?: unknown; error_codes?: unknown } | null;
      const consent = body !== null && (body.suberror === 'consent_required' || body.error === 'consent_required' || (Array.isArray(body.error_codes) && body.error_codes.some((c) => c === 65001 || c === 65004)));
      if (consent) throw new ConsentRequiredError();
      throw new Error('Identity provider rejected the token exchange');
    }
    return await response.json() as Record<string, unknown>;
  }
  async function verifyIdToken(idToken: unknown, tenantId: string, nonce: string): Promise<Record<string, unknown>> {
    if (typeof idToken !== 'string') throw new Error('Missing ID token');
    const authority = authorityFor(tenantId);
    let keys = keySets.get(tenantId);
    if (!keys) {
      if (keySets.size >= 100) keySets.delete(keySets.keys().next().value!);
      keys = createRemoteJWKSet(new URL(`${authority}/discovery/v2.0/keys`)); keySets.set(tenantId, keys);
    }
    const { payload } = await jwtVerify(idToken, keys, { issuer: `${authority}/v2.0`, audience: config.clientId, algorithms: ['RS256'], requiredClaims: ['exp', 'iat', 'sub', 'nonce', 'tid', 'oid'] });
    if (payload.tid !== tenantId || payload.nonce !== nonce || typeof payload.oid !== 'string') throw new Error('Account is not permitted');
    return payload;
  }
  function roleGate(payload: Record<string, unknown>): void {
    const wids = payload['wids'];
    if (config.openTenantOnboarding && (!Array.isArray(wids) || !wids.some((role: unknown) => typeof role === 'string' && assessmentRoles.has(role)))) throw new Error('A supported directory administrator or security reader role is required');
  }
  function connectorTokensFrom(response: Record<string, unknown>, connector: ConnectorId, tenantId: string, userId: string, previous?: ConnectorTokens): ConnectorTokens {
    if (typeof response.access_token !== 'string' || typeof response.expires_in !== 'number' || response.expires_in <= 0) throw new Error('Invalid token response');
    checkConnectorAccessToken(response.access_token, connector, tenantId, userId);
    const granted = typeof response.scope === 'string' && response.scope.length <= 8192 ? [...new Set(response.scope.split(/\s+/).filter((s) => /^[\w:/.-]{1,200}$/.test(s)))].slice(0, 50) : previous?.scopes;
    return {
      connector, tenantId, userId,
      accessToken: response.access_token,
      ...(typeof response.refresh_token === 'string' ? { refreshToken: response.refresh_token } : previous?.refreshToken !== undefined ? { refreshToken: previous.refreshToken } : {}),
      expiresAt: Date.now() + response.expires_in * 1000,
      ...(granted !== undefined ? { scopes: granted } : {}),
      ...(previous?.userPrincipalName !== undefined ? { userPrincipalName: previous.userPrincipalName } : {}),
      connectedAt: previous?.connectedAt ?? Date.now(),
    };
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
      const transaction: Transaction = { state: randomToken(), nonce: randomToken(), verifier: randomToken(), expiresAt: Date.now() + 600_000, tenantId, purpose: 'login' };
      const url = new URL(`${authority}/oauth2/v2.0/authorize`);
      url.search = new URLSearchParams({ client_id: config.clientId, response_type: 'code', response_mode: 'query', redirect_uri: redirectUri, scope: scopes, state: transaction.state, nonce: transaction.nonce, code_challenge: createHash('sha256').update(transaction.verifier).digest('base64url'), code_challenge_method: 'S256', prompt: options.consent === true ? 'consent' : 'select_account' }).toString();
      return { url: url.toString(), cookie: seal(transaction, config.tokenEncryptionKey) };
    },
    async complete(cookie: string, state: string, code: string) {
      const transaction = unseal(cookie, config.tokenEncryptionKey) as Transaction;
      if (!state || transaction.state !== state || transaction.expiresAt < Date.now() || !transaction.nonce || !transaction.verifier || (transaction.purpose ?? 'login') !== 'login') throw new Error('Invalid authentication transaction');
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
    /** Which flow a sealed transaction cookie belongs to; undefined when it cannot be read. */
    purposeOf(cookie: string): 'login' | 'connect' | undefined {
      try {
        const transaction = unseal(cookie, config.tokenEncryptionKey) as Transaction;
        return transaction.purpose === 'connect' ? 'connect' : 'login';
      } catch { return undefined; }
    },
    /**
     * Start the separate consent/sign-in for one connector. Always the session tenant's own
     * authority (never "organizations" or "common"), with only that resource's scope.
     */
    beginConnect(connector: ConnectorId, session: { tenantId: string; userId: string; sessionHash: string }, options: { consent?: boolean } = {}) {
      if (!isTenantId(session.tenantId) || !isTenantId(session.userId)) throw new Error('Invalid session');
      const authority = authorityFor(session.tenantId);
      const transaction: ConnectTransaction = { state: randomToken(), nonce: randomToken(), verifier: randomToken(), expiresAt: Date.now() + 600_000, tenantId: session.tenantId, purpose: 'connect', connector, userId: session.userId, sessionHash: session.sessionHash };
      const url = new URL(`${authority}/oauth2/v2.0/authorize`);
      url.search = new URLSearchParams({ client_id: config.clientId, response_type: 'code', response_mode: 'query', redirect_uri: redirectUri, scope: connectorScopes(connector), state: transaction.state, nonce: transaction.nonce, code_challenge: createHash('sha256').update(transaction.verifier).digest('base64url'), code_challenge_method: 'S256', ...(options.consent === true ? { prompt: 'consent' } : {}) }).toString();
      return { url: url.toString(), cookie: seal(transaction, config.tokenEncryptionKey), connector };
    },
    /**
     * Complete a connector sign-in for the current session only: the transaction, ID token and
     * access token must all name the session's tenant and user, and the role gate applies.
     */
    async completeConnect(cookie: string, state: string, code: string, session: { tenantId: string; userId: string; sessionHash: string }): Promise<ConnectorTokens> {
      const transaction = unseal(cookie, config.tokenEncryptionKey) as Partial<ConnectTransaction>;
      if (!state || transaction.purpose !== 'connect' || transaction.state !== state || typeof transaction.expiresAt !== 'number' || transaction.expiresAt < Date.now() || !transaction.nonce || !transaction.verifier) throw new Error('Invalid connector transaction');
      const connector = transaction.connector;
      if (connector !== 'azure' && connector !== 'exchange') throw new Error('Invalid connector transaction');
      if (transaction.sessionHash !== session.sessionHash || transaction.tenantId !== session.tenantId || transaction.userId !== session.userId) throw new Error('The connector sign-in does not belong to this session');
      const response = await exchange(session.tenantId, { grant_type: 'authorization_code', code, redirect_uri: redirectUri, code_verifier: transaction.verifier }, connectorScopes(connector));
      const payload = await verifyIdToken(response.id_token, session.tenantId, transaction.nonce);
      if (payload['oid'] !== session.userId) throw new Error('Sign in with the same account that started the assessment session');
      roleGate(payload);
      const upn = payload['preferred_username'] ?? payload['upn'];
      const tokens = connectorTokensFrom(response, connector, session.tenantId, session.userId);
      if (connector === 'exchange') {
        if (typeof upn !== 'string' || !/^[^@\s]{1,128}@[A-Za-z0-9.-]{1,253}$/.test(upn)) throw new Error('The account user principal name is required for Exchange Online');
        tokens.userPrincipalName = upn;
      }
      return tokens;
    },
    /** Refresh a connector token against the session tenant; the new token is checked like the first. */
    async refreshConnector(tokens: ConnectorTokens, binding: { tenantId: string; userId: string }): Promise<ConnectorTokens> {
      if (!isTenantId(binding.tenantId) || tokens.tenantId !== binding.tenantId || tokens.userId !== binding.userId) throw new Error('Connector tokens do not belong to this session');
      if (tokens.expiresAt > Date.now() + 120_000) {
        checkConnectorAccessToken(tokens.accessToken, tokens.connector, binding.tenantId, binding.userId);
        return tokens;
      }
      if (!tokens.refreshToken) throw new Error('Reconnect the connector');
      const response = await exchange(binding.tenantId, { grant_type: 'refresh_token', refresh_token: tokens.refreshToken }, `${CONNECTOR_RESOURCES[tokens.connector].scope} offline_access`);
      return connectorTokensFrom(response, tokens.connector, binding.tenantId, binding.userId, tokens);
    },
  };
}
