import Fastify, { type FastifyRequest } from 'fastify';
import { CONTROL_LIBRARY, CONTROL_LIBRARY_VERSION } from '@adminsecops/controls';
import { compareAssessments } from '@adminsecops/engine';
import { listDatasetDefinitions } from '@adminsecops/schemas';
import { buildJsonReport, renderHtmlReport, serializeJsonReport } from '@adminsecops/reporting';
import { isApprovedUser, isTenantId, type Config } from './config.js';
import { CONNECTOR_IDS, connectorFailureCode, createAuth, decryptTokens, encryptConnectorTokens, encryptTokens, hasFreshAuthorization, hashToken, parseConnectorMap, randomToken, serializeConnectorMap, type ConnectorId } from './auth.js';
import { ONLINE_REQUIRED_GRAPH_PERMISSIONS, type ExchangeRunner } from './collector/index.js';
import { connectorLabel, describeConnectors, prepareJobConnectors } from './connectors.js';
import type { Store, StoredSession } from './store.js';

const sessionName = '__Host-adminsecops';
const transactionName = '__Host-adminsecops-login';
function cookie(name: string, value: string, ttl: number): string {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${ttl}`;
}
function readCookie(request: FastifyRequest, name: string): string | undefined {
  return request.headers.cookie?.split(';').map(part => part.trim()).find(part => part.startsWith(`${name}=`))?.slice(name.length + 1);
}
function failure(statusCode: number, message: string): Error & { statusCode: number } {
  return Object.assign(new Error(message), { statusCode });
}

/** Expose only a bounded Microsoft error identifier, never its raw description or tokens. */
function connectorSignInError(error: unknown, description: unknown): string {
  const aadsts = typeof description === 'string' && description.length <= 8192
    ? /\bAADSTS[0-9]{4,9}\b/.exec(description)?.[0] : undefined;
  const knownErrors = ['access_denied', 'consent_required', 'interaction_required', 'login_required', 'invalid_scope', 'invalid_resource', 'invalid_client', 'unauthorized_client', 'server_error', 'temporarily_unavailable'];
  const oauth = typeof error === 'string' && knownErrors.includes(error) ? error : undefined;
  const reference = [aadsts, oauth].filter(Boolean).join(', ');
  const reason = oauth === 'invalid_scope' || oauth === 'invalid_resource' || oauth === 'invalid_client' || oauth === 'unauthorized_client'
    ? 'The connector authorization request was rejected. Share this error identifier with the ConfigReview maintainer.'
    : 'Return to the home page and try Reconnect; an administrator may need to grant consent. If it fails again, share this error identifier with the ConfigReview maintainer.';
  return `Microsoft sign-in or consent for the connector was not completed${reference ? ` (${reference})` : ''}. ${reason}`;
}

const isConnectorId = (value: unknown): value is ConnectorId => typeof value === 'string' && (CONNECTOR_IDS as readonly string[]).includes(value);

export async function buildServer({ config, store, exchangeRunner }: { config: Config; store: Store; exchangeRunner?: ExchangeRunner }) {
  const app = Fastify({ logger: false, bodyLimit: 16_384, trustProxy: false });
  const auth = createAuth(config);
  const sessions = new WeakMap<FastifyRequest, StoredSession>();
  const attempts = new Map<string, { count: number; until: number }>();
  function throttle(key: string, limit: number) {
    const now = Date.now();
    for (const [entry, value] of attempts) if (value.until <= now) attempts.delete(entry);
    const previous = attempts.get(key);
    if (previous && previous.count >= limit || !previous && attempts.size >= 10_000) throw failure(429, 'Too many requests. Please wait a minute and try again.');
    attempts.set(key, { count: (previous?.count ?? 0) + 1, until: previous?.until ?? now + 60_000 });
  }
  function session(request: FastifyRequest): StoredSession {
    const result = sessions.get(request);
    if (!result) throw failure(401, 'Sign in required');
    return result;
  }
  app.setErrorHandler((error, _request, reply) => {
    const status = (error as { statusCode?: number }).statusCode ?? 500;
    return reply.code(status).send({ error: { code: status === 401 ? 'UNAUTHENTICATED' : status === 403 ? 'FORBIDDEN' : status === 404 ? 'NOT_FOUND' : 'REQUEST_FAILED', message: status < 500 ? (error as Error).message : 'The request could not be completed.' } });
  });
  app.addHook('onRequest', async (request, reply) => {
    reply.header('Cache-Control', 'no-store').header('X-Content-Type-Options', 'nosniff').header('Referrer-Policy', 'no-referrer').header('X-Frame-Options', 'DENY').header('Strict-Transport-Security', 'max-age=31536000');
    const route = request.url.split('?')[0] ?? '';
    if (route === '/api/health' || !route.startsWith('/api/') && route !== '/auth/logout' && !route.startsWith('/auth/connect/')) return;
    const token = readCookie(request, sessionName);
    if (!token || !/^[\w-]{43}$/.test(token)) throw failure(401, 'Sign in required');
    const current = await store.getSession(hashToken(token));
    if (!current || current.expiresAt.getTime() <= Date.now() || !isApprovedUser(config, current.tenantId, current.userId)) throw failure(401, 'Sign in required');
    if (config.openTenantOnboarding) {
      try { if (!hasFreshAuthorization(decryptTokens(current.encryptedTokens, config.tokenEncryptionKey))) throw new Error('Expired'); }
      catch { throw failure(401, 'Sign in again to verify administrator access'); }
    }
    sessions.set(request, current);
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method) && (request.headers.origin !== config.publicUrl || request.headers['x-adminsecops-client'] !== 'web')) throw failure(403, 'Invalid request origin');
  });
  app.get('/api/health', () => ({ status: 'ok' }));
  app.get<{ Querystring: { tenantId?: string; consent?: string } }>('/auth/login', async (request, reply) => {
    throttle(`login:${request.ip}`, 30);
    const requestedTenant = request.query.tenantId ?? (config.openTenantOnboarding ? 'organizations' : config.tenantId);
    if (typeof requestedTenant !== 'string' || (config.openTenantOnboarding ? requestedTenant !== 'organizations' && !isTenantId(requestedTenant.toLowerCase()) : !Object.hasOwn(config.allowedTenantUsers, requestedTenant.toLowerCase()))) throw failure(403, 'This tenant is not approved for access.');
    // Re-consent path: only the literal value "true" is accepted; the same role gate applies at the callback.
    if (request.query.consent !== undefined && request.query.consent !== 'true') throw failure(400, 'Invalid sign-in request');
    const login = auth.begin(requestedTenant.toLowerCase(), { consent: request.query.consent === 'true' });
    return reply.header('Set-Cookie', cookie(transactionName, login.cookie, 600)).redirect(login.url);
  });
  // Separate consent and sign-in for one optional connector, for the current session's tenant and user only.
  app.get<{ Params: { connector: string }; Querystring: { consent?: string } }>('/auth/connect/:connector', async (request, reply) => {
    const current = session(request);
    // Connecting must be an explicit action in this app (or a typed URL), never started by another site.
    const site = request.headers['sec-fetch-site'];
    if (site !== undefined && site !== 'same-origin' && site !== 'none') throw failure(403, 'Start the connection from the ConfigReview home page.');
    throttle(`connect:${current.tenantId}:${current.userId}`, 10);
    if (!isConnectorId(request.params.connector)) throw failure(404, 'Unknown connector');
    const connector = request.params.connector;
    if (!config.connectors[connector]) throw failure(404, `The ${connectorLabel(connector)} connector is not enabled on this deployment.`);
    if (request.query.consent !== undefined && request.query.consent !== 'true') throw failure(400, 'Invalid connection request');
    const login = auth.beginConnect(connector, { tenantId: current.tenantId, userId: current.userId, sessionHash: current.idHash }, { consent: request.query.consent === 'true' });
    return reply.header('Set-Cookie', cookie(transactionName, login.cookie, 600)).redirect(login.url);
  });
  app.get<{ Querystring: { state?: string; code?: string; error?: string; error_description?: string } }>('/auth/callback', async (request, reply) => {
    reply.header('Set-Cookie', cookie(transactionName, '', 0));
    const transaction = readCookie(request, transactionName);
    if (request.query.error !== undefined) {
      if (transaction && auth.purposeOf(transaction) === 'connect') throw failure(401, connectorSignInError(request.query.error, request.query.error_description));
      throw failure(401, 'Microsoft sign-in or consent was not completed. Restart sign-in at /auth/login.');
    }
    if (!transaction || typeof request.query.state !== 'string' || typeof request.query.code !== 'string') throw failure(400, 'Invalid sign-in callback');
    if (auth.purposeOf(transaction) === 'connect') {
      // The connector is attached only to the session that started it (checked again in completeConnect).
      const token = readCookie(request, sessionName);
      const current = token && /^[\w-]{43}$/.test(token) ? await store.getSession(hashToken(token)) : null;
      if (!current || current.expiresAt.getTime() <= Date.now() || !isApprovedUser(config, current.tenantId, current.userId)) throw failure(401, 'Sign in required');
      if (config.openTenantOnboarding) {
        try { if (!hasFreshAuthorization(decryptTokens(current.encryptedTokens, config.tokenEncryptionKey))) throw new Error('Expired'); }
        catch { throw failure(401, 'Sign in again to verify administrator access'); }
      }
      try {
        const tokens = await auth.completeConnect(transaction, request.query.state, request.query.code, { tenantId: current.tenantId, userId: current.userId, sessionHash: current.idHash });
        const map = parseConnectorMap(current.encryptedConnectors);
        map[tokens.connector] = encryptConnectorTokens(tokens, config.tokenEncryptionKey);
        await store.putSession({ ...current, encryptedConnectors: serializeConnectorMap(map) });
        return reply.header('Set-Cookie', cookie(transactionName, '', 0)).redirect(`/?connected=${tokens.connector}`);
      } catch (error) {
        throw failure(401, 'Connecting failed (' + connectorFailureCode(error) + '). Return to the home page and reconnect. Share this diagnostic identifier with the ConfigReview maintainer.');
      }
    }
    try {
      const identity = await auth.complete(transaction, request.query.state, request.query.code);
      const id = randomToken();
      const previous = readCookie(request, sessionName);
      // Connectors stay with the same tenant and user after a re-sign-in (they are sealed to that tenant and user).
      const old = previous && /^[\w-]{43}$/.test(previous) ? await store.getSession(hashToken(previous)) : null;
      const encryptedConnectors = old && old.tenantId === identity.tenantId && old.userId === identity.userId ? old.encryptedConnectors ?? null : null;
      await store.putSession({ idHash: hashToken(id), tenantId: identity.tenantId, userId: identity.userId, displayName: identity.displayName, expiresAt: new Date(Date.now() + config.sessionTtlSeconds * 1000), encryptedTokens: encryptTokens(identity.tokens, config.tokenEncryptionKey), encryptedConnectors });
      if (previous) await store.deleteSession(hashToken(previous));
      return reply.header('Set-Cookie', [cookie(transactionName, '', 0), cookie(sessionName, id, config.sessionTtlSeconds)]).redirect('/');
    } catch {
      throw failure(401, 'Sign-in failed. Check Microsoft consent and tenant access. Open access requires an active Global Administrator, Security Administrator, Global Reader, Security Reader or Privileged Role Administrator role. Restart sign-in at /auth/login.');
    }
  });
  app.post<{ Params: { connector: string } }>('/api/connectors/:connector/disconnect', async (request, reply) => {
    const current = session(request);
    if (!isConnectorId(request.params.connector)) throw failure(404, 'Unknown connector');
    const map = parseConnectorMap(current.encryptedConnectors);
    delete map[request.params.connector];
    await store.putSession({ ...current, encryptedConnectors: serializeConnectorMap(map) });
    return reply.code(204).send();
  });
  app.post('/auth/logout', async (request, reply) => {
    await store.deleteSession(session(request).idHash);
    return reply.header('Set-Cookie', cookie(sessionName, '', 0)).code(204).send();
  });
  app.get('/api/me', async request => {
    const current = session(request);
    let granted: string[] | null = null;
    try { granted = decryptTokens(current.encryptedTokens, config.tokenEncryptionKey).scopes ?? null; } catch { granted = null; }
    const requested = new Set(config.graphScopes.map(scope => scope.replace(/^https:\/\/graph\.microsoft\.com\//, '')));
    // Scopes the online collector uses that were not granted (when Microsoft reported grants) or not requested by this deployment.
    const missingScopes = ONLINE_REQUIRED_GRAPH_PERMISSIONS.filter(scope => granted !== null ? !granted.includes(scope) : !requested.has(scope));
    const connectors = await describeConnectors(config, current, exchangeRunner);
    return { authenticated: true, user: { displayName: current.displayName, tenantId: current.tenantId, userId: current.userId }, connection: { connected: true, requiredScopes: ONLINE_REQUIRED_GRAPH_PERMISSIONS, grantedScopes: granted, missingScopes }, connectors };
  });
  app.get('/api/jobs', async request => ({ jobs: await store.listJobs(session(request).tenantId) }));
  app.post('/api/jobs', async (request, reply) => {
    if (request.body !== undefined && (request.body === null || typeof request.body !== 'object' || Array.isArray(request.body) || Object.keys(request.body).length > 0)) throw failure(400, 'Assessment requests must have an empty body');
    const current = session(request);
    throttle(`job:${current.tenantId}:${current.userId}`, 3);
    let tokens;
    try { tokens = await auth.refresh(decryptTokens(current.encryptedTokens, config.tokenEncryptionKey), current.tenantId); }
    catch { throw failure(401, 'Microsoft Graph access expired. Sign in again to reconnect.'); }
    const encryptedTokens = encryptTokens(tokens, config.tokenEncryptionKey);
    // Each connector is refreshed separately; an unusable one is recorded for the job instead of failing it.
    const connectors = await prepareJobConnectors(auth, config, current);
    await store.putSession({ ...current, encryptedTokens, encryptedConnectors: connectors.session });
    try { return reply.code(202).send(await store.createJob(current.tenantId, current.userId, encryptedTokens, connectors.job)); }
    catch (error) {
      if ((error as { code?: string }).code === '23505') throw failure(409, 'An assessment is already queued or running for this tenant.');
      throw error;
    }
  });
  app.get('/api/assessments', async request => ({ assessments: (await store.listAssessments(session(request).tenantId)).map(result => ({ assessmentId: result.assessmentId, ...result.collection.environment, assessedAt: result.assessedAt, processedAt: result.processedAt, integrityVerified: result.evidence.integrityVerified, source: 'cloud', summary: result.summary })) }));
  async function assessment(request: FastifyRequest, id: string) {
    if (!/^[0-9a-f-]{36}$/i.test(id)) throw failure(404, 'Assessment not found');
    const result = await store.getAssessment(session(request).tenantId, id);
    if (!result) throw failure(404, 'Assessment not found');
    return result;
  }
  app.get<{ Params: { id: string } }>('/api/assessments/:id', request => assessment(request, request.params.id));
  app.get<{ Params: { id: string } }>('/api/assessments/:id/report.json', async (request, reply) => reply.header('Content-Disposition', 'attachment; filename="assessment.json"').type('application/json').send(serializeJsonReport(buildJsonReport(await assessment(request, request.params.id)))));
  app.get<{ Params: { id: string } }>('/api/assessments/:id/report.html', async (request, reply) => reply.header('Content-Disposition', 'attachment; filename="assessment.html"').header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; sandbox").type('text/html').send(renderHtmlReport(await assessment(request, request.params.id))));
  app.get<{ Querystring: { baseline?: string; current?: string } }>('/api/compare', async request => {
    if (!request.query.baseline || !request.query.current) throw failure(400, 'Provide baseline and current assessment IDs');
    return compareAssessments(await assessment(request, request.query.baseline), await assessment(request, request.query.current));
  });
  app.get('/api/controls', () => ({ libraryVersion: CONTROL_LIBRARY_VERSION, controls: CONTROL_LIBRARY.map(control => control.metadata) }));
  app.get('/api/datasets', () => ({ datasets: listDatasetDefinitions().map(dataset => ({ id: dataset.id, module: dataset.module, technology: dataset.technology, title: dataset.title, description: dataset.description, source: dataset.source, operations: dataset.operations, permissions: dataset.permissions, prerequisites: dataset.prerequisites ?? [], personalData: dataset.personalData })) }));
  return app;
}
