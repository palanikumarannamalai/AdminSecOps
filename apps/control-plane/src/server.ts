import Fastify, { type FastifyRequest } from 'fastify';
import { CONTROL_LIBRARY, CONTROL_LIBRARY_VERSION } from '@adminsecops/controls';
import { compareAssessments } from '@adminsecops/engine';
import { listDatasetDefinitions } from '@adminsecops/schemas';
import { buildJsonReport, renderHtmlReport, serializeJsonReport } from '@adminsecops/reporting';
import type { Config } from './config.js';
import { createAuth, decryptTokens, encryptTokens, hashToken, randomToken } from './auth.js';
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

export async function buildServer({ config, store }: { config: Config; store: Store }) {
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
    if (route === '/api/health' || !route.startsWith('/api/') && route !== '/auth/logout') return;
    const token = readCookie(request, sessionName);
    if (!token || !/^[\w-]{43}$/.test(token)) throw failure(401, 'Sign in required');
    const current = await store.getSession(hashToken(token));
    if (!current || current.expiresAt.getTime() <= Date.now() || current.tenantId !== config.tenantId || !config.allowedUserIds.includes(current.userId)) throw failure(401, 'Sign in required');
    sessions.set(request, current);
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method) && (request.headers.origin !== config.publicUrl || request.headers['x-adminsecops-client'] !== 'web')) throw failure(403, 'Invalid request origin');
  });
  app.get('/api/health', () => ({ status: 'ok' }));
  app.get('/auth/login', async (request, reply) => {
    throttle(`login:${request.ip}`, 30);
    const login = auth.begin();
    return reply.header('Set-Cookie', cookie(transactionName, login.cookie, 600)).redirect(login.url);
  });
  app.get<{ Querystring: { state?: string; code?: string } }>('/auth/callback', async (request, reply) => {
    reply.header('Set-Cookie', cookie(transactionName, '', 0));
    const transaction = readCookie(request, transactionName);
    if (!transaction || typeof request.query.state !== 'string' || typeof request.query.code !== 'string') throw failure(400, 'Invalid sign-in callback');
    try {
      const identity = await auth.complete(transaction, request.query.state, request.query.code);
      const id = randomToken();
      await store.putSession({ idHash: hashToken(id), tenantId: identity.tenantId, userId: identity.userId, displayName: identity.displayName, expiresAt: new Date(Date.now() + config.sessionTtlSeconds * 1000), encryptedTokens: encryptTokens(identity.tokens, config.tokenEncryptionKey) });
      const previous = readCookie(request, sessionName);
      if (previous) await store.deleteSession(hashToken(previous));
      return reply.header('Set-Cookie', [cookie(transactionName, '', 0), cookie(sessionName, id, config.sessionTtlSeconds)]).redirect('/');
    } catch {
      throw failure(401, 'Sign-in failed. Check tenant access and try signing in again.');
    }
  });
  app.post('/auth/logout', async (request, reply) => {
    await store.deleteSession(session(request).idHash);
    return reply.header('Set-Cookie', cookie(sessionName, '', 0)).code(204).send();
  });
  app.get('/api/me', request => {
    const current = session(request);
    return { authenticated: true, user: { displayName: current.displayName, tenantId: current.tenantId, userId: current.userId }, connection: { connected: true } };
  });
  app.get('/api/jobs', async request => ({ jobs: await store.listJobs(session(request).tenantId) }));
  app.post('/api/jobs', async (request, reply) => {
    if (request.body !== undefined && (request.body === null || typeof request.body !== 'object' || Array.isArray(request.body) || Object.keys(request.body).length > 0)) throw failure(400, 'Assessment requests must have an empty body');
    const current = session(request);
    throttle(`job:${current.userId}`, 3);
    let tokens;
    try { tokens = await auth.refresh(decryptTokens(current.encryptedTokens, config.tokenEncryptionKey)); }
    catch { throw failure(401, 'Microsoft Graph access expired. Sign in again to reconnect.'); }
    const encryptedTokens = encryptTokens(tokens, config.tokenEncryptionKey);
    await store.putSession({ ...current, encryptedTokens });
    try { return reply.code(202).send(await store.createJob(current.tenantId, current.userId, encryptedTokens)); }
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
