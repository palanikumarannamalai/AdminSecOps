import { existsSync } from 'node:fs';
import path from 'node:path';
import fastifyMultipart from '@fastify/multipart';
import fastifyStatic from '@fastify/static';
import Fastify, { type FastifyInstance } from 'fastify';
import { CONTROL_LIBRARY, CONTROL_LIBRARY_VERSION } from '@adminsecops/controls';
import {
  AdminSecOpsError,
  ENGINE_VERSION,
  PRODUCT_NAME,
  createLogger,
  isAdminSecOpsError,
  type Logger,
} from '@adminsecops/core';
import { assessDirectory, assessZip, compareAssessments } from '@adminsecops/engine';
import { buildJsonReport, renderHtmlReport, reportFileName, serializeJsonReport } from '@adminsecops/reporting';
import { listDatasetDefinitions } from '@adminsecops/schemas';
import type { ApiConfig } from './config.js';
import { registerSecurity, requireFound } from './security.js';
import { AssessmentStore } from './store.js';

export const SAMPLES = [
  { name: 'contoso', title: 'Contoso (hybrid, partly secured)', description: 'A fictional hybrid Microsoft 365, Azure and Active Directory organisation with a realistic mix of issues.' },
  { name: 'contoso-followup', title: 'Contoso follow-up', description: 'The same fictional tenant 30 days later, after partial remediation. Compare it with Contoso.' },
  { name: 'fabrikam', title: 'Fabrikam (on-premises only)', description: 'A fictional Active Directory-only organisation assessed with the AD, AD CS, GPO and Windows modules.' },
] as const;

export interface ServerOptions {
  config: ApiConfig;
  logger?: Logger;
  /** Additional allowed Host header values (used by tests and the Vite dev proxy). */
  extraHosts?: readonly string[];
}

/**
 * Build the local API server. It serves the dashboard and processes evidence packages
 * entirely in memory; evidence is never sent anywhere.
 */
export async function buildServer(options: ServerOptions): Promise<FastifyInstance> {
  const { config } = options;
  const log = options.logger ?? createLogger();
  const store = new AssessmentStore(config.dataDir);
  let processing = false;

  const app = Fastify({ logger: false, bodyLimit: 1024 * 1024, trustProxy: false });
  registerSecurity(app, config.port, options.extraHosts ?? []);
  await app.register(fastifyMultipart, {
    limits: { fileSize: config.maxUploadBytes, files: 1, fields: 0, parts: 1, headerPairs: 100 },
  });

  app.setErrorHandler(async (error, request, reply) => {
    if (isAdminSecOpsError(error)) {
      log.warn('request rejected', { method: request.method, route: request.routeOptions.url, code: error.code });
      return reply.code(error.statusCode).send({ error: { code: error.code, message: error.message } });
    }
    const status = typeof (error as { statusCode?: unknown }).statusCode === 'number' ? (error as { statusCode: number }).statusCode : 500;
    if (status === 413 || (error as { code?: string }).code === 'FST_REQ_FILE_TOO_LARGE') {
      return reply.code(413).send({ error: { code: 'PACKAGE_TOO_LARGE', message: `The upload exceeds the ${config.maxUploadBytes} byte limit.` } });
    }
    if (status >= 400 && status < 500) {
      return reply.code(status).send({ error: { code: 'BAD_REQUEST', message: 'The request was not valid.' } });
    }
    log.error('unhandled error', { method: request.method, route: request.routeOptions.url, errorName: error instanceof Error ? error.name : 'unknown' });
    return reply.code(500).send({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected internal error occurred.' } });
  });

  app.addHook('onResponse', async (request, reply) => {
    log.info('request', { method: request.method, route: request.routeOptions.url ?? 'unmatched', status: reply.statusCode, ms: Math.round(reply.elapsedTime) });
  });

  /** Only one package is processed at a time to bound memory use. */
  async function exclusive<T>(work: () => Promise<T>): Promise<T> {
    if (processing) throw new AdminSecOpsError('BUSY', 'Another evidence package is being processed. Try again shortly.', { statusCode: 429 });
    processing = true;
    try {
      return await work();
    } finally {
      processing = false;
    }
  }

  app.get('/api/health', () => ({
    status: 'ok',
    product: PRODUCT_NAME,
    version: ENGINE_VERSION,
    engineVersion: ENGINE_VERSION,
    controlLibraryVersion: CONTROL_LIBRARY_VERSION,
  }));

  app.get('/api/assessments', async () => ({ assessments: await store.list() }));

  app.post('/api/assessments', async (request, reply) => {
    const file = await request.file();
    if (file === undefined || file.fieldname !== 'package') {
      throw new AdminSecOpsError('PACKAGE_MISSING', 'Upload an evidence package ZIP in the "package" field.');
    }
    const buffer = await file.toBuffer();
    if (file.file.truncated) throw new AdminSecOpsError('PACKAGE_TOO_LARGE', 'The upload exceeds the size limit.', { statusCode: 413 });
    const result = await exclusive(() => assessZip(buffer));
    await store.save(result, 'upload');
    log.info('assessment processed', { source: 'upload', controls: result.summary.controlsEvaluated, findings: result.findings.length });
    return reply.code(201).send({ assessmentId: result.assessmentId });
  });

  app.get('/api/samples', () => ({
    samples: SAMPLES.filter((s) => existsSync(path.join(config.samplesDir, s.name))).map(({ name, title, description }) => ({ name, title, description })),
  }));

  app.post<{ Params: { name: string } }>('/api/samples/:name', async (request, reply) => {
    const sample = SAMPLES.find((s) => s.name === request.params.name);
    if (sample === undefined) throw new AdminSecOpsError('SAMPLE_NOT_FOUND', 'Unknown sample.', { statusCode: 404 });
    const dir = path.join(config.samplesDir, sample.name);
    if (!existsSync(dir)) throw new AdminSecOpsError('SAMPLE_NOT_FOUND', 'Sample data is not installed.', { statusCode: 404 });
    const result = await exclusive(() => assessDirectory(dir));
    await store.save(result, 'sample');
    return reply.code(201).send({ assessmentId: result.assessmentId });
  });

  app.get<{ Params: { id: string } }>('/api/assessments/:id', async (request) => requireFound(await store.get(request.params.id)));

  app.delete<{ Params: { id: string } }>('/api/assessments/:id', async (request, reply) => {
    requireFound((await store.delete(request.params.id)) ? true : undefined);
    return reply.code(204).send();
  });

  app.get<{ Params: { id: string } }>('/api/assessments/:id/report.html', async (request, reply) => {
    const result = requireFound(await store.get(request.params.id));
    return reply
      .header('Content-Type', 'text/html; charset=utf-8')
      .header('Content-Disposition', `attachment; filename="${reportFileName(result, 'html')}"`)
      .header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; sandbox")
      .send(renderHtmlReport(result));
  });

  app.get<{ Params: { id: string } }>('/api/assessments/:id/report.json', async (request, reply) => {
    const result = requireFound(await store.get(request.params.id));
    return reply
      .header('Content-Type', 'application/json; charset=utf-8')
      .header('Content-Disposition', `attachment; filename="${reportFileName(result, 'json')}"`)
      .send(serializeJsonReport(buildJsonReport(result)));
  });

  app.get<{ Querystring: { baseline?: string; current?: string } }>('/api/compare', async (request) => {
    const { baseline, current } = request.query;
    if (baseline === undefined || current === undefined) {
      throw new AdminSecOpsError('COMPARE_PARAMS', 'Provide baseline and current assessment IDs.');
    }
    const a = requireFound(await store.get(baseline), 'Baseline assessment');
    const b = requireFound(await store.get(current), 'Current assessment');
    return compareAssessments(a, b);
  });

  app.get('/api/controls', () => ({
    libraryVersion: CONTROL_LIBRARY_VERSION,
    controls: CONTROL_LIBRARY.map((c) => c.metadata),
  }));

  app.get('/api/datasets', () => ({
    datasets: listDatasetDefinitions().map((d) => ({
      id: d.id,
      module: d.module,
      technology: d.technology,
      title: d.title,
      description: d.description,
      source: d.source,
      operations: d.operations,
      permissions: d.permissions,
      prerequisites: d.prerequisites ?? [],
      personalData: d.personalData,
    })),
  }));

  app.all('/api/*', () => {
    throw new AdminSecOpsError('NOT_FOUND', 'Unknown API endpoint.', { statusCode: 404 });
  });

  if (existsSync(path.join(config.webDistDir, 'index.html'))) {
    await app.register(fastifyStatic, { root: config.webDistDir, index: ['index.html'], dotfiles: 'deny' });
    app.setNotFoundHandler(async (request, reply) => {
      if ((request.method === 'GET' || request.method === 'HEAD') && !request.url.startsWith('/api/')) return reply.sendFile('index.html');
      return reply.code(404).send({ error: { code: 'NOT_FOUND', message: 'Not found.' } });
    });
  }

  return app;
}
