import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { silentLogger } from '@adminsecops/core';
import { makeZip } from '../../../packages/evidence/test/zip.js';
import { ASSESSMENT_ID, samplePackage } from '../../../packages/evidence/test/sample.js';
import type { ApiConfig } from './config.js';
import { loadConfig } from './config.js';
import { buildServer } from './server.js';

const PORT = 4399;
const HOST = `127.0.0.1:${PORT}`;
const WEB = { host: HOST, 'x-adminsecops-client': 'web' };

function multipart(name: string, filename: string, content: Buffer): { payload: Buffer; headers: Record<string, string> } {
  const boundary = '----adminsecopsTestBoundary';
  const head = Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="${name}"; filename="${filename}"\r\nContent-Type: application/zip\r\n\r\n`,
  );
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
  return { payload: Buffer.concat([head, content, tail]), headers: { 'content-type': `multipart/form-data; boundary=${boundary}` } };
}

describe('API server', () => {
  let dir: string;
  let app: FastifyInstance;
  let zip: Buffer;

  beforeAll(async () => {
    dir = mkdtempSync(path.join(tmpdir(), 'aso-api-'));
    const samplesDir = path.join(dir, 'samples');
    const { files } = samplePackage();
    const contoso = path.join(samplesDir, 'contoso');
    for (const [name, data] of files) {
      mkdirSync(path.dirname(path.join(contoso, name)), { recursive: true });
      writeFileSync(path.join(contoso, name), data);
    }
    const config: ApiConfig = {
      host: '127.0.0.1',
      port: PORT,
      dataDir: path.join(dir, 'data'),
      webDistDir: path.join(dir, 'no-web'),
      samplesDir,
      maxUploadBytes: 2 * 1024 * 1024,
    };
    app = await buildServer({ config, logger: silentLogger });
    zip = await makeZip([...files.entries()].map(([name, data]) => ({ name, data })));
  });

  afterAll(async () => {
    await app.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('reports health with security headers', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/health', headers: { host: HOST } });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ status: 'ok', product: 'AdminSecOps' });
    expect(res.headers['content-security-policy']).toContain("default-src 'self'");
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('rejects unexpected Host headers (DNS rebinding)', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/health', headers: { host: 'attacker.example:4399' } });
    expect(res.statusCode).toBe(421);
  });

  it('rejects cross-origin requests', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/assessments', headers: { host: HOST, origin: 'https://attacker.example' } });
    expect(res.statusCode).toBe(403);
  });

  it('requires the client header for state-changing requests (CSRF)', async () => {
    const body = multipart('package', 'a.zip', zip);
    const res = await app.inject({ method: 'POST', url: '/api/assessments', headers: { host: HOST, ...body.headers }, payload: body.payload });
    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe('CLIENT_HEADER_REQUIRED');
  });

  it('processes an uploaded evidence package end to end', async () => {
    const body = multipart('package', 'assessment.zip', zip);
    const res = await app.inject({ method: 'POST', url: '/api/assessments', headers: { ...WEB, ...body.headers }, payload: body.payload });
    expect(res.statusCode).toBe(201);
    expect(res.json().assessmentId).toBe(ASSESSMENT_ID);

    const list = await app.inject({ method: 'GET', url: '/api/assessments', headers: { host: HOST } });
    expect(list.json().assessments).toHaveLength(1);

    const result = await app.inject({ method: 'GET', url: `/api/assessments/${ASSESSMENT_ID}`, headers: { host: HOST } });
    expect(result.statusCode).toBe(200);
    expect(result.json().evidence.integrityVerified).toBe(true);

    const html = await app.inject({ method: 'GET', url: `/api/assessments/${ASSESSMENT_ID}/report.html`, headers: { host: HOST } });
    expect(html.statusCode).toBe(200);
    expect(html.headers['content-disposition']).toMatch(/^attachment; filename="adminsecops-report-/);
    expect(html.body).toContain('What should I fix first?');

    const json = await app.inject({ method: 'GET', url: `/api/assessments/${ASSESSMENT_ID}/report.json`, headers: { host: HOST } });
    expect(json.json().reportType).toBe('adminsecops.assessment');

    const compare = await app.inject({ method: 'GET', url: `/api/compare?baseline=${ASSESSMENT_ID}&current=${ASSESSMENT_ID}`, headers: { host: HOST } });
    expect(compare.json().direction).toBe('unchanged');
  });

  it('persists results across server restarts', async () => {
    const again = await buildServer({
      config: { ...loadConfig({ ADMINSECOPS_PORT: String(PORT) }), dataDir: path.join(dir, 'data'), samplesDir: path.join(dir, 'samples'), webDistDir: path.join(dir, 'no-web') },
      logger: silentLogger,
    });
    const list = await again.inject({ method: 'GET', url: '/api/assessments', headers: { host: HOST } });
    expect(list.json().assessments.length).toBeGreaterThanOrEqual(1);
    await again.close();
  });

  it('rejects non-ZIP uploads with a safe error', async () => {
    const body = multipart('package', 'x.zip', Buffer.from('not a zip'));
    const res = await app.inject({ method: 'POST', url: '/api/assessments', headers: { ...WEB, ...body.headers }, payload: body.payload });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe('PACKAGE_NOT_ZIP');
  });

  it('rejects uploads over the size limit', async () => {
    const body = multipart('package', 'big.zip', Buffer.alloc(3 * 1024 * 1024, 1));
    const res = await app.inject({ method: 'POST', url: '/api/assessments', headers: { ...WEB, ...body.headers }, payload: body.payload });
    expect(res.statusCode).toBe(413);
  });

  it('validates assessment IDs (no path traversal)', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/assessments/..%2F..%2Fsecrets', headers: { host: HOST } });
    expect(res.statusCode).toBe(400);
    const missing = await app.inject({ method: 'GET', url: '/api/assessments/00000000-0000-4000-8000-00000000abcd', headers: { host: HOST } });
    expect(missing.statusCode).toBe(404);
  });

  it('loads bundled samples by allow-listed name only', async () => {
    const samples = await app.inject({ method: 'GET', url: '/api/samples', headers: { host: HOST } });
    expect(samples.json<{ samples: Array<{ name: string }> }>().samples.map((s) => s.name)).toEqual(['contoso']);
    const ok = await app.inject({ method: 'POST', url: '/api/samples/contoso', headers: WEB });
    expect(ok.statusCode).toBe(201);
    const bad = await app.inject({ method: 'POST', url: '/api/samples/..%2F..', headers: WEB });
    expect(bad.statusCode).toBe(404);
  });

  it('serves the control catalog and dataset definitions', async () => {
    const controls = await app.inject({ method: 'GET', url: '/api/controls', headers: { host: HOST } });
    expect(controls.json().controls.length).toBeGreaterThan(20);
    const datasets = await app.inject({ method: 'GET', url: '/api/datasets', headers: { host: HOST } });
    expect(datasets.json().datasets.length).toBeGreaterThan(40);
  });

  it('deletes assessments', async () => {
    const res = await app.inject({ method: 'DELETE', url: `/api/assessments/${ASSESSMENT_ID}`, headers: WEB });
    expect(res.statusCode).toBe(204);
    const after = await app.inject({ method: 'GET', url: `/api/assessments/${ASSESSMENT_ID}`, headers: { host: HOST } });
    expect(after.statusCode).toBe(404);
  });

  it('returns JSON 404 for unknown API routes', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/nope', headers: { host: HOST } });
    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe('NOT_FOUND');
  });
});

describe('config', () => {
  it('refuses to bind to non-loopback addresses', () => {
    expect(() => loadConfig({ ADMINSECOPS_HOST: '0.0.0.0' })).toThrow(/loopback/);
    expect(loadConfig({}).host).toBe('127.0.0.1');
  });
});
