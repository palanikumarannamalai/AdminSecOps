import { randomUUID } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { loadEvidenceBundle, readZipPackage } from '@adminsecops/evidence';
import { runAssessment } from '@adminsecops/engine';
import { CONTROL_LIBRARY } from '@adminsecops/controls';
import { hashToken, randomToken } from './auth.js';
import type { StoredSession } from './store.js';
import type { OnPremAgent, OnPremStore } from './onprem-store.js';

export const ONPREM_LIMITS = {
  maxArchiveBytes: 20 * 1024 * 1024,
  maxEntries: 100,
  maxFileBytes: 24 * 1024 * 1024,
  maxTotalBytes: 64 * 1024 * 1024,
  maxCompressionRatio: 100,
};
const allowed = new Set(['AD', 'ADCS', 'GPO', 'Windows']);
const fail = (statusCode: number, message: string) =>
  Object.assign(new Error(message), { statusCode });
export async function assessOnPrem(bytes: Buffer, tenantId: string) {
  const bundle = loadEvidenceBundle(await readZipPackage(bytes, ONPREM_LIMITS));
  if (bundle.manifest.environment.tenantId?.toLowerCase() !== tenantId.toLowerCase())
    throw fail(
      403,
      'The package tenant ID must match this connection. Collect again using the tenant ID shown in your workspace.',
    );
  if (
    !bundle.manifest.files.length ||
    bundle.manifest.files.some(
      (f) => !allowed.has(f.module) || !/^(ad|adcs|gpo|windows)\./.test(f.datasetId),
    ) ||
    bundle.manifest.modules.some((m) => !allowed.has(m.name))
  )
    throw fail(400, 'Upload an on-premises-only package (AD, AD CS, GPO or Windows).');
  if (
    !bundle.integrityVerified ||
    bundle.files.some(
      (f) =>
        f.sensitiveContent ||
        (f.schema !== 'valid' &&
          !(
            f.schema === 'not-checked' &&
            f.collectionStatus !== 'Success' &&
            f.collectionStatus !== 'Partial'
          )),
    ) ||
    bundle.issues.some((i) => i.origin === 'ingestion' && i.level === 'error')
  )
    throw fail(400, 'Package integrity or schema validation failed. Recollect the evidence.');
  const result = runAssessment(bundle, CONTROL_LIBRARY);
  result.assessmentId = randomUUID();
  result.evidence.issues.push({
    code: 'ONPREM_UPLOADED_EVIDENCE',
    message:
      'Uploaded configuration evidence. The authenticated uploader selected the tenant association; hashes check file integrity, not source authenticity. This is a separate on-premises snapshot, not a merged cloud assessment.',
    target: null,
    level: 'warning',
    module: null,
    datasetId: null,
    origin: 'ingestion',
  });
  return result;
}
export function registerOnPrem(
  app: FastifyInstance,
  store: OnPremStore,
  session: (r: FastifyRequest) => StoredSession,
) {
  const agents = new WeakMap<FastifyRequest, OnPremAgent>();
  const locked = new WeakSet<FastifyRequest>();
  let busy = false;
  const recent = new Map<string, number>();
  app.addHook('onRequestAbort', (request, done) => {
    if (locked.has(request)) {
      busy = false;
      locked.delete(request);
    }
    done();
  });
  app.addContentTypeParser(
    'application/zip',
    { parseAs: 'buffer', bodyLimit: ONPREM_LIMITS.maxArchiveBytes },
    (_request, body, done) => done(null, body),
  );
  app.get('/api/onprem/agents', async (request) => ({
    agents: await store.agents(session(request).tenantId),
  }));
  app.post<{ Body: { name?: unknown } }>('/api/onprem/agents', async (request, reply) => {
    const current = session(request);
    const name = request.body?.name;
    if (typeof name !== 'string' || !name.trim() || name.length > 80)
      throw fail(400, 'Give the agent a name of 1–80 characters.');
    const token = randomToken();
    const agent = await store.enroll(
      current.tenantId,
      current.userId,
      name.trim(),
      hashToken(token),
    );
    return reply.code(201).send({ agent, token });
  });
  app.post<{ Params: { id: string } }>('/api/onprem/agents/:id/revoke', async (request, reply) => {
    if (!/^[a-f0-9-]{36}$/i.test(request.params.id)) throw fail(400, 'Invalid agent ID');
    await store.revoke(session(request).tenantId, request.params.id);
    return reply.code(204).send();
  });
  for (const agentMode of [false, true])
    app.post(
      agentMode ? '/api/onprem/ingest' : '/api/onprem/upload',
      {
        bodyLimit: ONPREM_LIMITS.maxArchiveBytes,
        onRequest: async (request) => {
          let tenantId: string;
          if (agentMode) {
            const match = /^Bearer ([\w-]{43})$/.exec(request.headers.authorization ?? '');
            const agent = match ? await store.authenticate(hashToken(match[1]!)) : null;
            if (!agent)
              throw fail(
                401,
                'Agent credential expired, revoked or invalid. Enroll again from the workspace.',
              );
            agents.set(request, agent);
            tenantId = agent.tenantId;
          } else tenantId = session(request).tenantId;
          if (request.headers['content-type'] !== 'application/zip')
            throw fail(415, 'Upload a ZIP with application/zip content type.');
          const now = Date.now();
          for (const [key, time] of recent) if (now - time > 60_000) recent.delete(key);
          if (busy || (recent.get(tenantId) ?? 0) > now - 60_000 || recent.size >= 1000)
            throw fail(
              429,
              'Another upload is processing or was submitted recently. Wait one minute.',
            );
          recent.set(tenantId, now);
          busy = true;
          locked.add(request);
        },
        onResponse: (request, _reply, done) => {
          if (locked.has(request)) {
            busy = false;
            locked.delete(request);
          }
          done();
        },
      },
      async (request, reply) => {
        const agent = agents.get(request);
        const current = agentMode ? null : session(request);
        const tenantId = agent?.tenantId ?? current!.tenantId;
        if (!Buffer.isBuffer(request.body)) throw fail(400, 'A ZIP evidence package is required.');
        let result;
        try {
          result = await assessOnPrem(request.body, tenantId);
        } catch (error) {
          if ((error as { statusCode?: number }).statusCode === 403) throw error;
          throw fail(
            400,
            'The on-premises package is invalid, exceeds limits, or contains unsupported evidence.',
          );
        }
        await store.save(tenantId, current?.userId ?? null, result, agent?.id);
        return reply.code(201).send({ assessmentId: result.assessmentId });
      },
    );
}
