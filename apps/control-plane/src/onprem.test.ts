/* eslint-disable @typescript-eslint/unbound-method -- Store methods are Vitest spies. */
import { describe, it, expect, vi } from 'vitest';
import Fastify from 'fastify';
import { buildEvidencePackage } from '@adminsecops/evidence';
import { manifestBase, envelope } from '../../../packages/evidence/test/sample.js';
import { makeZip } from '../../../packages/evidence/test/zip.js';
import { assessOnPrem, registerOnPrem } from './onprem.js';
import type { OnPremStore } from './onprem-store.js';
import type { StoredSession } from './store.js';
const tenant = '11111111-2222-4333-8444-555555555555';
const other = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
async function zip(cloud = false, notCollected = false) {
  const base = manifestBase();
  base.modules[0]!.name = cloud ? 'Entra' : 'AD';
  const env = envelope(
    cloud ? 'entra.guestUsers' : 'ad.users',
    cloud ? [] : { domains: [], users: [] },
    {
      collector: {
        name: 'AdminSecOps.Collector',
        version: '0.1.0',
        module: cloud ? 'Entra' : 'AD',
        moduleVersion: '0.1.0',
      },
      source: {
        system: cloud ? 'MicrosoftGraph' : 'ActiveDirectory',
        operations: ['read'],
        apiVersion: null,
      },
    },
  );
  if (notCollected) {
    env.status = 'NotCollected';
    env.data = null;
  }
  const { files } = buildEvidencePackage(base, [
    { path: cloud ? 'evidence/entra/guestUsers.json' : 'evidence/ad/users.json', envelope: env },
  ]);
  return makeZip([...files].map(([name, data]) => ({ name, data })));
}
function memory() {
  const agent = {
    id: '11111111-1111-1111-1111-111111111111',
    tenantId: tenant,
    name: 'test',
    expiresAt: new Date(Date.now() + 60000).toISOString(),
    revoked: false,
  };
  const store: OnPremStore = {
    enroll: vi.fn(() => Promise.resolve(agent)),
    agents: vi.fn(() => Promise.resolve([agent])),
    revoke: vi.fn(() => Promise.resolve()),
    authenticate: vi.fn(() => Promise.resolve(agent)),
    save: vi.fn(() => Promise.resolve()),
  };
  return store;
}
describe('on-premises upload boundary', () => {
  it('preserves unavailable collection as unknown rather than rejecting a partial package', async () => {
    const result = await assessOnPrem(await zip(false, true), tenant);
    expect(result.evidence.files[0]?.collectionStatus).toBe('NotCollected');
  });
  it('assesses validated on-premises evidence as a separate snapshot', async () => {
    const result = await assessOnPrem(await zip(), tenant);
    expect(result.collection.environment.tenantId).toBe(tenant);
    expect(result.evidence.issues.some((i) => i.code === 'ONPREM_UPLOADED_EVIDENCE')).toBe(true);
    expect(result.assessmentId).not.toBe(manifestBase().assessmentId);
  });
  it('rejects cross-tenant, cloud-only and malformed packages', async () => {
    await expect(assessOnPrem(await zip(), other)).rejects.toMatchObject({ statusCode: 403 });
    await expect(assessOnPrem(await zip(true), tenant)).rejects.toThrow('on-premises-only');
    await expect(assessOnPrem(Buffer.from('not ZIP'), tenant)).rejects.toThrow();
  });
  it('requires an active agent credential before accepting a body and binds results to its tenant', async () => {
    const app = Fastify();
    const store = memory();
    registerOnPrem(app, store, () => ({ tenantId: tenant, userId: 'user' }) as StoredSession);
    const bytes = await zip();
    expect(
      (
        await app.inject({
          method: 'POST',
          url: '/api/onprem/ingest',
          headers: { 'content-type': 'application/zip' },
          payload: bytes,
        })
      ).statusCode,
    ).toBe(401);
    const response = await app.inject({
      method: 'POST',
      url: '/api/onprem/ingest',
      headers: { 'content-type': 'application/zip', authorization: 'Bearer ' + 'a'.repeat(43) },
      payload: bytes,
    });
    expect(response.statusCode).toBe(201);
    expect(store.save).toHaveBeenCalledWith(
      tenant,
      null,
      expect.any(Object),
      '11111111-1111-1111-1111-111111111111',
    );
    expect(
      (
        await app.inject({
          method: 'POST',
          url: '/api/onprem/ingest',
          headers: { 'content-type': 'application/zip', authorization: 'Bearer ' + 'a'.repeat(43) },
          payload: bytes,
        })
      ).statusCode,
    ).toBe(429);
    await app.close();
  });
  it('rejects revoked credentials and never trusts a tenant in the URL', async () => {
    const app = Fastify();
    const store = memory();
    store.authenticate = vi.fn(() => Promise.resolve(null));
    registerOnPrem(app, store, () => ({ tenantId: tenant, userId: 'user' }) as StoredSession);
    expect(
      (
        await app.inject({
          method: 'POST',
          url: '/api/onprem/ingest?tenantId=' + other,
          headers: { 'content-type': 'application/zip', authorization: 'Bearer ' + 'a'.repeat(43) },
          payload: await zip(),
        })
      ).statusCode,
    ).toBe(401);
    expect(store.save).not.toHaveBeenCalled();
    await app.close();
  });
});
