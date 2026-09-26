import * as crypto from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import type { AssessmentResult } from '@adminsecops/schemas';
import { buildServer } from './server.js';
import { encryptTokens, hashToken } from './auth.js';
import { loadConfig } from './config.js';
import type { Store } from './store.js';
import { COLLECTORS, FAILURE_CODES, USAGE_COUNTERS, UsageCounters, collectorsRan, failureCode, hashOrganisation, isUsageCounter, usageSecretMatches } from './usage.js';

vi.mock('node:crypto', async (original) => {
  const actual = await original<typeof crypto>();
  return { ...actual, timingSafeEqual: vi.fn(actual.timingSafeEqual) };
});

vi.mock('@adminsecops/reporting', () => ({ buildJsonReport: vi.fn(() => ({})), serializeJsonReport: vi.fn(() => '{}'), renderHtmlReport: vi.fn(() => '<p></p>') }));

const tenant = 'aaaaaaaa-0000-4000-8000-000000000001';
const salt = 'usage-salt-for-tests-only-0123456789abc';

describe('usage counters', () => {
  it('allows only the fixed counter names', () => {
    expect(USAGE_COUNTERS).toEqual([
      'assessments_started', 'assessments_completed', 'assessments_failed', 'controls_evaluated',
      'exports_json', 'exports_html',
      ...COLLECTORS.map(name => `collector_${name}`),
      ...FAILURE_CODES.map(code => `failed_${code}`),
    ]);
    expect(COLLECTORS).toEqual(['entra', 'm365', 'intune', 'azure', 'exchange', 'dns']);
    expect(FAILURE_CODES).toEqual(['NOT_APPROVED', 'CONSENT_OR_TOKEN', 'COLLECTION_FAILED', 'TIMEOUT', 'QUEUE_EXPIRED', 'UNKNOWN']);
    for (const name of ['failed_Something went wrong', 'tenant_id', 'exports_pdf', '', 'collector_Entra']) expect(isUsageCounter(name)).toBe(false);
  });

  it('refuses unknown counters before writing and swallows the error with a fixed message', async () => {
    const recordUsage = vi.fn(() => Promise.resolve());
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const usage = new UsageCounters({ recordUsage }, { counting: true, hashSalt: null });
    await expect(usage.failed('Tenant user is no longer approved' as never)).resolves.toBeUndefined();
    expect(recordUsage).not.toHaveBeenCalled();
    expect(error).toHaveBeenCalledWith('Usage counter update failed.');
    error.mockRestore();
  });

  it('hashes the organisation with the salt and never returns the tenant ID', () => {
    const hash = hashOrganisation(tenant, salt);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).not.toContain(tenant.replace(/-/g, ''));
    expect(hash).toBe(hashOrganisation(tenant.toUpperCase(), salt));
    expect(hash).not.toBe(hashOrganisation(tenant, `${salt}-other`));
    expect(hash).not.toBe(crypto.createHash('sha256').update(tenant).digest('hex'));
    expect(hashOrganisation('aaaaaaaa-0000-4000-8000-000000000002', salt)).not.toBe(hash);
  });

  it('records the organisation hash only when a salt is configured, and nothing when counting is off', async () => {
    const recordUsage = vi.fn(() => Promise.resolve());
    await new UsageCounters({ recordUsage }, { counting: true, hashSalt: salt }).started(tenant);
    expect(recordUsage).toHaveBeenLastCalledWith({ assessments_started: 1 }, hashOrganisation(tenant, salt));
    await new UsageCounters({ recordUsage }, { counting: true, hashSalt: null }).started(tenant);
    expect(recordUsage).toHaveBeenLastCalledWith({ assessments_started: 1 }, null);
    expect(JSON.stringify(recordUsage.mock.calls)).not.toContain(tenant);
    recordUsage.mockClear();
    await new UsageCounters({ recordUsage }, { counting: false, hashSalt: salt }).started(tenant);
    expect(recordUsage).not.toHaveBeenCalled();
  });

  it('counts completed assessments, controls and the collectors that returned data', async () => {
    const dataset = (datasetId: string, module: string, state: string) => ({ datasetId, module, state });
    const result = {
      summary: { controlsEvaluated: 42 },
      evidence: { datasets: [
        dataset('entra.users', 'Entra', 'available'), dataset('entra.groups', 'Entra', 'partial'),
        dataset('intune.compliancePolicies', 'Intune', 'available'), dataset('azure.subscriptions', 'Azure', 'unavailable'),
        dataset('exchange.mailDnsRecords', 'Exchange', 'available'), dataset('exchange.transportRules', 'Exchange', 'unavailable'),
      ] },
    } as unknown as AssessmentResult;
    expect(collectorsRan(result)).toEqual(['entra', 'intune', 'dns']);
    const recordUsage = vi.fn(() => Promise.resolve());
    await new UsageCounters({ recordUsage }, { counting: true, hashSalt: salt }).completed(result);
    expect(recordUsage).toHaveBeenCalledWith({ assessments_completed: 1, controls_evaluated: 42, collector_entra: 1, collector_intune: 1, collector_dns: 1 }, null);
  });

  it('classifies failures by stage, and cancelled or timed-out collection as TIMEOUT', () => {
    expect(failureCode('CONSENT_OR_TOKEN', new Error('Refresh failed'))).toBe('CONSENT_OR_TOKEN');
    expect(failureCode('COLLECTION_FAILED', Object.assign(new Error('x'), { name: 'CollectionCancelledError' }))).toBe('TIMEOUT');
    expect(failureCode('COLLECTION_FAILED', new DOMException('timed out', 'TimeoutError'))).toBe('TIMEOUT');
    expect(failureCode('UNKNOWN', null)).toBe('UNKNOWN');
  });

  it('compares the API secret in constant time on SHA-256 digests', () => {
    const secret = 'usage-secret-for-tests-only-0123456789';
    const compare = vi.mocked(crypto.timingSafeEqual);
    for (const [header, expected] of [[`Bearer ${secret}`, true], ['Bearer x', false], [`Bearer ${secret}${secret}`, false], [undefined, false], [secret, false], [`Bearer  ${secret}`, false]] as const) {
      compare.mockClear();
      expect(usageSecretMatches(header, secret)).toBe(expected);
      // The comparison always runs, on equal-length digests, whatever was supplied.
      expect(compare).toHaveBeenCalledTimes(1);
      const [a, b] = compare.mock.calls[0] as [Buffer, Buffer];
      expect([a.length, b.length]).toEqual([32, 32]);
    }
  });

  it('counts report exports by format only after the assessment is found', async () => {
    const user = 'aaaaaaaa-0000-4000-8000-000000000002';
    const config = loadConfig({ PUBLIC_URL: 'https://admin.example.com', AZURE_TENANT_ID: tenant, AZURE_CLIENT_ID: 'aaaaaaaa-0000-4000-8000-000000000003', AZURE_CLIENT_SECRET: 'test-only', ALLOWED_USER_IDS: user, TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 1).toString('base64'), DATABASE_URL: 'postgresql://localhost/test', GRAPH_SCOPES: 'User.Read' });
    const token = 'a'.repeat(43);
    const session = { idHash: hashToken(token), tenantId: tenant, userId: user, displayName: 'Test Admin', expiresAt: new Date(Date.now() + 60_000), encryptedTokens: encryptTokens({ accessToken: 't', expiresAt: Date.now() + 600_000 }, config.tokenEncryptionKey) };
    const recordUsage = vi.fn(() => Promise.resolve());
    const id = 'aaaaaaaa-0000-4000-8000-000000000004';
    const getAssessment = vi.fn((_tenant: string, requested: string) => Promise.resolve(requested === id ? { assessmentId: id } : null));
    const store = { getSession: () => Promise.resolve(session), getAssessment, recordUsage } as unknown as Store;
    const app = await buildServer({ config, store });
    const headers = { cookie: `__Host-adminsecops=${token}` };
    expect((await app.inject({ url: `/api/assessments/${id}/report.json`, headers })).statusCode).toBe(200);
    expect(recordUsage).toHaveBeenLastCalledWith({ exports_json: 1 }, null);
    expect((await app.inject({ url: `/api/assessments/${id}/report.html`, headers })).statusCode).toBe(200);
    expect(recordUsage).toHaveBeenLastCalledWith({ exports_html: 1 }, null);
    expect((await app.inject({ url: '/api/assessments/aaaaaaaa-0000-4000-8000-000000000005/report.html', headers })).statusCode).toBe(404);
    expect(recordUsage).toHaveBeenCalledTimes(2);
    await app.close();
  });
});
