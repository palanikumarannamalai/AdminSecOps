/* eslint-disable @typescript-eslint/unbound-method -- Runner methods are Vitest spies, never detached calls. */
import { describe, expect, it, vi } from 'vitest';
import { AdminSecOpsError } from '@adminsecops/core';
import { CONTROL_LIBRARY } from '@adminsecops/controls';
import { runAssessment } from '@adminsecops/engine/browser';
import type { EvidenceBundle } from '@adminsecops/evidence/browser';
import type { AssessmentResult } from '@adminsecops/schemas';
import { ARM_OPERATIONS, validateArmNextLink, validateArmUrl } from './arm-client.js';
import { isQueryableDomain, type TxtResolver } from './dns.js';
import { CollectionCancelledError, GRAPH_BETA_EXCEPTIONS, validateGraphBetaUrl, validateGraphUrl } from './graph-client.js';
import { ExchangeRunnerError, type ExchangeRunResult, type ExchangeRunner } from './exchange-runner.js';
import { collectOnline, collectOnlineEvidence, type CollectOnlineOptions } from './online.js';

/*
 * Synthetic tenant for the connector datasets. Shapes follow the Microsoft Graph v1.0, Azure
 * Resource Manager and Exchange Online PowerShell documentation. No real service is contacted.
 */

const TENANT = '11111111-2222-4333-8444-555555555555';
const OTHER_TENANT = '99999999-2222-4333-8444-555555555555';
const USER = '22222222-3333-4444-8555-666666666666';
const ASSESSMENT = '6f1c1a52-4b7e-4f8e-9a51-0c6f7d2b9e10';
const GRAPH_TOKEN = 'graph-token-value-7a1c';
const ARM_TOKEN = 'arm-token-value-5b2d';
const EXO_TOKEN = 'exchange-token-value-3c4e';
const NOW = new Date('2026-09-22T10:00:00.000Z');
const SUB_A = 'aaaa0001-0000-4000-8000-000000000001';
const SUB_B = 'aaaa0001-0000-4000-8000-000000000002';
const SUB_FOREIGN = 'aaaa0001-0000-4000-8000-000000000009';
const GA = '62e90394-69f5-4237-9190-012177145e10';
const OWNER = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635';

type Handler = (url: URL) => Response | Promise<Response>;
const json = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const failure = (status: number, code: string, text = 'synthetic error PRIVATE-DETAIL'): Response => json({ error: { code, message: text } }, status);
const plan = (servicePlanName: string) => ({ servicePlanId: TENANT, servicePlanName, provisioningStatus: 'Success', appliesTo: 'User' });

function graphRoutes(): Record<string, Handler> {
  return {
    '/v1.0/organization': () =>
      json({ value: [{ id: TENANT, displayName: 'Contoso', onPremisesSyncEnabled: true, onPremisesLastSyncDateTime: '2026-09-22T09:00:00Z', verifiedDomains: [
        { name: 'contoso.example', isDefault: true, isInitial: false, type: 'Managed', capabilities: 'Email, OfficeCommunicationsOnline' },
        { name: 'contoso.onmicrosoft.com', isDefault: false, isInitial: true, type: 'Managed', capabilities: 'Email' },
        { name: 'intranet.contoso.example', isDefault: false, isInitial: false, type: 'Managed', capabilities: 'None' },
      ] }] }),
    '/v1.0/subscribedSkus': () =>
      json({ value: [{ skuId: 'c7df2760-2c81-4ef7-b578-5b5392b571df', skuPartNumber: 'SPE_E5', capabilityStatus: 'Enabled', consumedUnits: 5, prepaidUnits: { enabled: 10 }, servicePlans: [plan('AAD_PREMIUM'), plan('AAD_PREMIUM_P2'), plan('INTUNE_A'), plan('ATP_ENTERPRISE')] }] }),
    '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy': () => json({ isEnabled: false }),
    '/v1.0/policies/authorizationPolicy': () => json({ allowInvitesFrom: 'adminsAndGuestInviters', guestUserRoleId: '2af84b1e-32c8-42b7-82bc-daa82404023b', permissionGrantPolicyIdsAssignedToDefaultUserRole: [], defaultUserRolePermissions: { allowedToCreateApps: false, allowedToCreateSecurityGroups: false, allowedToReadOtherUsers: true } }),
    '/v1.0/policies/authenticationMethodsPolicy': () => json({ policyMigrationState: 'migrationComplete', authenticationMethodConfigurations: [] }),
    '/v1.0/identity/conditionalAccess/policies': () => json({ value: [] }),
    '/v1.0/reports/authenticationMethods/userRegistrationDetails': () => json({ value: [] }),
    '/v1.0/roleManagement/directory/roleDefinitions': () => json({ value: [] }),
    '/v1.0/roleManagement/directory/roleAssignments': () => json({ value: [] }),
    '/v1.0/users': () => json({ value: [] }),
    '/v1.0/groupSettings': () => json({ value: [] }),
    '/v1.0/admin/sharepoint/settings': () => json({ sharingCapability: 'disabled' }),
    '/v1.0/teamwork/teamsAppSettings': () => json({ allowUserRequestsForAppAccess: false, isUserPersonalScopeResourceSpecificConsentEnabled: false }),
    '/v1.0/teams': () => json({ value: [] }),
    '/v1.0/deviceManagement': () => json({ id: 'dm', settings: { secureByDefault: true, deviceComplianceCheckinThresholdDays: 30, isScheduledActionEnabled: true } }),
    '/v1.0/deviceManagement/managedDeviceOverview': () => json({ enrolledDeviceCount: 0, deviceOperatingSystemSummary: { windowsCount: 0, macOSCount: 0, iosCount: 0, androidCount: 0 } }),
    '/v1.0/deviceManagement/deviceCompliancePolicies': () => json({ value: [] }),
    '/v1.0/roleManagement/directory/roleAssignmentScheduleInstances': () =>
      json({ value: [
        { id: 'i1', roleDefinitionId: GA, principalId: USER, directoryScopeId: '/', assignmentType: 'Assigned', memberType: 'Direct', startDateTime: '2025-01-01T00:00:00Z', endDateTime: null },
        { id: 'i2', roleDefinitionId: '194ae4cb-b126-40b2-bd5b-6091b380977d', principalId: USER, directoryScopeId: '/', assignmentType: 'Assigned', memberType: 'Direct', startDateTime: '2025-01-01T00:00:00Z', endDateTime: null },
      ] }),
    '/v1.0/roleManagement/directory/roleEligibilitySchedules': () =>
      json({ value: [{ id: 'e1', roleDefinitionId: GA, principalId: USER, directoryScopeId: '/', memberType: 'Direct', scheduleInfo: { startDateTime: '2025-02-01T00:00:00Z', expiration: { type: 'afterDateTime', endDateTime: '2027-02-01T00:00:00Z' } } }] }),
    '/v1.0/applications': () =>
      json({ value: [{ id: 'app1', appId: 'bbbb0001-0000-4000-8000-000000000001', displayName: 'Payroll', signInAudience: 'AzureADMyOrg', createdDateTime: '2024-01-01T00:00:00Z',
        passwordCredentials: [{ keyId: 'cccc0001-0000-4000-8000-000000000001', displayName: 'ci', startDateTime: '2026-01-01T00:00:00Z', endDateTime: '2026-10-01T00:00:00Z', hint: 'Xy7', secretText: 'SECRET-VALUE-SHOULD-NEVER-APPEAR' }],
        keyCredentials: [{ keyId: 'cccc0001-0000-4000-8000-000000000002', displayName: 'cert', startDateTime: '2026-01-01T00:00:00Z', endDateTime: '2027-01-01T00:00:00Z', type: 'AsymmetricX509Cert', usage: 'Verify', key: 'S0VZLU1BVEVSSUFMLVNIT1VMRC1ORVZFUi1BUFBFQVI=' }] }] }),
    '/v1.0/servicePrincipals': () =>
      json({ value: [{ id: 'sp1', appId: 'bbbb0001-0000-4000-8000-000000000001', displayName: 'Payroll', servicePrincipalType: 'Application', appOwnerOrganizationId: TENANT, accountEnabled: true, passwordCredentials: [], keyCredentials: [] }] }),
    "/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')": () =>
      json({ id: 'ffff0001-0000-4000-8000-000000000001', appId: '00000003-0000-0000-c000-000000000000', displayName: 'Microsoft Graph', appRoles: [{ id: '19dbc75e-c2e2-444c-a770-ec69d8559fc7', value: 'Directory.ReadWrite.All' }] }),
    "/v1.0/servicePrincipals(appId='00000002-0000-0ff1-ce00-000000000000')": () => failure(404, 'Request_ResourceNotFound'),
    '/v1.0/servicePrincipals/ffff0001-0000-4000-8000-000000000001/appRoleAssignedTo': () =>
      json({ value: [{ id: 'grant1', principalId: 'sp1', principalType: 'ServicePrincipal', principalDisplayName: 'Payroll', appRoleId: '19dbc75e-c2e2-444c-a770-ec69d8559fc7', createdDateTime: '2025-05-01T00:00:00Z' }] }),
    '/v1.0/directory/onPremisesSynchronization': () =>
      json({ value: [{ id: TENANT, features: { blockSoftMatchEnabled: true, blockCloudObjectTakeoverThroughHardMatchEnabled: false, passwordSyncEnabled: true } }] }),
    [`/v1.0/directoryObjects/${USER}`]: () => json({ id: USER, displayName: 'Alex', userPrincipalName: 'alex@contoso.example' }),
  };
}

const sub = (id: string, tenantId: string | undefined, state = 'Enabled') => ({ subscriptionId: id, displayName: `Sub ${id.slice(-1)}`, state, ...(tenantId === undefined ? {} : { tenantId }) });

function armRoutes(): Record<string, Handler> {
  const scoped = (id: string, path: string): string => `/subscriptions/${id}${path}`;
  const routes: Record<string, Handler> = {
    '/subscriptions': () => json({ value: [sub(SUB_A, TENANT), sub(SUB_FOREIGN, OTHER_TENANT)] }),
  };
  for (const id of [SUB_A, SUB_B]) {
    routes[scoped(id, ARM_OPERATIONS.roleAssignments.path)] = () =>
      json({ value: [{ id: `/subscriptions/${id}/providers/Microsoft.Authorization/roleAssignments/ra1`, properties: { scope: `/subscriptions/${id}`, roleDefinitionId: `/subscriptions/${id}/providers/Microsoft.Authorization/roleDefinitions/${OWNER}`, principalId: USER, principalType: 'User' } }] });
    routes[scoped(id, ARM_OPERATIONS.roleDefinitions.path)] = () => json({ value: [{ name: OWNER, properties: { roleName: 'Owner', type: 'BuiltInRole' } }] });
    routes[scoped(id, ARM_OPERATIONS.pricings.path)] = () =>
      json({ value: ['VirtualMachines', 'StorageAccounts', 'KeyVaults', 'Arm', 'CloudPosture', 'SqlServers', 'AppServices', 'Containers'].map((name) => ({ name, properties: { pricingTier: 'Standard' } })) });
    routes[scoped(id, ARM_OPERATIONS.securityContacts.path)] = () =>
      json({ value: [{ name: 'default', properties: { emails: 'secops@contoso.example;soc@contoso.example', isEnabled: true, notificationsByRole: { state: 'On', roles: ['Owner'] }, notificationsSources: [{ sourceType: 'Alert', minimalSeverity: 'Medium' }] } }] });
    routes[scoped(id, ARM_OPERATIONS.storageAccounts.path)] = () =>
      json({ value: [{ id: `/subscriptions/${id}/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/stpublic`, name: 'stpublic', location: 'westeurope', kind: 'StorageV2', properties: { allowBlobPublicAccess: true, supportsHttpsTrafficOnly: true, minimumTlsVersion: 'TLS1_2', allowSharedKeyAccess: false, publicNetworkAccess: 'Enabled', networkAcls: { defaultAction: 'Allow' } } }] });
    routes[scoped(id, ARM_OPERATIONS.keyVaults.path)] = () => json({ value: [] });
    routes[scoped(id, ARM_OPERATIONS.networkSecurityGroups.path)] = () =>
      json({ value: [{ id: `/subscriptions/${id}/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg1`, name: 'nsg1', properties: { securityRules: [{ name: 'rdp', properties: { direction: 'Inbound', access: 'Allow', priority: 100, protocol: 'Tcp', sourceAddressPrefix: '*', destinationPortRange: '3389' } }] } }] });
    routes[scoped(id, ARM_OPERATIONS.diagnosticSettings.path)] = () =>
      json({ value: [{ name: 'to-la', properties: { workspaceId: '/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/la', logs: [{ category: 'Administrative', enabled: true }, { category: 'Security', enabled: false }] } }] });
  }
  return routes;
}

interface Mock {
  fetch: typeof globalThis.fetch;
  calls: { url: string; authorization: string | null }[];
}

function mockServices(graph: Record<string, Handler> = {}, arm: Record<string, Handler> = {}): Mock {
  const g = { ...graphRoutes(), ...graph };
  const a = { ...armRoutes(), ...arm };
  const calls: Mock['calls'] = [];
  const fetch = vi.fn(async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const headers = new Headers(init?.headers);
    calls.push({ url: href, authorization: headers.get('authorization') });
    if (init?.method !== 'GET') throw new Error('test fetch: non-GET request');
    const url = new URL(href);
    if (url.origin === 'https://graph.microsoft.com') {
      const handler = g[decodeURIComponent(url.pathname)];
      return handler === undefined ? failure(404, 'Request_ResourceNotFound') : handler(url);
    }
    if (url.origin === 'https://management.azure.com') {
      const handler = a[url.pathname];
      return handler === undefined ? failure(404, 'ResourceNotFound') : handler(url);
    }
    throw new Error(`test fetch: request left the allowlists (${url.origin})`);
  });
  return { fetch, calls };
}

const dns: TxtResolver = {
  resolveTxt: (name) =>
    Promise.resolve(name.startsWith('_dmarc.') ? { status: 'Found', records: ['v=DMARC1; p=reject'] } : { status: 'Found', records: ['v=spf1 -all'] }),
};

function options(mock: Mock, extra: Partial<CollectOnlineOptions> = {}): CollectOnlineOptions {
  return { tenantId: TENANT, assessmentId: ASSESSMENT, accessToken: GRAPH_TOKEN, fetch: mock.fetch, now: () => NOW, dnsResolver: dns, azure: { state: 'connected', accessToken: ARM_TOKEN }, ...extra };
}

const assess = (bundle: EvidenceBundle): AssessmentResult => runAssessment(bundle, CONTROL_LIBRARY, { processedAt: NOW });
function status(result: AssessmentResult, id: string) {
  const found = result.results.find((r) => r.controlId === id);
  if (found === undefined) throw new Error(`control ${id} missing`);
  return found.status;
}
function dataset(bundle: EvidenceBundle, id: string) {
  const d = bundle.datasets.get(id);
  if (d === undefined) throw new Error(`dataset ${id} missing`);
  return d;
}
const issue = (bundle: EvidenceBundle, datasetId: string, code: string) => bundle.issues.find((i) => i.datasetId === datasetId && i.code === code);
const text = (files: ReadonlyMap<string, Uint8Array>): string => [...files.values()].map((b) => new TextDecoder().decode(b)).join('\n');
const AZURE_CONTROLS = ['AZ-DEF-001', 'AZ-DEF-002', 'AZ-KV-001', 'AZ-KV-002', 'AZ-LOG-001', 'AZ-NET-001', 'AZ-NET-002', 'AZ-RBAC-001', 'AZ-RBAC-002', 'AZ-STG-001', 'AZ-STG-002', 'AZ-STG-003'];
const AZURE_DATASETS = ['azure.subscriptions', 'azure.roleAssignments', 'azure.defenderPlans', 'azure.securityContacts', 'azure.storageAccounts', 'azure.keyVaults', 'azure.networkSecurityGroups', 'azure.activityLogDiagnostics'];

// ---------------------------------------------------------------------------------------------
// Azure Resource Manager
// ---------------------------------------------------------------------------------------------

describe('Azure Resource Manager connector', () => {
  it('collects tenant-bound subscriptions and evaluates all twelve Azure controls', async () => {
    const mock = mockServices();
    const { bundle, files } = await collectOnlineEvidence(options(mock));
    for (const id of AZURE_DATASETS) expect(dataset(bundle, id).state, id).toBe('available');
    const result = assess(bundle);
    for (const id of AZURE_CONTROLS) expect(['PASS', 'FAIL', 'REVIEW', 'NOT_APPLICABLE'], id).toContain(status(result, id));
    expect(status(result, 'AZ-STG-001')).toBe('FAIL'); // anonymous blob access allowed
    expect(status(result, 'AZ-NET-001')).not.toBe('PASS'); // RDP open to the internet
    expect(status(result, 'AZ-KV-001')).toBe('NOT_APPLICABLE'); // no key vaults
    // Only the verified tenant's subscription was read; the foreign one was excluded and never requested.
    expect(mock.calls.some((c) => c.url.includes(SUB_FOREIGN))).toBe(false);
    expect(issue(bundle, 'azure.subscriptions', 'SUBSCRIPTIONS_OTHER_TENANT')).toBeDefined();
    expect((dataset(bundle, 'azure.subscriptions').data as unknown[]).length).toBe(1);
    // Role and principal names are resolved (principal through Graph with the Graph token).
    const ra = (dataset(bundle, 'azure.roleAssignments').data as { roleDefinitionName: string; principalSignInName: string }[])[0];
    expect(ra?.roleDefinitionName).toBe('Owner');
    expect(ra?.principalSignInName).toBe('alex@contoso.example');
    // Security contact addresses are never stored; only their number.
    expect(text(files)).not.toContain('secops@contoso.example');
    expect((dataset(bundle, 'azure.securityContacts').data as { contacts: { emailCount: number }[] }[])[0]?.contacts[0]?.emailCount).toBe(2);
  });

  it('never sends the Graph token to ARM or the ARM token to Graph, and stores neither', async () => {
    const mock = mockServices();
    const { files } = await collectOnlineEvidence(options(mock));
    const arm = mock.calls.filter((c) => c.url.startsWith('https://management.azure.com/'));
    const graph = mock.calls.filter((c) => c.url.startsWith('https://graph.microsoft.com/'));
    expect(arm.length).toBeGreaterThan(8);
    expect(arm.every((c) => c.authorization === `Bearer ${ARM_TOKEN}`)).toBe(true);
    expect(graph.every((c) => c.authorization === `Bearer ${GRAPH_TOKEN}`)).toBe(true);
    expect(text(files)).not.toContain(ARM_TOKEN);
    expect(text(files)).not.toContain(GRAPH_TOKEN);
    // Every ARM URL used an allow-listed operation and api-version.
    for (const c of arm) expect(validateArmUrl(c.url), c.url).toBeDefined();
  });

  it('refuses an ARM token identical to the Graph token (wrong audience) without calling ARM', async () => {
    const mock = mockServices();
    const bundle = await collectOnline(options(mock, { azure: { state: 'connected', accessToken: GRAPH_TOKEN } }));
    expect(mock.calls.some((c) => c.url.startsWith('https://management.azure.com/'))).toBe(false);
    for (const id of AZURE_DATASETS) expect(dataset(bundle, id).collectionStatus).toBe('NotCollected');
    expect(issue(bundle, 'azure.subscriptions', 'CONNECTOR_UNAVAILABLE')).toBeDefined();
  });

  it('reports not connected, consent required and expired connectors distinctly and never as passing', async () => {
    for (const [azure, code, collectionStatus] of [
      [undefined, 'CONNECTOR_NOT_CONNECTED', 'NotCollected'],
      [{ state: 'consent-required', reason: 'Consent missing.' }, 'CONNECTOR_CONSENT_REQUIRED', 'Unauthorized'],
      [{ state: 'expired', reason: 'Reconnect.' }, 'CONNECTOR_EXPIRED', 'NotCollected'],
      [{ state: 'unavailable', reason: 'Disabled.' }, 'CONNECTOR_UNAVAILABLE', 'NotCollected'],
    ] as const) {
      const mock = mockServices();
      const opts = options(mock);
      if (azure === undefined) delete opts.azure;
      else opts.azure = azure;
      const bundle = await collectOnline(opts);
      expect(dataset(bundle, 'azure.storageAccounts').collectionStatus).toBe(collectionStatus);
      expect(issue(bundle, 'azure.storageAccounts', code)).toBeDefined();
      const result = assess(bundle);
      for (const id of AZURE_CONTROLS) expect(status(result, id), `${code} ${id}`).toBe('NOT_ASSESSED');
      expect(mock.calls.some((c) => c.url.startsWith('https://management.azure.com/'))).toBe(false);
    }
  });

  it('reports an account without Reader rights (no visible subscriptions) as not assessed', async () => {
    const bundle = await collectOnline(options(mockServices({}, { '/subscriptions': () => json({ value: [] }) })));
    expect(dataset(bundle, 'azure.subscriptions').collectionStatus).toBe('Success');
    expect(issue(bundle, 'azure.subscriptions', 'NO_VISIBLE_SUBSCRIPTIONS')).toBeDefined();
    for (const id of AZURE_DATASETS.slice(1)) {
      expect(dataset(bundle, id).collectionStatus, id).toBe('Unauthorized');
      expect(issue(bundle, id, 'NO_ACCESSIBLE_SUBSCRIPTIONS'), id).toBeDefined();
    }
    const result = assess(bundle);
    for (const id of AZURE_CONTROLS) expect(status(result, id), id).toBe('NOT_ASSESSED');
  });

  it('maps 403 on every subscription to Unauthorized and 403 on one subscription to Partial', async () => {
    const storage = ARM_OPERATIONS.storageAccounts.path;
    const allDenied = await collectOnline(options(mockServices({}, { [`/subscriptions/${SUB_A}${storage}`]: () => failure(403, 'AuthorizationFailed') })));
    expect(dataset(allDenied, 'azure.storageAccounts').collectionStatus).toBe('Unauthorized');
    expect(issue(allDenied, 'azure.storageAccounts', 'READER_REQUIRED')).toBeDefined();
    expect(JSON.stringify(allDenied.issues)).not.toContain('PRIVATE-DETAIL');
    for (const id of ['AZ-STG-001', 'AZ-STG-002', 'AZ-STG-003']) expect(status(assess(allDenied), id)).toBe('NOT_ASSESSED');

    const oneDenied = await collectOnline(options(mockServices({}, {
      '/subscriptions': () => json({ value: [sub(SUB_A, TENANT), sub(SUB_B, TENANT)] }),
      [`/subscriptions/${SUB_B}${storage}`]: () => failure(403, 'AuthorizationFailed'),
    })));
    expect(dataset(oneDenied, 'azure.storageAccounts').collectionStatus).toBe('Partial');
    expect(oneDenied.issues.find((i) => i.datasetId === 'azure.storageAccounts' && i.target === `subscription ${SUB_B}`)).toBeDefined();
    expect(status(assess(oneDenied), 'AZ-STG-002')).not.toBe('PASS');
  });

  it('fails a dataset on 404 in every subscription and on a missing required field', async () => {
    const missing = await collectOnline(options(mockServices({}, { [`/subscriptions/${SUB_A}${ARM_OPERATIONS.keyVaults.path}`]: () => failure(404, 'ResourceNotFound') })));
    expect(dataset(missing, 'azure.keyVaults').collectionStatus).toBe('Failed');
    expect(issue(missing, 'azure.keyVaults', 'ALL_SUBSCRIPTIONS_FAILED')).toBeDefined();

    const invalid = await collectOnline(options(mockServices({}, { [`/subscriptions/${SUB_A}${ARM_OPERATIONS.pricings.path}`]: () => json({ value: [{ name: 'VirtualMachines', properties: {} }] }) })));
    expect(dataset(invalid, 'azure.defenderPlans').collectionStatus).toBe('Failed');
    expect(issue(invalid, 'azure.defenderPlans', 'DATA_INVALID')).toBeDefined();
    expect(status(assess(invalid), 'AZ-DEF-001')).toBe('NOT_ASSESSED');
  });

  it('keeps earlier pages but marks the dataset Partial when a later ARM page fails', async () => {
    const path = `/subscriptions/${SUB_A}${ARM_OPERATIONS.networkSecurityGroups.path}`;
    const bundle = await collectOnline(options(mockServices({}, {
      [path]: (url) =>
        url.searchParams.has('$skiptoken')
          ? failure(500, 'InternalServerError')
          : json({ value: [], nextLink: `https://management.azure.com${path}?api-version=${ARM_OPERATIONS.networkSecurityGroups.apiVersion}&$skiptoken=p2` }),
    })));
    expect(dataset(bundle, 'azure.networkSecurityGroups').collectionStatus).toBe('Partial');
    expect(issue(bundle, 'azure.networkSecurityGroups', 'PAGE_FAILED')).toBeDefined();
    expect(status(assess(bundle), 'AZ-NET-001')).not.toBe('PASS');
  });

  it('never follows a malicious nextLink (other host, other subscription, other api-version)', async () => {
    const path = `/subscriptions/${SUB_A}${ARM_OPERATIONS.storageAccounts.path}`;
    for (const next of [
      'https://attacker.example/steal?api-version=2023-05-01',
      `https://management.azure.com/subscriptions/${SUB_B}${ARM_OPERATIONS.storageAccounts.path}?api-version=2023-05-01&$skiptoken=x`,
      `https://management.azure.com${path}?api-version=2099-01-01&$skiptoken=x`,
      `https://management.azure.com${path}?api-version=2023-05-01&$filter=x`,
      `http://management.azure.com${path}?api-version=2023-05-01`,
    ]) {
      const mock = mockServices({}, { [path]: () => json({ value: [], nextLink: next }) });
      const bundle = await collectOnline(options(mock));
      expect(mock.calls.some((c) => c.url === next || c.url.includes('attacker') || c.url.includes(SUB_B)), next).toBe(false);
      expect(dataset(bundle, 'azure.storageAccounts').collectionStatus, next).toBe('Partial');
      expect(issue(bundle, 'azure.storageAccounts', 'NEXT_LINK_REJECTED'), next).toBeDefined();
    }
  });

  it('caps the number of subscriptions read (fan-out limit) and reports the rest as not read', async () => {
    const mock = mockServices({}, { '/subscriptions': () => json({ value: [sub(SUB_A, TENANT), sub(SUB_B, TENANT)] }) });
    const bundle = await collectOnline(options(mock, { limits: { maxFanoutRequests: 1 } }));
    expect(mock.calls.some((c) => c.url.includes(`/subscriptions/${SUB_B}/providers/Microsoft.Storage`))).toBe(false);
    expect(dataset(bundle, 'azure.storageAccounts').collectionStatus).toBe('Partial');
    expect(issue(bundle, 'azure.storageAccounts', 'FANOUT_LIMIT')).toBeDefined();
  });

  it('excludes subscriptions without a tenant ID and marks the list incomplete', async () => {
    const bundle = await collectOnline(options(mockServices({}, { '/subscriptions': () => json({ value: [sub(SUB_A, TENANT), sub(SUB_B, undefined)] }) })));
    expect(dataset(bundle, 'azure.subscriptions').collectionStatus).toBe('Partial');
    expect(issue(bundle, 'azure.storageAccounts', 'SUBSCRIPTION_LIST_INCOMPLETE')).toBeDefined();
  });

  it('reports a refused subscription list (for example a token for another resource) as Unauthorized everywhere', async () => {
    const bundle = await collectOnline(options(mockServices({}, { '/subscriptions': () => failure(401, 'InvalidAuthenticationTokenAudience') })));
    expect(dataset(bundle, 'azure.subscriptions').collectionStatus).toBe('Unauthorized');
    expect(dataset(bundle, 'azure.roleAssignments').collectionStatus).toBe('Unauthorized');
    expect(issue(bundle, 'azure.roleAssignments', 'SUBSCRIPTIONS_UNAUTHORIZED')).toBeDefined();
  });

  it('propagates cancellation during ARM collection and produces no bundle', async () => {
    const controller = new AbortController();
    const mock = mockServices({}, {
      [`/subscriptions/${SUB_A}${ARM_OPERATIONS.pricings.path}`]: () => {
        controller.abort();
        return json({ value: [] });
      },
    });
    await expect(collectOnline(options(mock, { signal: controller.signal }))).rejects.toSatisfy((e: unknown) => e instanceof AdminSecOpsError && e.code === 'COLLECTION_CANCELLED');
  });

  it('allows only fixed ARM operations and api-versions', () => {
    const ok = `https://management.azure.com/subscriptions/${SUB_A}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01`;
    expect(validateArmUrl(ok)).toBe(ok);
    expect(validateArmUrl('https://management.azure.com/subscriptions?api-version=2022-12-01&%24skiptoken=abc')).toBeDefined();
    for (const bad of [
      'http://management.azure.com/subscriptions?api-version=2022-12-01',
      'https://management.azure.com:444/subscriptions?api-version=2022-12-01',
      'https://user:pw@management.azure.com/subscriptions?api-version=2022-12-01',
      'https://management.azure.com.attacker.example/subscriptions?api-version=2022-12-01',
      'https://management.azure.com/subscriptions?api-version=2022-12-01&api-version=2022-12-01',
      'https://management.azure.com/subscriptions',
      `https://management.azure.com/subscriptions/${SUB_A}/providers/Microsoft.Storage/storageAccounts/x/listKeys?api-version=2023-05-01`,
      `https://management.azure.com/subscriptions/${SUB_A}/providers/Microsoft.Compute/virtualMachines?api-version=2023-05-01`,
      `https://management.azure.com/subscriptions/not-a-guid/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01`,
      `https://management.azure.com/subscriptions/${SUB_A}/../${SUB_B}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01`,
      `https://management.azure.com/subscriptions/${SUB_A}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01#x`,
      'https://graph.microsoft.com/v1.0/organization',
    ]) {
      expect(validateArmUrl(bad), bad).toBeUndefined();
    }
    expect(validateArmNextLink(`https://management.azure.com/subscriptions/${SUB_B}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01`, ok)).toBeUndefined();
    expect(validateArmNextLink(`${ok}&$skiptoken=2`, ok)).toBeDefined();
  });
});

// ---------------------------------------------------------------------------------------------
// Exchange Online
// ---------------------------------------------------------------------------------------------

function exchangeResult(overrides: Partial<ExchangeRunResult> = {}, operations: ExchangeRunResult['operations'] = {}): ExchangeRunResult {
  return {
    kind: 'adminsecops.exchange.result',
    status: 'ok',
    connectedTenantId: TENANT.toUpperCase(),
    operations: {
      organizationConfig: { status: 'ok', truncated: false, items: [{ AuditDisabled: false, OAuth2ClientProfileEnabled: true, CustomerLockBoxEnabled: false, MailTipsExternalRecipientsTipsEnabled: true }] },
      transportConfig: { status: 'ok', truncated: false, items: [{ SmtpClientAuthenticationDisabled: true }] },
      adminAuditLogConfig: { status: 'ok', truncated: false, items: [{ UnifiedAuditLogIngestionEnabled: true }] },
      acceptedDomains: { status: 'ok', truncated: false, items: [
        { DomainName: 'contoso.example', DomainType: 'Authoritative', Default: true, IsCoexistenceDomain: false },
        { DomainName: 'contoso.onmicrosoft.com', DomainType: 'Authoritative', Default: false, IsCoexistenceDomain: false },
        { DomainName: 'relay.contoso.example', DomainType: 'InternalRelay', Default: false, IsCoexistenceDomain: false },
      ] },
      dkimSigningConfigs: { status: 'ok', truncated: false, items: [{ Domain: 'contoso.example', Enabled: true, Status: 'Valid' }] },
      outboundSpamPolicies: { status: 'ok', truncated: false, items: [{ Name: 'Default', IsDefault: true, AutoForwardingMode: 'Off' }] },
      remoteDomains: { status: 'ok', truncated: false, items: [{ Name: 'Default', DomainName: '*', AutoForwardEnabled: false }] },
      mailboxForwarding: { status: 'ok', truncated: false, items: [] },
      smtpAuthMailboxes: { status: 'ok', truncated: false, items: [{ PrimarySmtpAddress: 'scanner@contoso.example', SmtpClientAuthenticationDisabled: false }] },
      atpPolicy: { status: 'ok', truncated: false, items: [{ EnableATPForSPOTeamsODB: true, EnableSafeDocs: true, AllowSafeDocsOpen: false }] },
      ...operations,
    },
    ...overrides,
  };
}

function fakeRunner(result: ExchangeRunResult | Error, available = true): ExchangeRunner & { run: ReturnType<typeof vi.fn> } {
  return {
    status: vi.fn(() => Promise.resolve({ available, reason: available ? 'ok' : 'PowerShell is not installed.' })),
    run: vi.fn(() => (result instanceof Error ? Promise.reject(result) : Promise.resolve(result))),
  };
}

const EXCHANGE_DATASETS = ['exchange.organizationConfig', 'exchange.transportConfig', 'exchange.adminAuditLogConfig', 'exchange.acceptedDomains', 'exchange.dkimSigningConfigs', 'exchange.outboundSpamPolicies', 'exchange.remoteDomains', 'exchange.mailboxForwarding', 'exchange.smtpAuthMailboxes', 'exchange.atpPolicy'];
const exchange = (runner: ExchangeRunner) => ({ state: 'connected' as const, accessToken: EXO_TOKEN, userPrincipalName: 'admin@contoso.example', runner });

describe('Exchange Online connector', () => {
  it('collects every Exchange dataset through one fixed runner call and evaluates the email controls', async () => {
    const runner = fakeRunner(exchangeResult());
    const { bundle, files } = await collectOnlineEvidence(options(mockServices(), { exchange: exchange(runner) }));
    for (const id of EXCHANGE_DATASETS) expect(dataset(bundle, id).collectionStatus, id).toBe('Success');
    expect(runner.run).toHaveBeenCalledTimes(1);
    expect(runner.run).toHaveBeenCalledWith(expect.objectContaining({ tenantId: TENANT, userPrincipalName: 'admin@contoso.example', accessToken: EXO_TOKEN }), undefined);
    const result = assess(bundle);
    expect(status(result, 'M365-EXO-001')).toBe('PASS');
    expect(status(result, 'M365-AUD-001')).toBe('PASS');
    expect(status(result, 'M365-MAIL-001')).toBe('PASS');
    // The DNS domain list came from the authoritative accepted domains (not relay, not onmicrosoft.com).
    const domains = (dataset(bundle, 'exchange.mailDnsRecords').data as { domain: string }[]).map((d) => d.domain);
    expect(domains).toEqual(['contoso.example']);
    expect(issue(bundle, 'exchange.mailDnsRecords', 'DOMAINS_FROM_VERIFIED_DOMAINS')).toBeUndefined();
    expect(text(files)).not.toContain(EXO_TOKEN);
  });

  it('reports a missing server runtime as unavailable without starting a collection', async () => {
    const runner = fakeRunner(exchangeResult(), false);
    const bundle = await collectOnline(options(mockServices(), { exchange: exchange(runner) }));
    expect(runner.run).not.toHaveBeenCalled();
    for (const id of EXCHANGE_DATASETS.filter((d) => d !== 'exchange.atpPolicy')) {
      expect(dataset(bundle, id).collectionStatus, id).toBe('NotCollected');
      expect(issue(bundle, id, 'CONNECTOR_UNAVAILABLE'), id).toBeDefined();
    }
    expect(status(assess(bundle), 'M365-EXO-001')).toBe('NOT_ASSESSED');
  });

  it('maps a refused Exchange connection and a denied cmdlet to Unauthorized', async () => {
    const refused = await collectOnline(options(mockServices(), { exchange: exchange(fakeRunner(exchangeResult({ status: 'connect-unauthorized', operations: {} }))) }));
    for (const id of EXCHANGE_DATASETS.filter((d) => d !== 'exchange.atpPolicy')) expect(dataset(refused, id).collectionStatus, id).toBe('Unauthorized');
    expect(issue(refused, 'exchange.transportConfig', 'EXCHANGE_CONNECT_UNAUTHORIZED')).toBeDefined();

    const denied = await collectOnline(options(mockServices(), { exchange: exchange(fakeRunner(exchangeResult({}, { transportConfig: { status: 'unauthorized' } }))) }));
    expect(dataset(denied, 'exchange.transportConfig').collectionStatus).toBe('Unauthorized');
    expect(dataset(denied, 'exchange.organizationConfig').collectionStatus).toBe('Success');
    expect(status(assess(denied), 'M365-EXO-001')).toBe('NOT_ASSESSED');
  });

  it('discards everything when the Exchange session tenant is not the verified tenant', async () => {
    for (const connectedTenantId of [OTHER_TENANT, null]) {
      const bundle = await collectOnline(options(mockServices(), { exchange: exchange(fakeRunner(exchangeResult({ connectedTenantId }))) }));
      for (const id of EXCHANGE_DATASETS.filter((d) => d !== 'exchange.atpPolicy')) {
        expect(dataset(bundle, id).collectionStatus, id).toBe('Failed');
        expect(issue(bundle, id, 'EXCHANGE_TENANT_NOT_VERIFIED'), id).toBeDefined();
      }
    }
  });

  it('marks truncated lists Partial and missing values Failed instead of assuming defaults', async () => {
    const bundle = await collectOnline(options(mockServices(), { exchange: exchange(fakeRunner(exchangeResult({}, {
      mailboxForwarding: { status: 'ok', truncated: true, items: [] },
      organizationConfig: { status: 'ok', truncated: false, items: [{ AuditDisabled: null, OAuth2ClientProfileEnabled: true }] },
      remoteDomains: { status: 'ok', truncated: false, items: [] },
      adminAuditLogConfig: { status: 'ok', truncated: false, items: [] },
    }))) }));
    expect(dataset(bundle, 'exchange.mailboxForwarding').collectionStatus).toBe('Partial');
    expect(issue(bundle, 'exchange.mailboxForwarding', 'RESULT_LIMIT')).toBeDefined();
    expect(dataset(bundle, 'exchange.organizationConfig').collectionStatus).toBe('Failed');
    expect(dataset(bundle, 'exchange.adminAuditLogConfig').collectionStatus).toBe('Failed');
    const result = assess(bundle);
    expect(status(result, 'M365-EXO-005')).not.toBe('PASS');
    expect(status(result, 'M365-AUD-002')).toBe('NOT_ASSESSED');
  });

  it('treats a missing Get-AtpPolicyForO365 as not licensed, and no ATP licence as not applicable', async () => {
    const bundle = await collectOnline(options(mockServices(), { exchange: exchange(fakeRunner(exchangeResult({}, { atpPolicy: { status: 'not-available' } }))) }));
    expect(dataset(bundle, 'exchange.atpPolicy').collectionStatus).toBe('NotApplicable');
    expect(issue(bundle, 'exchange.atpPolicy', 'FEATURE_NOT_AVAILABLE')).toBeDefined();
  });

  it('reports a runner timeout as a collection failure and propagates cancellation', async () => {
    const timedOut = await collectOnline(options(mockServices(), { exchange: exchange(fakeRunner(new ExchangeRunnerError('TIMEOUT', 'The Exchange Online collection exceeded its time limit.'))) }));
    expect(dataset(timedOut, 'exchange.transportConfig').collectionStatus).toBe('Failed');
    expect(issue(timedOut, 'exchange.transportConfig', 'EXCHANGE_TIMEOUT')).toBeDefined();
    await expect(collectOnline(options(mockServices(), { exchange: exchange(fakeRunner(new CollectionCancelledError())) }))).rejects.toBeInstanceOf(CollectionCancelledError);
  });
});

// ---------------------------------------------------------------------------------------------
// Public mail DNS
// ---------------------------------------------------------------------------------------------

describe('public mail DNS records', () => {
  it('checks only Email-capable verified domains when Exchange is not connected, with provenance limits', async () => {
    const seen: string[] = [];
    const resolver: TxtResolver = { resolveTxt: (name) => { seen.push(name); return dns.resolveTxt(name); } };
    const bundle = await collectOnline(options(mockServices(), { dnsResolver: resolver }));
    expect(seen.sort()).toEqual(['_dmarc.contoso.example', 'contoso.example']);
    expect(issue(bundle, 'exchange.mailDnsRecords', 'DOMAINS_FROM_VERIFIED_DOMAINS')).toBeDefined();
    expect(issue(bundle, 'exchange.mailDnsRecords', 'DNS_PROVENANCE')?.message).toContain('do not show Exchange accepted domains or DKIM');
    const result = assess(bundle);
    expect(status(result, 'M365-MAIL-001')).toBe('NOT_ASSESSED');
  });

  it('never treats failed lookups as passing and fails the dataset when every lookup fails', async () => {
    const failing: TxtResolver = { resolveTxt: () => Promise.resolve({ status: 'Error', records: [] }) };
    const bundle = await collectOnline(options(mockServices(), { dnsResolver: failing }));
    expect(dataset(bundle, 'exchange.mailDnsRecords').collectionStatus).toBe('Failed');
    const result = assess(bundle);
    expect(status(result, 'M365-MAIL-002')).toBe('NOT_ASSESSED');
    expect(status(result, 'M365-MAIL-003')).toBe('NOT_ASSESSED');

    const dmarcOnlyFails: TxtResolver = { resolveTxt: (name) => (name.startsWith('_dmarc.') ? Promise.resolve({ status: 'Error', records: [] }) : dns.resolveTxt(name)) };
    const partial = assess(await collectOnline(options(mockServices(), { dnsResolver: dmarcOnlyFails })));
    expect(status(partial, 'M365-MAIL-002')).toBe('PASS');
    expect(status(partial, 'M365-MAIL-003')).toBe('NOT_ASSESSED');
  });

  it('accepts only DNS host names', () => {
    for (const ok of ['contoso.example', 'mail.contoso-1.example', 'xn--bcher-kva.example']) expect(isQueryableDomain(ok), ok).toBe(true);
    for (const bad of ['localhost', '', 'contoso..example', '-bad.example', '10.0.0.1', 'a b.example', 'contoso.example.', '*.contoso.example', `${'a'.repeat(64)}.example`]) {
      expect(isQueryableDomain(bad), bad).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------------------------
// Entra datasets added in this release
// ---------------------------------------------------------------------------------------------

describe('Entra PIM, application and synchronization datasets', () => {
  it('collects the six datasets, maps PIM schedules and never stores credential secrets', async () => {
    const { bundle, files } = await collectOnlineEvidence(options(mockServices()));
    for (const id of ['entra.roleAssignmentScheduleInstances', 'entra.roleEligibilitySchedules', 'entra.applications', 'entra.servicePrincipals', 'entra.apiPermissionGrants', 'entra.onPremisesSynchronization']) {
      expect(dataset(bundle, id).collectionStatus, id).toBe('Success');
    }
    const eligible = (dataset(bundle, 'entra.roleEligibilitySchedules').data as { startDateTime: string; endDateTime: string }[])[0];
    expect(eligible?.endDateTime).toBe('2027-02-01T00:00:00Z');
    const all = text(files);
    for (const secret of ['SECRET-VALUE-SHOULD-NEVER-APPEAR', 'S0VZLU1BVEVSSUFMLVNIT1VMRC1ORVZFUi1BUFBFQVI=', '"hint"']) expect(all).not.toContain(secret);
    // The Exchange Online resource principal is absent in this tenant: noted, not a failure.
    expect(issue(bundle, 'entra.apiPermissionGrants', 'RESOURCE_NOT_PRESENT')).toBeDefined();
    const result = assess(bundle);
    expect(status(result, 'ENTRA-PRIV-004')).toBe('FAIL'); // permanent Global Administrator and Security Administrator
    expect(status(result, 'HYB-SYNC-001')).toBe('FAIL'); // hard-match takeover not blocked
    expect(status(result, 'HYB-SYNC-002')).toBe('PASS');
  });

  it('collects PIM pages when the service rejects wildcard language negotiation', async () => {
    const mock = mockServices();
    const fetch: typeof globalThis.fetch = (input, init) => {
      if (/roleAssignmentScheduleInstances|roleEligibilitySchedules/.test(String(input)) &&
          new Headers(init?.headers).get('accept-language') !== 'en-US') {
        return Promise.resolve(failure(400, 'UnknownError', 'CultureNotFoundException: * is an invalid culture identifier.'));
      }
      return mock.fetch(input, init);
    };
    const bundle = await collectOnline(options(mock, { fetch }));
    expect(dataset(bundle, 'entra.roleAssignmentScheduleInstances').collectionStatus).toBe('Success');
    expect(dataset(bundle, 'entra.roleEligibilitySchedules').collectionStatus).toBe('Success');
  });

  it('marks PIM datasets NotApplicable without requests when P2 / ID Governance is not licensed', async () => {
    const mock = mockServices({
      '/v1.0/subscribedSkus': () => json({ value: [{ skuId: 'c7df2760-2c81-4ef7-b578-5b5392b571df', skuPartNumber: 'SPE_E3', capabilityStatus: 'Enabled', consumedUnits: 1, prepaidUnits: { enabled: 1 }, servicePlans: [plan('AAD_PREMIUM')] }] }),
    });
    const bundle = await collectOnline(options(mock));
    expect(dataset(bundle, 'entra.roleAssignmentScheduleInstances').collectionStatus).toBe('NotApplicable');
    expect(mock.calls.some((c) => c.url.includes('roleAssignmentScheduleInstances') || c.url.includes('roleEligibilitySchedules'))).toBe(false);
    expect(status(assess(bundle), 'ENTRA-PRIV-004')).toBe('NOT_APPLICABLE');
  });

  it('reports directory synchronization as Unauthorized (never passing) for roles other than Global Administrator', async () => {
    const bundle = await collectOnline(options(mockServices({ '/v1.0/directory/onPremisesSynchronization': () => failure(403, 'Authorization_RequestDenied') }), { grantedScopes: ['Directory.Read.All', 'Organization.Read.All'] }));
    expect(dataset(bundle, 'entra.onPremisesSynchronization').collectionStatus).toBe('Unauthorized');
    expect(issue(bundle, 'entra.onPremisesSynchronization', 'UNAUTHORIZED')?.message).toContain('OnPremDirectorySynchronization.Read.All');
    const result = assess(bundle);
    expect(status(result, 'HYB-SYNC-001')).toBe('NOT_ASSESSED');
    expect(status(result, 'HYB-SYNC-002')).toBe('NOT_ASSESSED');
  });

  it('does not report application consent gaps for scopes the collector does not use', async () => {
    const bundle = await collectOnline(options(mockServices({ '/v1.0/applications': () => failure(403, 'Authorization_RequestDenied') }), { grantedScopes: ['Directory.Read.All'] }));
    expect(dataset(bundle, 'entra.applications').collectionStatus).toBe('Unauthorized');
    expect(issue(bundle, 'entra.applications', 'UNAUTHORIZED')?.message).not.toContain('Delegated consent was not granted');
  });

  it('marks credential lists that were not returned as Partial, and a denied grant read as Unauthorized', async () => {
    const partial = await collectOnline(options(mockServices({ '/v1.0/applications': () => json({ value: [{ id: 'app1', appId: 'bbbb0001-0000-4000-8000-000000000001', displayName: 'Payroll' }] }) })));
    expect(dataset(partial, 'entra.applications').collectionStatus).toBe('Partial');
    expect(issue(partial, 'entra.applications', 'CREDENTIALS_MISSING')).toBeDefined();
    expect(status(assess(partial), 'ENTRA-APP-003')).not.toBe('PASS');

    const denied = await collectOnline(options(mockServices({ "/v1.0/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')": () => failure(403, 'Authorization_RequestDenied') })));
    expect(dataset(denied, 'entra.apiPermissionGrants').collectionStatus).toBe('Unauthorized');
  });

  it('keeps earlier PIM pages but marks the dataset Partial when a later page fails', async () => {
    const path = '/v1.0/roleManagement/directory/roleAssignmentScheduleInstances';
    const bundle = await collectOnline(options(mockServices({
      [path]: (url) => (url.searchParams.has('$skiptoken') ? failure(503, 'ServiceUnavailable') : json({ value: [], '@odata.nextLink': `https://graph.microsoft.com${path}?$skiptoken=2` })),
    }), { limits: { maxRetries: 0 } }));
    expect(dataset(bundle, 'entra.roleAssignmentScheduleInstances').collectionStatus).toBe('Partial');
    expect(status(assess(bundle), 'ENTRA-PRIV-004')).not.toBe('PASS');
  });
});

// ---------------------------------------------------------------------------------------------
// Intune tenant compliance settings
// ---------------------------------------------------------------------------------------------

describe('Intune settings with the single Graph beta exception', () => {
  const betaSettings = (body: unknown, status = 200): Record<string, Handler> => ({
    '/v1.0/deviceManagement': () => json({ id: 'dm' }),
    '/beta/deviceManagement/settings': () => (status === 200 ? json(body) : failure(status, 'Forbidden')),
  });

  function graphWithBeta(routes: Record<string, Handler>): Mock {
    const mock = mockServices();
    const base = mock.fetch;
    const fetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      const url = new URL(href);
      const handler = routes[url.pathname];
      if (url.origin === 'https://graph.microsoft.com' && handler !== undefined) {
        mock.calls.push({ url: href, authorization: new Headers(init?.headers).get('authorization') });
        return handler(url);
      }
      return base(input, init);
    });
    return { fetch, calls: mock.calls };
  }

  it('reads settings from the beta property only after both v1.0 requests omit them', async () => {
    const mock = graphWithBeta(betaSettings({ '@odata.context': 'x', secureByDefault: true, deviceComplianceCheckinThresholdDays: 30, isScheduledActionEnabled: true }));
    const bundle = await collectOnline(options(mock));
    expect(dataset(bundle, 'intune.settings').collectionStatus).toBe('Success');
    expect(issue(bundle, 'intune.settings', 'GRAPH_BETA_SOURCE')).toBeDefined();
    const beta = mock.calls.filter((c) => c.url.includes('/beta/'));
    expect(beta.map((c) => c.url)).toEqual(['https://graph.microsoft.com/beta/deviceManagement/settings']);
    expect(status(assess(bundle), 'INTUNE-CMP-001')).toBe('PASS');
  });

  it('never calls beta when v1.0 returns the settings', async () => {
    const mock = mockServices();
    await collectOnline(options(mock));
    expect(mock.calls.some((c) => c.url.includes('/beta/'))).toBe(false);
  });

  it('reports a denied beta read as Unauthorized and an empty beta response as a service gap, never a default', async () => {
    const denied = await collectOnline(options(graphWithBeta(betaSettings({}, 403))));
    expect(dataset(denied, 'intune.settings').collectionStatus).toBe('Unauthorized');
    const empty = await collectOnline(options(graphWithBeta(betaSettings({ '@odata.context': 'x' }))));
    expect(dataset(empty, 'intune.settings').collectionStatus).toBe('Failed');
    expect(empty.issues.find((i) => i.datasetId === 'intune.settings')?.message).toContain('not a missing consent');
    expect(status(assess(empty), 'INTUNE-CMP-001')).toBe('NOT_ASSESSED');
    const noDefault = await collectOnline(options(graphWithBeta(betaSettings({ deviceComplianceCheckinThresholdDays: 30 }))));
    expect(dataset(noDefault, 'intune.settings').collectionStatus).toBe('Failed');
  });

  it('allows exactly one beta path, without query strings, and never as a v1.0 nextLink', () => {
    expect([...GRAPH_BETA_EXCEPTIONS]).toEqual(['/beta/deviceManagement/settings']);
    expect(validateGraphBetaUrl('https://graph.microsoft.com/beta/deviceManagement/settings')).toBeDefined();
    for (const bad of [
      'https://graph.microsoft.com/beta/deviceManagement/settings?$select=x',
      'https://graph.microsoft.com/beta/deviceManagement',
      'https://graph.microsoft.com/beta/users',
      'https://graph.microsoft.com/beta/deviceManagement/settings/../../users',
      'http://graph.microsoft.com/beta/deviceManagement/settings',
    ]) {
      expect(validateGraphBetaUrl(bad), bad).toBeUndefined();
    }
    expect(validateGraphUrl('https://graph.microsoft.com/beta/deviceManagement/settings')).toBeUndefined();
  });
});
