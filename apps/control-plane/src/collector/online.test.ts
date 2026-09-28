import { describe, expect, it, vi } from 'vitest';
import { AdminSecOpsError } from '@adminsecops/core';
import { CONTROL_LIBRARY } from '@adminsecops/controls';
import { runAssessment } from '@adminsecops/engine/browser';
import type { EvidenceBundle } from '@adminsecops/evidence/browser';
import type { AssessmentResult } from '@adminsecops/schemas';
import { READ_ONLY_GRAPH_SCOPES } from '../config.js';
import type { TxtResolver } from './dns.js';
import { GRAPH_BASE } from './graph-client.js';
import {
  ONLINE_DATASETS_COLLECTED,
  ONLINE_NOT_COLLECTED,
  ONLINE_REQUIRED_GRAPH_PERMISSIONS,
  collectOnline,
  collectOnlineEvidence,
  type CollectOnlineOptions,
} from './online.js';

const TENANT_ID = '11111111-2222-4333-8444-555555555555';
const ASSESSMENT_ID = '6f1c1a52-4b7e-4f8e-9a51-0c6f7d2b9e10';
const TOKEN = 'test-access-token-value-9d2f';
const FIXED_NOW = new Date('2026-09-21T10:00:00.000Z');
const TEAM_A = 'dddd0001-0000-4000-8000-000000000001';
const TEAM_B = 'dddd0001-0000-4000-8000-000000000002';
const POLICY_WIN = 'eeee0001-0000-4000-8000-000000000001';
const POLICY_IOS = 'eeee0001-0000-4000-8000-000000000002';

type Handler = (url: URL) => Response | Promise<Response>;

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const graphError = (status: number, code: string, message: string): Response => json({ error: { code, message } }, status);

const plan = (servicePlanName: string) => ({ servicePlanId: TENANT_ID, servicePlanName, provisioningStatus: 'Success', appliesTo: 'User' });

function windowsPolicy(assignments?: unknown[]) {
  return {
    '@odata.type': '#microsoft.graph.windows10CompliancePolicy',
    id: POLICY_WIN,
    displayName: 'Windows baseline',
    lastModifiedDateTime: '2026-08-01T00:00:00Z',
    bitLockerEnabled: true,
    secureBootEnabled: true,
    codeIntegrityEnabled: true,
    storageRequireEncryption: true,
    passwordRequired: true,
    osMinimumVersion: '10.0.22631',
    ...(assignments === undefined ? {} : { assignments }),
  };
}

function iosPolicy(assignments?: unknown[]) {
  return {
    '@odata.type': '#microsoft.graph.iosCompliancePolicy',
    id: POLICY_IOS,
    displayName: 'iOS baseline',
    lastModifiedDateTime: '2026-08-01T00:00:00Z',
    passcodeRequired: true,
    osMinimumVersion: '17.0',
    ...(assignments === undefined ? {} : { assignments }),
  };
}

const allDevices = [{ id: 'a1', target: { '@odata.type': '#microsoft.graph.allDevicesAssignmentTarget' } }];

function teamDetail(id: string, name: string, guestCanCreate: boolean) {
  return {
    id,
    displayName: name,
    visibility: 'private',
    isArchived: false,
    memberSettings: {
      allowCreateUpdateChannels: true,
      allowDeleteChannels: false,
      allowAddRemoveApps: false,
      allowCreateUpdateRemoveTabs: true,
      allowCreateUpdateRemoveConnectors: false,
    },
    guestSettings: { allowCreateUpdateChannels: guestCanCreate, allowDeleteChannels: false },
  };
}

/** Synthetic tenant responses keyed by path below /v1.0 (shapes follow the Microsoft Graph v1.0 reference). */
function defaultRoutes(): Record<string, Handler> {
  return {
    '/organization': () =>
      json({ value: [{ id: TENANT_ID, displayName: 'Contoso', verifiedDomains: [{ name: 'contoso.example', isDefault: true, isInitial: false, type: 'Managed', capabilities: 'Email' }] }] }),
    '/subscribedSkus': () =>
      json({
        value: [
          {
            skuId: 'c7df2760-2c81-4ef7-b578-5b5392b571df',
            skuPartNumber: 'SPE_E3',
            capabilityStatus: 'Enabled',
            consumedUnits: 10,
            prepaidUnits: { enabled: 25, suspended: 0, warning: 0 },
            servicePlans: [plan('AAD_PREMIUM'), plan('AAD_PREMIUM_P2'), plan('INTUNE_A'), plan('SHAREPOINTENTERPRISE'), plan('TEAMS1')],
          },
        ],
      }),
    '/policies/identitySecurityDefaultsEnforcementPolicy': () => json({ isEnabled: false }),
    '/policies/authorizationPolicy': () =>
      json({
        allowInvitesFrom: 'adminsAndGuestInviters',
        allowedToSignUpEmailBasedSubscriptions: false,
        allowEmailVerifiedUsersToJoinOrganization: false,
        allowUserConsentForRiskyApps: false,
        blockMsolPowerShell: true,
        guestUserRoleId: '2af84b1e-32c8-42b7-82bc-daa82404023b',
        permissionGrantPolicyIdsAssignedToDefaultUserRole: [],
        defaultUserRolePermissions: {
          allowedToCreateApps: false,
          allowedToCreateSecurityGroups: false,
          allowedToCreateTenants: false,
          allowedToReadBitlockerKeysForOwnedDevice: true,
          allowedToReadOtherUsers: true,
        },
      }),
    '/policies/authenticationMethodsPolicy': () => json({ policyMigrationState: 'migrationComplete', authenticationMethodConfigurations: [] }),
    '/identity/conditionalAccess/policies': () => json({ value: [] }),
    '/reports/authenticationMethods/userRegistrationDetails': () => json({ value: [] }),
    '/roleManagement/directory/roleDefinitions': () => json({ value: [] }),
    '/roleManagement/directory/roleAssignments': () => json({ value: [] }),
    '/users': () => json({ value: [] }),
    '/groupSettings': () =>
      json({
        value: [
          {
            id: 'gs1',
            displayName: 'Group.Unified',
            templateId: '62375ab9-6b52-47ed-826b-58e47e0e304b',
            values: [
              { name: 'AllowToAddGuests', value: 'true' },
              { name: 'CustomBlockedWordsList', value: 'confidential-term' },
            ],
          },
        ],
      }),
    '/admin/sharepoint/settings': () =>
      json({
        sharingCapability: 'externalUserAndGuestSharing',
        sharingDomainRestrictionMode: 'none',
        sharingAllowedDomainList: [],
        sharingBlockedDomainList: [],
        isResharingByExternalUsersEnabled: true,
        isLegacyAuthProtocolsEnabled: false,
        isUnmanagedSyncAppForTenantRestricted: false,
        isRequireAcceptingUserToMatchInvitedUserEnabled: true,
        idleSessionSignOut: { isEnabled: true, warnAfterInSeconds: 2700, signOutAfterInSeconds: 3600 },
        tenantDefaultTimezone: 'UTC',
      }),
    '/teamwork/teamsAppSettings': () => json({ id: 'settings', allowUserRequestsForAppAccess: true, isUserPersonalScopeResourceSpecificConsentEnabled: false }),
    '/teams': () =>
      json({ value: [{ id: TEAM_A, displayName: 'Finance', visibility: 'private' }, { id: TEAM_B, displayName: 'Partner', visibility: 'private' }] }),
    [`/teams/${TEAM_A}`]: () => json(teamDetail(TEAM_A, 'Finance', false)),
    [`/teams/${TEAM_B}`]: () => json(teamDetail(TEAM_B, 'Partner', true)),
    '/deviceManagement': () => json({ id: 'dm', settings: { secureByDefault: true, deviceComplianceCheckinThresholdDays: 30, isScheduledActionEnabled: true } }),
    '/deviceManagement/managedDeviceOverview': () =>
      json({
        id: 'overview',
        enrolledDeviceCount: 12,
        mdmEnrolledCount: 12,
        deviceOperatingSystemSummary: { androidCount: 0, iosCount: 2, macOSCount: 0, windowsMobileCount: 0, windowsCount: 10, unknownCount: 0 },
      }),
    '/deviceManagement/deviceCompliancePolicies': () => json({ value: [windowsPolicy(allDevices), iosPolicy(allDevices)] }),
    '/roleManagement/directory/roleAssignmentScheduleInstances': () => json({ value: [] }),
    '/roleManagement/directory/roleEligibilitySchedules': () => json({ value: [] }),
    '/applications': () => json({ value: [] }),
    '/servicePrincipals': () => json({ value: [] }),
    "/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')": () =>
      json({ id: 'ffff0001-0000-4000-8000-000000000001', appId: '00000003-0000-0000-c000-000000000000', displayName: 'Microsoft Graph', appRoles: [] }),
    "/servicePrincipals(appId='00000002-0000-0ff1-ce00-000000000000')": () =>
      json({ id: 'ffff0001-0000-4000-8000-000000000002', appId: '00000002-0000-0ff1-ce00-000000000000', displayName: 'Office 365 Exchange Online', appRoles: [] }),
    '/servicePrincipals/ffff0001-0000-4000-8000-000000000001/appRoleAssignedTo': () => json({ value: [] }),
    '/servicePrincipals/ffff0001-0000-4000-8000-000000000002/appRoleAssignedTo': () => json({ value: [] }),
    '/directory/onPremisesSynchronization': () => json({ value: [] }),
  };
}

/** Synthetic public DNS: every domain publishes SPF -all and DMARC p=reject. No real DNS is queried. */
const fakeDns: TxtResolver = {
  resolveTxt: (name) =>
    Promise.resolve(
      name.startsWith('_dmarc.')
        ? { status: 'Found', records: ['v=DMARC1; p=reject; rua=mailto:dmarc@contoso.example'] }
        : { status: 'Found', records: ['v=spf1 include:spf.protection.outlook.com -all', 'unrelated-verification=abc'] },
    ),
};

function mockGraph(overrides: Record<string, Handler> = {}) {
  const routes = { ...defaultRoutes(), ...overrides };
  const calls: string[] = [];
  const fetch = vi.fn(async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    calls.push(href);
    if (init?.method !== 'GET') throw new Error('test fetch: non-GET request');
    const url = new URL(href);
    if (url.origin !== 'https://graph.microsoft.com' || !url.pathname.startsWith('/v1.0/')) {
      throw new Error('test fetch: request left the Graph allowlist');
    }
    const handler = routes[url.pathname.slice('/v1.0'.length)];
    return handler === undefined ? graphError(404, 'Request_ResourceNotFound', 'not found') : handler(url);
  });
  return { fetch: fetch as unknown as typeof globalThis.fetch, calls };
}

function options(fetch: typeof globalThis.fetch, extra: Partial<CollectOnlineOptions> = {}): CollectOnlineOptions {
  return { tenantId: TENANT_ID, assessmentId: ASSESSMENT_ID, accessToken: TOKEN, fetch, now: () => FIXED_NOW, dnsResolver: fakeDns, ...extra };
}

function dataset(bundle: EvidenceBundle, id: string) {
  const loaded = bundle.datasets.get(id);
  if (loaded === undefined) throw new Error(`dataset ${id} missing`);
  return loaded;
}

const assess = (bundle: EvidenceBundle): AssessmentResult => runAssessment(bundle, CONTROL_LIBRARY, { processedAt: FIXED_NOW });
function status(result: AssessmentResult, controlId: string) {
  const found = result.results.find((r) => r.controlId === controlId);
  if (found === undefined) throw new Error(`control ${controlId} missing`);
  return found.status;
}
const issue = (bundle: EvidenceBundle, datasetId: string, code: string) =>
  bundle.issues.find((i) => i.datasetId === datasetId && i.code === code);

const ONLINE_WORKLOAD_CONTROLS = ['INTUNE-CMP-001', 'INTUNE-CMP-002', 'INTUNE-CMP-003', 'M365-SPO-001', 'M365-SPO-002', 'M365-SPO-003', 'M365-SPO-004', 'M365-TMS-001', 'M365-TMS-002'];

it('retries an omitted SharePoint invitation setting without inventing a secure default', async () => {
  const base = { sharingCapability: 'externalUserSharingOnly', sharingDomainRestrictionMode: 'none', sharingAllowedDomainList: [], sharingBlockedDomainList: [], isResharingByExternalUsersEnabled: false, isLegacyAuthProtocolsEnabled: false, isUnmanagedSyncAppForTenantRestricted: false, idleSessionSignOut: { isEnabled: true } };
  const found = mockGraph({ '/admin/sharepoint/settings': (url) => json(url.searchParams.has('$select') ? { isRequireAcceptingUserToMatchInvitedUserEnabled: false } : base) });
  const collected = await collectOnline(options(found.fetch));
  expect(dataset(collected, 'm365.sharePointSettings').data).toMatchObject({ isRequireAcceptingUserToMatchInvitedUserEnabled: false });
  const absent = mockGraph({ '/admin/sharepoint/settings': () => json(base) });
  const missing = await collectOnline(options(absent.fetch));
  expect(status(assess(missing), 'M365-SPO-005')).toBe('NOT_ASSESSED');
  expect(issue(missing, 'm365.sharePointSettings', 'SETTING_NOT_RETURNED')).toBeDefined();
});

describe('collectOnline across workloads', () => {
  it('collects Entra, SharePoint, Teams and Intune and evaluates their controls online', async () => {
    const graph = mockGraph();
    const bundle = await collectOnline(options(graph.fetch, { limits: { maxRetryDelayMs: 5 } }));
    expect(bundle.integrityVerified).toBe(true);
    for (const definition of ONLINE_DATASETS_COLLECTED.filter((d) => d.source === 'MicrosoftGraph' || d.source === 'DNS')) {
      expect(dataset(bundle, definition.id).state, definition.id).toBe('available');
    }
    expect(bundle.manifest.modules.map((m) => [m.name, m.status])).toEqual([
      ['Entra', 'Completed'],
      ['M365', 'Completed'],
      ['Intune', 'Completed'],
      ['Azure', 'Skipped'],
      ['Exchange', 'CompletedWithErrors'],
    ]);
    expect(bundle.manifest.files.map((f) => f.path)).toContain('evidence/m365/teamsTeamSettings.json');
    expect(bundle.manifest.files.map((f) => f.path)).toContain('evidence/intune/compliancePolicies.json');

    const result = assess(bundle);
    for (const id of ONLINE_WORKLOAD_CONTROLS) expect(['PASS', 'FAIL', 'REVIEW', 'NOT_APPLICABLE'], id).toContain(status(result, id));
    expect(status(result, 'M365-SPO-001')).toBe('FAIL'); // Anyone links
    expect(status(result, 'M365-SPO-003')).toBe('REVIEW'); // context dependent, never FAIL
    expect(status(result, 'M365-SPO-004')).toBe('PASS');
    expect(status(result, 'M365-TMS-001')).toBe('PASS');
    expect(status(result, 'M365-TMS-002')).toBe('REVIEW');
    expect(status(result, 'INTUNE-CMP-001')).toBe('PASS');
    expect(status(result, 'INTUNE-CMP-002')).toBe('PASS');
    expect(status(result, 'INTUNE-CMP-003')).toBe('PASS');
  });

  it('keeps Exchange controls NOT_ASSESSED without the Exchange connector; only public DNS controls run', async () => {
    const bundle = await collectOnline(options(mockGraph().fetch));
    const result = assess(bundle);
    const exchange = CONTROL_LIBRARY.filter((c) => c.metadata.requiredEvidence.some((id) => id.startsWith('exchange.') && id !== 'exchange.mailDnsRecords'));
    expect(exchange.length).toBeGreaterThan(5);
    for (const control of exchange) {
      // Defender for Office 365 is not licensed in this synthetic tenant, so its control does not apply.
      const expected = control.metadata.id === 'M365-MDO-001' ? 'NOT_APPLICABLE' : 'NOT_ASSESSED';
      expect(status(result, control.metadata.id), control.metadata.id).toBe(expected);
    }
    expect(dataset(bundle, 'exchange.organizationConfig').collectionStatus).toBe('NotCollected');
    expect(issue(bundle, 'exchange.organizationConfig', 'CONNECTOR_NOT_CONNECTED')).toBeDefined();
    // DNS never establishes accepted domains or DKIM: M365-MAIL-001 stays NOT_ASSESSED, SPF/DMARC are checked.
    expect(status(result, 'M365-MAIL-001')).toBe('NOT_ASSESSED');
    expect(status(result, 'M365-MAIL-002')).toBe('PASS');
    expect(status(result, 'M365-MAIL-003')).toBe('PASS');
    expect(issue(bundle, 'exchange.mailDnsRecords', 'DOMAINS_FROM_VERIFIED_DOMAINS')).toBeDefined();
    expect(issue(bundle, 'exchange.mailDnsRecords', 'DNS_PROVENANCE')).toBeDefined();
    // Azure is not connected: Azure controls are NOT_ASSESSED with the reason recorded.
    for (const id of ['AZ-DEF-001', 'AZ-RBAC-001', 'AZ-STG-001']) expect(status(result, id)).toBe('NOT_ASSESSED');
    expect(issue(bundle, 'azure.subscriptions', 'CONNECTOR_NOT_CONNECTED')).toBeDefined();
    // Missing services lower coverage instead of inflating it.
    expect(result.summary.assessmentCoverage.assessed).toBeLessThan(result.summary.assessmentCoverage.applicable);
  });

  it('never calls non-GET, non-v1.0 or beta endpoints and never stores the token', async () => {
    const graph = mockGraph();
    const { files } = await collectOnlineEvidence(options(graph.fetch));
    expect(graph.calls.every((c) => c.startsWith(`${GRAPH_BASE}/`))).toBe(true);
    const text = [...files.values()].map((b) => new TextDecoder().decode(b)).join('\n');
    expect(text).not.toContain(TOKEN);
    // Directory settings outside the allow-list (custom blocked words) are dropped.
    expect(text).not.toContain('confidential-term');
  });

  it('verifies the tenant before any other customer read (cross-tenant guard)', async () => {
    const graph = mockGraph({ '/organization': () => json({ value: [{ id: '99999999-2222-4333-8444-555555555555', displayName: 'Other' }] }) });
    await expect(collectOnline(options(graph.fetch))).rejects.toSatisfy(
      (e: unknown) => e instanceof AdminSecOpsError && e.code === 'TENANT_MISMATCH',
    );
    expect(graph.calls).toHaveLength(1);
  });
});

describe('online partial, denied and missing evidence', () => {
  it('reports a 403 as Unauthorized with the missing consent and keeps SharePoint controls NOT_ASSESSED', async () => {
    const graph = mockGraph({ '/admin/sharepoint/settings': () => graphError(403, 'accessDenied', 'Access denied. PRIVATE-BODY') });
    const bundle = await collectOnline(options(graph.fetch, { grantedScopes: ['Policy.Read.All', 'https://graph.microsoft.com/Organization.Read.All'] }));
    const settings = dataset(bundle, 'm365.sharePointSettings');
    expect(settings.collectionStatus).toBe('Unauthorized');
    expect(issue(bundle, 'm365.sharePointSettings', 'UNAUTHORIZED')?.message).toContain('consent was not granted for: SharePointTenantSettings.Read.All');
    expect(JSON.stringify(bundle.issues)).not.toContain('PRIVATE-BODY');
    const result = assess(bundle);
    for (const id of ['M365-SPO-001', 'M365-SPO-002', 'M365-SPO-003', 'M365-SPO-004']) expect(status(result, id)).toBe('NOT_ASSESSED');
    expect(bundle.manifest.modules.find((m) => m.name === 'M365')?.status).toBe('CompletedWithErrors');
  });

  it('fails Intune settings with a missing secureByDefault instead of assuming a default', async () => {
    const graph = mockGraph({ '/deviceManagement': () => json({ settings: { deviceComplianceCheckinThresholdDays: 30 } }) });
    const bundle = await collectOnline(options(graph.fetch));
    expect(dataset(bundle, 'intune.settings').collectionStatus).toBe('Failed');
    expect(issue(bundle, 'intune.settings', 'DATA_INVALID')).toBeDefined();
    expect(status(assess(bundle), 'INTUNE-CMP-001')).toBe('NOT_ASSESSED');
  });

  it('retries deviceManagement without $select when settings are omitted', async () => {
    const graph = mockGraph({
      '/deviceManagement': (url) =>
        url.searchParams.has('$select') ? json({ id: 'dm' }) : json({ id: 'dm', settings: { secureByDefault: false } }),
    });
    const bundle = await collectOnline(options(graph.fetch));
    expect(dataset(bundle, 'intune.settings').state).toBe('available');
    expect(status(assess(bundle), 'INTUNE-CMP-001')).toBe('FAIL');
  });

  it('fails the device overview when a platform count is missing', async () => {
    const graph = mockGraph({
      '/deviceManagement/managedDeviceOverview': () => json({ enrolledDeviceCount: 3, deviceOperatingSystemSummary: { windowsCount: 3, iosCount: 0, macOSCount: 0 } }),
    });
    const bundle = await collectOnline(options(graph.fetch));
    expect(dataset(bundle, 'intune.deviceOverview').collectionStatus).toBe('Failed');
    expect(status(assess(bundle), 'INTUNE-CMP-002')).toBe('NOT_ASSESSED');
  });

  it('keeps earlier compliance-policy pages but marks the dataset Partial when a later page fails', async () => {
    const graph = mockGraph({
      '/deviceManagement/deviceCompliancePolicies': (url) =>
        url.searchParams.has('$skiptoken')
          ? graphError(500, 'InternalServerError', 'boom')
          : json({ value: [windowsPolicy(allDevices)], '@odata.nextLink': `${GRAPH_BASE}/deviceManagement/deviceCompliancePolicies?$expand=assignments&$skiptoken=2` }),
    });
    const bundle = await collectOnline(options(graph.fetch));
    const policies = dataset(bundle, 'intune.compliancePolicies');
    expect(policies.collectionStatus).toBe('Partial');
    expect(policies.data).toHaveLength(1);
    expect(issue(bundle, 'intune.compliancePolicies', 'PAGE_FAILED')).toBeDefined();
    const result = assess(bundle);
    expect(status(result, 'INTUNE-CMP-003')).not.toBe('PASS');
    expect(status(result, 'INTUNE-CMP-002')).not.toBe('PASS');
  });

  it('reads assignments per policy when they are not expanded, and a failed request contaminates completeness', async () => {
    const assignmentCalls: string[] = [];
    const graph = mockGraph({
      '/deviceManagement/deviceCompliancePolicies': () => json({ value: [windowsPolicy(), iosPolicy()] }),
      [`/deviceManagement/deviceCompliancePolicies/${POLICY_WIN}/assignments`]: (url) => {
        assignmentCalls.push(url.pathname);
        return json({ value: allDevices });
      },
      [`/deviceManagement/deviceCompliancePolicies/${POLICY_IOS}/assignments`]: (url) => {
        assignmentCalls.push(url.pathname);
        return graphError(403, 'Forbidden', 'denied');
      },
    });
    const bundle = await collectOnline(options(graph.fetch));
    expect(assignmentCalls).toHaveLength(2);
    const policies = dataset(bundle, 'intune.compliancePolicies');
    expect(policies.collectionStatus).toBe('Partial');
    expect(issue(bundle, 'intune.compliancePolicies', 'FANOUT_ITEM_FAILED')?.target).toBe(POLICY_IOS);
    const win = (policies.data as Array<{ id: string; assignments: unknown[] }>).find((p) => p.id === POLICY_WIN);
    expect(win?.assignments).toHaveLength(1);
    const result = assess(bundle);
    expect(status(result, 'INTUNE-CMP-002')).not.toBe('PASS');
    expect(status(result, 'INTUNE-CMP-003')).toBe('REVIEW'); // PASS downgraded: evidence incomplete
  });

  it('does not follow a team list nextLink outside the allowlist', async () => {
    const graph = mockGraph({
      '/teams': () => json({ value: [{ id: TEAM_A, displayName: 'Finance' }], '@odata.nextLink': 'https://graph.microsoft.com/beta/teams?$skiptoken=x' }),
    });
    const bundle = await collectOnline(options(graph.fetch));
    expect(graph.calls.some((c) => c.includes('/beta/'))).toBe(false);
    expect(dataset(bundle, 'm365.teamsTeamSettings').collectionStatus).toBe('Partial');
    expect(issue(bundle, 'm365.teamsTeamSettings', 'NEXT_LINK_REJECTED')).toBeDefined();
    expect(status(assess(bundle), 'M365-TMS-002')).not.toBe('PASS');
  });

  it('marks teams that cannot be read as unknown and the dataset Partial', async () => {
    const graph = mockGraph({
      [`/teams/${TEAM_B}`]: () => graphError(403, 'Forbidden', 'not a member'),
      [`/teams/${TEAM_A}`]: () => json({ ...teamDetail(TEAM_A, 'Finance', false), guestSettings: undefined }),
    });
    const bundle = await collectOnline(options(graph.fetch));
    const teams = dataset(bundle, 'm365.teamsTeamSettings');
    expect(teams.collectionStatus).toBe('Partial');
    expect(issue(bundle, 'm365.teamsTeamSettings', 'FANOUT_ITEM_FAILED')?.target).toBe(TEAM_B);
    expect(issue(bundle, 'm365.teamsTeamSettings', 'TEAM_SETTINGS_MISSING')?.target).toBe(TEAM_A);
    expect((teams.data as Array<{ guestSettings: unknown }>).every((t) => t.guestSettings === null)).toBe(true);
    expect(status(assess(bundle), 'M365-TMS-002')).toBe('REVIEW');
  });

  it('caps per-team requests and reports the rest as not read', async () => {
    const graph = mockGraph();
    const bundle = await collectOnline(options(graph.fetch, { limits: { maxFanoutRequests: 1 } }));
    expect(graph.calls.filter((c) => c.includes(`/teams/${TEAM_A}`) || c.includes(`/teams/${TEAM_B}`))).toHaveLength(1);
    expect(dataset(bundle, 'm365.teamsTeamSettings').collectionStatus).toBe('Partial');
    expect(issue(bundle, 'm365.teamsTeamSettings', 'FANOUT_LIMIT')).toBeDefined();
  });

  it('fails an unsupported endpoint without guessing and leaves its control NOT_ASSESSED', async () => {
    const graph = mockGraph({
      '/teamwork/teamsAppSettings': () => graphError(400, 'BadRequest', "Resource not found for the segment 'teamsAppSettings'."),
    });
    const bundle = await collectOnline(options(graph.fetch));
    expect(dataset(bundle, 'm365.teamsAppSettings').collectionStatus).toBe('Failed');
    expect(issue(bundle, 'm365.teamsAppSettings', 'HTTP_400')).toBeDefined();
    expect(status(assess(bundle), 'M365-TMS-001')).toBe('NOT_ASSESSED');
  });

  it('marks Intune NotApplicable without calling Intune endpoints when no Intune licence is present', async () => {
    const graph = mockGraph({
      '/subscribedSkus': () =>
        json({ value: [{ skuId: 'c7df2760-2c81-4ef7-b578-5b5392b571df', skuPartNumber: 'O365_BUSINESS', capabilityStatus: 'Enabled', consumedUnits: 1, prepaidUnits: { enabled: 1 }, servicePlans: [plan('SHAREPOINTSTANDARD')] }] }),
    });
    const bundle = await collectOnline(options(graph.fetch));
    for (const id of ['intune.settings', 'intune.deviceOverview', 'intune.compliancePolicies']) {
      expect(dataset(bundle, id).collectionStatus).toBe('NotApplicable');
    }
    expect(graph.calls.some((c) => c.includes('/deviceManagement'))).toBe(false);
    const result = assess(bundle);
    for (const id of ['INTUNE-CMP-001', 'INTUNE-CMP-002', 'INTUNE-CMP-003']) expect(status(result, id)).toBe('NOT_APPLICABLE');
  });

  it('maps a service licence error to NotApplicable, never to passing evidence', async () => {
    const graph = mockGraph({
      '/deviceManagement/managedDeviceOverview': () => graphError(403, 'Forbidden', 'The tenant is not licensed for Intune.'),
    });
    const bundle = await collectOnline(options(graph.fetch));
    expect(dataset(bundle, 'intune.deviceOverview').collectionStatus).toBe('NotApplicable');
  });

  it('propagates cancellation during per-team requests and produces no bundle', async () => {
    const controller = new AbortController();
    const graph = mockGraph({
      [`/teams/${TEAM_A}`]: () => {
        controller.abort();
        return json(teamDetail(TEAM_A, 'Finance', false));
      },
    });
    await expect(collectOnline(options(graph.fetch, { signal: controller.signal }))).rejects.toSatisfy(
      (e: unknown) => e instanceof AdminSecOpsError && e.code === 'COLLECTION_CANCELLED',
    );
    expect(graph.calls.some((c) => c.includes(`/teams/${TEAM_B}`))).toBe(false);
  });

  it('stops per-resource requests once the shared time budget is exhausted', async () => {
    let clock = FIXED_NOW.getTime();
    const graph = mockGraph({
      [`/teams/${TEAM_A}`]: () => {
        clock += 60 * 60_000; // the request consumed the remaining collection time
        return json(teamDetail(TEAM_A, 'Finance', false));
      },
    });
    const bundle = await collectOnline(options(graph.fetch, { now: () => new Date(clock) }));
    expect(graph.calls.some((c) => c.includes(`/teams/${TEAM_B}`))).toBe(false);
    expect(dataset(bundle, 'm365.teamsTeamSettings').collectionStatus).toBe('Partial');
    // Datasets after the exhausted budget fail; none is reported as successfully collected.
    expect(dataset(bundle, 'intune.settings').collectionStatus).toBe('Failed');
  });
});

describe('online permissions', () => {
  it('requests only read-only scopes that the deployment allowlist accepts', () => {
    expect([...ONLINE_REQUIRED_GRAPH_PERMISSIONS].sort()).toEqual(
      [
        'AuditLog.Read.All',
        'DeviceManagementConfiguration.Read.All',
        'DeviceManagementManagedDevices.Read.All',
        'Directory.Read.All',
        'OnPremDirectorySynchronization.Read.All',
        'Organization.Read.All',
        'Policy.Read.All',
        'RoleManagement.Read.Directory',
        'SharePointTenantSettings.Read.All',
        'Team.ReadBasic.All',
        'TeamworkAppSettings.Read.All',
        'User.Read.All',
        'UserAuthenticationMethod.Read.All',
      ].sort(),
    );
    for (const scope of ONLINE_REQUIRED_GRAPH_PERMISSIONS) {
      expect(READ_ONLY_GRAPH_SCOPES).toContain(scope);
      expect(scope).toMatch(/\.Read(Basic)?(\.|$)/);
      expect(scope).not.toMatch(/Write/i);
    }
  });

  it('collects every Entra, M365, Intune, Azure and Exchange dataset of the registry', () => {
    for (const module of ['Entra', 'M365', 'Intune', 'Azure', 'Exchange'] as const) expect(ONLINE_NOT_COLLECTED.has(module), module).toBe(false);
  });
});

describe('deployment review regressions', () => {
  it('accepts the documented wrapped Teams app settings response', async () => {
    const graph = mockGraph({ '/teamwork/teamsAppSettings': () => json({ value: { allowUserRequestsForAppAccess: true, isUserPersonalScopeResourceSpecificConsentEnabled: false } }) });
    const bundle = await collectOnline(options(graph.fetch));
    expect(dataset(bundle, 'm365.teamsAppSettings').collectionStatus).toBe('Success');
    expect(status(assess(bundle), 'M365-TMS-001')).toBe('PASS');
  });
  it('does not pass coverage with truncated expanded assignments', async () => {
    const graph = mockGraph({ '/deviceManagement/deviceCompliancePolicies': () => json({ value: [{ ...windowsPolicy(allDevices), 'assignments@odata.nextLink': 'https://graph.microsoft.com/v1.0/more' }] }) });
    const bundle = await collectOnline(options(graph.fetch));
    expect(dataset(bundle, 'intune.compliancePolicies').collectionStatus).toBe('Partial');
    expect(status(assess(bundle), 'INTUNE-CMP-002')).not.toBe('PASS');
  });
});

it('honours selected workloads while always verifying tenant identity and reporting real progress',async()=>{
 const graph=mockGraph();const progress=vi.fn(()=>Promise.resolve());const bundle=await collectOnline(options(graph.fetch,{modules:['Intune'],onProgress:progress}));
 expect(graph.calls[0]).toContain('/organization');expect(graph.calls.some(url=>url.includes('conditionalAccess'))).toBe(false);
 expect(bundle.datasets.has('intune.settings')).toBe(true);expect(bundle.datasets.has('exchange.transportRules')).toBe(false);
 expect(progress).toHaveBeenCalledWith('entra.organization','collecting');expect(progress).toHaveBeenCalledWith('entra.organization','Success');
});
