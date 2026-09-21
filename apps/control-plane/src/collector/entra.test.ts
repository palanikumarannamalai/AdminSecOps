import { describe, expect, it, vi } from 'vitest';
import { AdminSecOpsError } from '@adminsecops/core';
import { CONTROL_LIBRARY } from '@adminsecops/controls';
import { runAssessment } from '@adminsecops/engine/browser';
import type { EvidenceBundle } from '@adminsecops/evidence/browser';
import { getDatasetDefinition } from '@adminsecops/schemas';
import {
  ENTRA_GRAPH_PERMISSIONS,
  ENTRA_REQUIRED_GRAPH_PERMISSIONS,
  HOSTED_ENTRA_DATASETS,
  HOSTED_ENTRA_UNSUPPORTED_DATASETS,
  collectEntra,
  collectEntraEvidence,
  type CollectEntraOptions,
} from './entra.js';
import { GRAPH_BASE, validateGraphUrl } from './graph-client.js';

const TENANT_ID = '11111111-2222-4333-8444-555555555555';
const ASSESSMENT_ID = '6f1c1a52-4b7e-4f8e-9a51-0c6f7d2b9e10';
const TOKEN = 'test-access-token-value-7c1e';
const FIXED_NOW = new Date('2026-09-01T10:00:00.000Z');
const GLOBAL_ADMIN = '62e90394-69f5-4237-9190-012177145e10';

type Handler = (url: URL, init: RequestInit | undefined) => Response | Promise<Response>;

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

const graphError = (status: number, code: string, message: string): Response =>
  json({ error: { code, message } }, status);

/** Default tenant responses keyed by path below /v1.0. */
function defaultRoutes(): Record<string, Handler> {
  return {
    '/organization': () =>
      json({
        value: [
          {
            id: TENANT_ID,
            displayName: 'Contoso',
            createdDateTime: '2020-01-01T00:00:00Z',
            onPremisesSyncEnabled: null,
            onPremisesLastSyncDateTime: null,
            technicalNotificationMails: ['admin@contoso.example'],
            verifiedDomains: [
              {
                name: 'contoso.example',
                isDefault: true,
                isInitial: false,
                type: 'Managed',
                capabilities: 'Email',
              },
            ],
          },
        ],
      }),
    '/subscribedSkus': () =>
      json({
        value: [
          {
            skuId: 'c7df2760-2c81-4ef7-b578-5b5392b571df',
            skuPartNumber: 'ENTERPRISEPREMIUM',
            capabilityStatus: 'Enabled',
            consumedUnits: 10,
            prepaidUnits: { enabled: 25, suspended: 0, warning: 0, lockedOut: 0 },
            servicePlans: [
              {
                servicePlanId: '41781fb2-bc02-4b7c-bd55-b576c07bb09d',
                servicePlanName: 'AAD_PREMIUM',
                provisioningStatus: 'Success',
                appliesTo: 'User',
              },
            ],
          },
        ],
      }),
    '/policies/identitySecurityDefaultsEnforcementPolicy': () =>
      json({
        id: '00000000-0000-0000-0000-000000000005',
        displayName: 'Security Defaults',
        isEnabled: true,
      }),
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
    '/policies/authenticationMethodsPolicy': () =>
      json({
        policyMigrationState: 'migrationComplete',
        authenticationMethodConfigurations: [
          {
            id: 'Fido2',
            state: 'enabled',
            includeTargets: [
              { targetType: 'group', id: 'all_users', isRegistrationRequired: false },
            ],
          },
          { id: 'Sms', state: 'disabled' },
        ],
      }),
    '/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Sms': () =>
      json({
        id: 'Sms',
        state: 'disabled',
        includeTargets: [{ targetType: 'group', id: 'all_users' }],
      }),
    '/identity/conditionalAccess/policies': () =>
      json({
        value: [
          {
            id: '0a1b2c3d-0000-4000-8000-000000000001',
            displayName: 'Require MFA for admins',
            state: 'enabled',
            createdDateTime: '2025-01-01T00:00:00Z',
            modifiedDateTime: null,
            conditions: {
              users: {
                includeUsers: [],
                excludeUsers: [],
                includeGroups: [],
                excludeGroups: [],
                includeRoles: [GLOBAL_ADMIN],
                excludeRoles: [],
              },
              applications: {
                includeApplications: ['All'],
                excludeApplications: [],
                includeUserActions: [],
              },
              clientAppTypes: ['all'],
              signInRiskLevels: [],
              userRiskLevels: [],
              platforms: null,
              locations: null,
            },
            grantControls: {
              operator: 'OR',
              builtInControls: ['mfa'],
              customAuthenticationFactors: [],
              termsOfUse: [],
              authenticationStrength: null,
            },
            sessionControls: null,
          },
        ],
      }),
    '/reports/authenticationMethods/userRegistrationDetails': (url) =>
      url.searchParams.get('$skiptoken') === 'page2'
        ? json({ value: [registration('u2', 'user2@contoso.example', false)] })
        : json({
            value: [registration('u1', 'admin@contoso.example', true)],
            '@odata.nextLink': `${GRAPH_BASE}/reports/authenticationMethods/userRegistrationDetails?$skiptoken=page2`,
          }),
    '/roleManagement/directory/roleDefinitions': () =>
      json({
        value: [
          {
            id: GLOBAL_ADMIN,
            displayName: 'Global Administrator',
            templateId: GLOBAL_ADMIN,
            isBuiltIn: true,
            isEnabled: true,
            rolePermissions: [],
          },
        ],
      }),
    '/roleManagement/directory/roleAssignments': () =>
      json({
        value: [
          {
            id: 'assignment-1',
            roleDefinitionId: GLOBAL_ADMIN,
            principalId: 'u1',
            directoryScopeId: '/',
            principal: {
              '@odata.type': '#microsoft.graph.user',
              id: 'u1',
              displayName: 'Admin',
              userPrincipalName: 'admin@contoso.example',
              userType: 'Member',
              accountEnabled: true,
              onPremisesSyncEnabled: null,
            },
          },
        ],
      }),
    '/users': () =>
      json({
        value: [
          {
            id: 'g1',
            userPrincipalName: 'guest_fabrikam.example#EXT#@contoso.example',
            accountEnabled: true,
            createdDateTime: '2025-06-01T00:00:00Z',
            externalUserState: 'Accepted',
            signInActivity: {
              lastSignInDateTime: '2026-08-01T00:00:00Z',
              lastNonInteractiveSignInDateTime: null,
            },
          },
        ],
      }),
  };
}

function registration(id: string, upn: string, isAdmin: boolean) {
  return {
    id,
    userPrincipalName: upn,
    userType: 'member',
    isAdmin,
    isMfaRegistered: true,
    isMfaCapable: true,
    isPasswordlessCapable: false,
    isSsprRegistered: true,
    methodsRegistered: ['microsoftAuthenticatorPush'],
  };
}

interface Call {
  url: string;
  init: RequestInit | undefined;
}

/** Mocked fetch serving the default tenant; `overrides` replace routes. Unknown URLs return 404. */
function mockGraph(overrides: Record<string, Handler> = {}) {
  const routes = { ...defaultRoutes(), ...overrides };
  const calls: Call[] = [];
  const fetch = vi.fn(
    async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const href =
        typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      calls.push({ url: href, init });
      const url = new URL(href);
      if (url.origin !== 'https://graph.microsoft.com' || !url.pathname.startsWith('/v1.0/')) {
        throw new Error('test fetch: request left the Graph allowlist');
      }
      const handler = routes[url.pathname.slice('/v1.0'.length)];
      return handler === undefined
        ? graphError(404, 'Request_ResourceNotFound', 'not found')
        : handler(url, init);
    },
  );
  return { fetch: fetch as unknown as typeof globalThis.fetch, calls };
}

function options(
  fetch: typeof globalThis.fetch,
  extra: Partial<CollectEntraOptions> = {},
): CollectEntraOptions {
  return {
    tenantId: TENANT_ID,
    assessmentId: ASSESSMENT_ID,
    accessToken: TOKEN,
    fetch,
    now: () => FIXED_NOW,
    ...extra,
  };
}

function dataset(bundle: EvidenceBundle, id: string) {
  const loaded = bundle.datasets.get(id);
  if (loaded === undefined) throw new Error(`dataset ${id} missing`);
  return loaded;
}

function controlStatus(bundle: EvidenceBundle, controlId: string) {
  const result = runAssessment(bundle, CONTROL_LIBRARY, { processedAt: FIXED_NOW }).results.find(
    (r) => r.controlId === controlId,
  );
  if (result === undefined) throw new Error(`control ${controlId} missing`);
  return result.status;
}

async function rejectsWith(promise: Promise<unknown>, code: string): Promise<void> {
  await expect(promise).rejects.toSatisfy(
    (error: unknown) => error instanceof AdminSecOpsError && error.code === code,
  );
}

describe('collectEntra happy path', () => {
  it('preserves device filters and MFA strength requirements from Graph', async () => {
    const routes = defaultRoutes();
    const graph = mockGraph({
      '/policies/identitySecurityDefaultsEnforcementPolicy': () => json({ id: 'defaults', isEnabled: false }),
      '/identity/conditionalAccess/policies': async (url, init) => {
        const response = await routes['/identity/conditionalAccess/policies']!(url, init);
        const body = (await response.json()) as {
          value: Array<{
            conditions: { devices?: unknown; applications: { applicationFilter?: unknown } };
            grantControls: { authenticationStrength: unknown };
          }>;
        };
        body.value[0]!.conditions.devices = {
          deviceFilter: { mode: 'exclude', rule: 'device.isCompliant -eq True' },
        };
        body.value[0]!.grantControls.authenticationStrength = {
          id: 'custom-strength',
          displayName: 'Custom',
          requirementsSatisfied: 'singleFactorAuthentication',
        };
        return json(body);
      },
    });
    const bundle = await collectEntra(options(graph.fetch));
    expect(dataset(bundle, 'entra.conditionalAccessPolicies').data).toMatchObject([
      {
        conditions: {
          devices: { deviceFilter: { mode: 'exclude', rule: 'device.isCompliant -eq True' } },
        },
        grantControls: {
          authenticationStrength: { requirementsSatisfied: 'singleFactorAuthentication' },
        },
      },
    ]);
    expect(controlStatus(bundle, 'ENTRA-CA-002')).not.toBe('PASS');
  });

  it('marks unmodeled application scope as partial rather than silently passing', async () => {
    const routes = defaultRoutes();
    const graph = mockGraph({
      '/policies/identitySecurityDefaultsEnforcementPolicy': () => json({ id: 'defaults', isEnabled: false }),
      '/identity/conditionalAccess/policies': async (url, init) => {
        const response = await routes['/identity/conditionalAccess/policies']!(url, init);
        const body = (await response.json()) as {
          value: Array<{
            conditions: { devices?: unknown; applications: { applicationFilter?: unknown } };
            grantControls: { authenticationStrength: unknown };
          }>;
        };
        body.value[0]!.conditions.applications.applicationFilter = {
          mode: 'include',
          rule: 'customSecurityAttributes/Department -eq "Finance"',
        };
        return json(body);
      },
    });
    const bundle = await collectEntra(options(graph.fetch));
    expect(bundle.issues.some((i) => i.code === 'CA_SCOPE_NOT_MODELED')).toBe(true);
    expect(controlStatus(bundle, 'ENTRA-CA-002')).not.toBe('PASS');
  });

  it('produces a verified bundle with every supported dataset available', async () => {
    const graph = mockGraph();
    const bundle = await collectEntra(options(graph.fetch));

    expect(bundle.integrityVerified).toBe(true);
    expect(bundle.manifest.assessmentId).toBe(ASSESSMENT_ID);
    expect(bundle.manifest.environment).toMatchObject({
      tenantId: TENANT_ID,
      tenantDisplayName: 'Contoso',
      primaryDomain: 'contoso.example',
    });
    expect(bundle.manifest.modules[0]?.status).toBe('Completed');
    for (const definition of HOSTED_ENTRA_DATASETS) {
      expect(dataset(bundle, definition.id).state, definition.id).toBe('available');
    }
    // Unsupported datasets are absent from the package, not fabricated.
    for (const id of HOSTED_ENTRA_UNSUPPORTED_DATASETS) expect(bundle.datasets.has(id)).toBe(false);
    expect(bundle.issues.some((i) => i.code === 'DATASETS_NOT_COLLECTED')).toBe(true);

    // Pagination was followed and undeclared Graph properties were not copied.
    expect(dataset(bundle, 'entra.userRegistrationDetails').data).toHaveLength(2);
    expect(JSON.stringify(dataset(bundle, 'entra.organization').data)).not.toContain(
      'technicalNotificationMails',
    );
    const assignment = (
      dataset(bundle, 'entra.roleAssignments').data as Array<{
        principal: { principalType: string };
      }>
    )[0];
    expect(assignment?.principal.principalType).toBe('user');
  });

  it('sends only authenticated GETs to Graph v1.0 and never stores the token', async () => {
    const graph = mockGraph();
    const { files } = await collectEntraEvidence(options(graph.fetch));

    expect(graph.calls.length).toBeGreaterThan(0);
    for (const call of graph.calls) {
      expect(call.url.startsWith(`${GRAPH_BASE}/`)).toBe(true);
      expect(call.init?.method).toBe('GET');
      expect(call.init?.redirect).toBe('error');
      expect((call.init?.headers as Record<string, string>)['Authorization']).toBe(
        `Bearer ${TOKEN}`,
      );
    }
    const decoder = new TextDecoder();
    for (const bytes of files.values()) expect(decoder.decode(bytes)).not.toContain(TOKEN);
  });

  it('is usable with runAssessment and CONTROL_LIBRARY', async () => {
    const bundle = await collectEntra(options(mockGraph().fetch));
    const result = runAssessment(bundle, CONTROL_LIBRARY, { processedAt: FIXED_NOW });
    expect(result.assessmentId).toBe(ASSESSMENT_ID);
    expect(result.evidence.integrityVerified).toBe(true);
    expect(result.results.find((r) => r.controlId === 'ENTRA-CA-001')?.status).toBe('PASS');
    // Controls that depend on datasets this collector does not produce are never passed.
    const adResults = result.results.filter((r) => r.technology === 'ad');
    expect(adResults.length).toBeGreaterThan(0);
    for (const r of adResults) expect(r.status).not.toBe('PASS');
  });
});

describe('pagination links', () => {
  it.each([
    'https://evil.example/v1.0/reports/authenticationMethods/userRegistrationDetails?$skiptoken=x',
    'http://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails',
    'https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails',
    'https://graph.microsoft.com.evil.example/v1.0/users',
    'https://graph.microsoft.com@evil.example/v1.0/users',
    'https://graph.microsoft.com:8443/v1.0/users',
    'https://graph.microsoft.com/v1.0/../beta/users',
    '//evil.example/v1.0/users',
  ])('does not follow the forbidden nextLink %s and reports Partial', async (nextLink) => {
    const graph = mockGraph({
      '/reports/authenticationMethods/userRegistrationDetails': () =>
        json({
          value: [registration('u1', 'admin@contoso.example', true)],
          '@odata.nextLink': nextLink,
        }),
    });
    const bundle = await collectEntra(options(graph.fetch));

    expect(graph.calls.every((c) => c.url.startsWith(`${GRAPH_BASE}/`))).toBe(true);
    expect(graph.calls.some((c) => c.url.includes('evil') || c.url.includes('/beta/'))).toBe(false);
    const registrations = dataset(bundle, 'entra.userRegistrationDetails');
    expect(registrations.state).toBe('partial');
    expect(registrations.collectionStatus).toBe('Partial');
    expect(registrations.data).toHaveLength(1);
    expect(
      bundle.issues.some(
        (i) => i.datasetId === 'entra.userRegistrationDetails' && i.code === 'NEXT_LINK_REJECTED',
      ),
    ).toBe(true);
    expect(bundle.manifest.modules[0]?.status).toBe('CompletedWithErrors');
  });

  it('validateGraphUrl accepts only Graph v1.0 URLs', () => {
    expect(validateGraphUrl(`${GRAPH_BASE}/users?$skiptoken=abc`)).toBe(
      `${GRAPH_BASE}/users?$skiptoken=abc`,
    );
    expect(validateGraphUrl('https://graph.microsoft.com/v1.0/%2e%2e/beta/users')).toBeUndefined();
    expect(validateGraphUrl(`${GRAPH_BASE}/users#frag`)).toBeUndefined();
    expect(validateGraphUrl(`${GRAPH_BASE}/users\r\nX-Injected: 1`)).toBeUndefined();
    expect(validateGraphUrl(42)).toBeUndefined();
  });

  it('stops at the page limit and reports Partial', async () => {
    let page = 0;
    const graph = mockGraph({
      '/users': () => {
        page += 1;
        return json({
          value: [{ id: `g${page}`, userPrincipalName: `g${page}@x.example` }],
          '@odata.nextLink': `${GRAPH_BASE}/users?$skiptoken=${page}`,
        });
      },
    });
    const bundle = await collectEntra(options(graph.fetch, { limits: { maxPages: 3 } }));
    const guests = dataset(bundle, 'entra.guestUsers');
    expect(guests.state).toBe('partial');
    expect(guests.data).toHaveLength(3);
    expect(bundle.issues.some((i) => i.code === 'PAGE_LIMIT')).toBe(true);
  });

  it('keeps earlier pages but reports Partial when a later page fails', async () => {
    const graph = mockGraph({
      '/reports/authenticationMethods/userRegistrationDetails': (url) =>
        url.searchParams.has('$skiptoken')
          ? graphError(500, 'InternalServerError', 'boom')
          : json({
              value: [registration('u1', 'admin@contoso.example', true)],
              '@odata.nextLink': `${GRAPH_BASE}/reports/authenticationMethods/userRegistrationDetails?$skiptoken=2`,
            }),
    });
    const registrations = dataset(
      await collectEntra(options(graph.fetch)),
      'entra.userRegistrationDetails',
    );
    expect(registrations.state).toBe('partial');
    expect(registrations.data).toHaveLength(1);
  });
});

describe('permission and error handling', () => {
  it('reports an unexplained 403 as Unauthorized, never as passing evidence', async () => {
    const graph = mockGraph({
      '/policies/identitySecurityDefaultsEnforcementPolicy': () =>
        graphError(
          403,
          'Authorization_RequestDenied',
          'Insufficient privileges. DETAIL-FROM-ERROR-BODY',
        ),
    });
    const bundle = await collectEntra(options(graph.fetch));
    const sd = dataset(bundle, 'entra.securityDefaults');
    expect(sd.state).toBe('unavailable');
    expect(sd.collectionStatus).toBe('Unauthorized');
    expect(sd.data).toBeNull();
    const issue = bundle.issues.find(
      (i) => i.datasetId === 'entra.securityDefaults' && i.code === 'UNAUTHORIZED',
    );
    expect(issue?.message).toContain('Policy.Read.All');
    // The error body message is not copied into evidence.
    expect(JSON.stringify(bundle.issues)).not.toContain('DETAIL-FROM-ERROR-BODY');
    expect(controlStatus(bundle, 'ENTRA-CA-001')).toBe('NOT_ASSESSED');
    // Other datasets are unaffected.
    expect(dataset(bundle, 'entra.organization').state).toBe('available');
  });

  it('reports a 403 with no error body as Unauthorized', async () => {
    const graph = mockGraph({
      '/roleManagement/directory/roleAssignments': () => new Response('', { status: 403 }),
    });
    const assignments = dataset(await collectEntra(options(graph.fetch)), 'entra.roleAssignments');
    expect(assignments.collectionStatus).toBe('Unauthorized');
    expect(assignments.data).toBeNull();
  });

  it('maps a licence error to NotApplicable', async () => {
    const graph = mockGraph({
      '/reports/authenticationMethods/userRegistrationDetails': () =>
        graphError(
          403,
          'Authentication_RequestFromNonPremiumTenantOrB2CTenant',
          'Tenant does not have a SKU required.',
        ),
    });
    const registrations = dataset(
      await collectEntra(options(graph.fetch)),
      'entra.userRegistrationDetails',
    );
    expect(registrations.collectionStatus).toBe('NotApplicable');
  });

  it('marks P1-dependent datasets NotApplicable without calling Graph when subscribedSkus shows no P1', async () => {
    const graph = mockGraph({ '/subscribedSkus': () => json({ value: [] }) });
    const bundle = await collectEntra(options(graph.fetch));
    expect(dataset(bundle, 'entra.conditionalAccessPolicies').collectionStatus).toBe(
      'NotApplicable',
    );
    expect(graph.calls.some((c) => c.url.includes('/identity/conditionalAccess/'))).toBe(false);
  });

  it('collects guests without sign-in activity when signInActivity is forbidden', async () => {
    const graph = mockGraph({
      '/users': (url) =>
        (url.searchParams.get('$select') ?? '').includes('signInActivity')
          ? graphError(403, 'Authorization_RequestDenied', 'denied')
          : json({
              value: [
                {
                  id: 'g1',
                  userPrincipalName: 'g1@x.example',
                  accountEnabled: true,
                  createdDateTime: null,
                  externalUserState: null,
                },
              ],
            }),
    });
    const bundle = await collectEntra(options(graph.fetch));
    const guests = dataset(bundle, 'entra.guestUsers');
    expect(guests.state).toBe('partial');
    expect(
      (guests.data as Array<{ lastSignInDateTime: unknown }>)[0]?.lastSignInDateTime,
    ).toBeNull();
    expect(bundle.issues.some((i) => i.code === 'SIGNIN_ACTIVITY_UNAVAILABLE')).toBe(true);
  });

  it('fails a dataset whose response does not match the schema instead of guessing', async () => {
    const graph = mockGraph({
      '/policies/identitySecurityDefaultsEnforcementPolicy': () =>
        json({ displayName: 'no isEnabled here' }),
    });
    const bundle = await collectEntra(options(graph.fetch));
    expect(dataset(bundle, 'entra.securityDefaults').collectionStatus).toBe('Failed');
    expect(bundle.issues.some((i) => i.code === 'DATA_INVALID')).toBe(true);
    expect(controlStatus(bundle, 'ENTRA-CA-001')).toBe('NOT_ASSESSED');
  });

  it('fails a dataset whose response exceeds the size limit', async () => {
    const graph = mockGraph({
      '/roleManagement/directory/roleDefinitions': () =>
        json({ value: [{ id: 'x', displayName: 'y'.repeat(5000), isBuiltIn: true }] }),
    });
    const bundle = await collectEntra(options(graph.fetch, { limits: { maxResponseBytes: 4096 } }));
    expect(dataset(bundle, 'entra.roleDefinitions').collectionStatus).toBe('Failed');
    expect(
      bundle.issues.some((i) => i.datasetId === 'entra.roleDefinitions' && i.code === 'TOO_LARGE'),
    ).toBe(true);
  });

  it('refuses to produce evidence for a different tenant', async () => {
    const graph = mockGraph({
      '/organization': () =>
        json({
          value: [
            {
              id: '99999999-2222-4333-8444-555555555555',
              displayName: 'Other',
              verifiedDomains: [],
            },
          ],
        }),
    });
    await rejectsWith(collectEntra(options(graph.fetch)), 'TENANT_MISMATCH');
  });

  it('stops before collecting evidence when tenant identity cannot be verified', async () => {
    for (const response of [
      () => graphError(403, 'Authorization_RequestDenied', 'denied'),
      () => json({ value: [{ displayName: 'Missing ID' }] }),
    ]) {
      const graph = mockGraph({ '/organization': response });
      await rejectsWith(collectEntra(options(graph.fetch)), 'TENANT_NOT_VERIFIED');
      expect(graph.calls).toHaveLength(1);
    }
  });

  it('does not interpret missing authentication configurations as an empty successful dataset', async () => {
    const graph = mockGraph({
      '/policies/authenticationMethodsPolicy': () =>
        json({ policyMigrationState: 'migrationComplete' }),
    });
    const bundle = await collectEntra(options(graph.fetch));
    expect(dataset(bundle, 'entra.authenticationMethodsPolicy').collectionStatus).toBe('Failed');
  });

  it('does not infer licence absence from malformed SKU evidence', async () => {
    const graph = mockGraph({
      '/subscribedSkus': () => json({ value: [{ skuId: 'invalid-guid', servicePlans: [] }] }),
    });
    const bundle = await collectEntra(options(graph.fetch));
    expect(dataset(bundle, 'entra.subscribedSkus').collectionStatus).toBe('Failed');
    expect(dataset(bundle, 'entra.conditionalAccessPolicies').collectionStatus).toBe('Success');
  });

  it('treats omitted licence plans and authentication targets as incomplete evidence', async () => {
    const graph = mockGraph({
      '/subscribedSkus': () =>
        json({
          value: [
            {
              skuId: TENANT_ID,
              skuPartNumber: 'TEST',
              capabilityStatus: 'Enabled',
              consumedUnits: 1,
              prepaidUnits: { enabled: 1 },
            },
          ],
        }),
      '/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Sms': () =>
        json({ id: 'Sms', state: 'disabled' }),
    });
    const bundle = await collectEntra(options(graph.fetch));
    expect(dataset(bundle, 'entra.subscribedSkus').collectionStatus).toBe('Partial');
    expect(dataset(bundle, 'entra.authenticationMethodsPolicy').collectionStatus).toBe('Partial');
    expect(dataset(bundle, 'entra.conditionalAccessPolicies').collectionStatus).toBe('Success');
  });

  it('validates inputs without echoing the token', async () => {
    const graph = mockGraph();
    await rejectsWith(
      collectEntra(options(graph.fetch, { tenantId: 'contoso.example' })),
      'INVALID_TENANT_ID',
    );
    const badToken = 'abc\r\nX-Injected: 1';
    await expect(collectEntra(options(graph.fetch, { accessToken: badToken }))).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof AdminSecOpsError &&
        error.code === 'INVALID_ACCESS_TOKEN' &&
        !error.message.includes('abc'),
    );
    expect(graph.calls).toHaveLength(0);
  });
});

describe('bounded retry and cancellation', () => {
  const SD = `${GRAPH_BASE}/policies/identitySecurityDefaultsEnforcementPolicy`;

  it('retries 429 a bounded number of times with a capped Retry-After, then fails the dataset', async () => {
    const graph = mockGraph({
      '/policies/identitySecurityDefaultsEnforcementPolicy': () =>
        json({ error: { code: 'TooManyRequests' } }, 429, { 'retry-after': '3600' }),
    });
    const started = Date.now();
    const bundle = await collectEntra(
      options(graph.fetch, { limits: { maxRetries: 2, maxRetryDelayMs: 5 } }),
    );
    expect(Date.now() - started).toBeLessThan(5000); // Retry-After: 3600 was capped
    expect(graph.calls.filter((c) => c.url === SD)).toHaveLength(3);
    const sd = dataset(bundle, 'entra.securityDefaults');
    expect(sd.collectionStatus).toBe('Failed');
    expect(
      bundle.issues.some((i) => i.datasetId === 'entra.securityDefaults' && i.code === 'HTTP_429'),
    ).toBe(true);
  });

  it('recovers after a transient 503', async () => {
    let attempts = 0;
    const graph = mockGraph({
      '/policies/identitySecurityDefaultsEnforcementPolicy': () => {
        attempts += 1;
        return attempts === 1
          ? json({ error: { code: 'ServiceUnavailable' } }, 503, { 'retry-after': '0' })
          : json({ isEnabled: false });
      },
    });
    const bundle = await collectEntra(options(graph.fetch, { limits: { maxRetryDelayMs: 5 } }));
    expect(attempts).toBe(2);
    expect(dataset(bundle, 'entra.securityDefaults').state).toBe('available');
  });

  it('does not retry other errors', async () => {
    const graph = mockGraph({
      '/policies/identitySecurityDefaultsEnforcementPolicy': () =>
        graphError(500, 'InternalServerError', 'x'),
    });
    await collectEntra(options(graph.fetch, { limits: { maxRetryDelayMs: 5 } }));
    expect(graph.calls.filter((c) => c.url === SD)).toHaveLength(1);
  });

  it('does not send any request when the signal is already aborted', async () => {
    const graph = mockGraph();
    const controller = new AbortController();
    controller.abort();
    await rejectsWith(
      collectEntra(options(graph.fetch, { signal: controller.signal })),
      'COLLECTION_CANCELLED',
    );
    expect(graph.calls).toHaveLength(0);
  });

  it('aborts an in-flight request and produces no bundle', async () => {
    const controller = new AbortController();
    const hanging = vi.fn(
      (_input: string | URL | Request, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () =>
            reject(new DOMException('The operation was aborted.', 'AbortError')),
          );
          setTimeout(() => controller.abort(), 5);
        }),
    );
    await rejectsWith(
      collectEntra(options(hanging, { signal: controller.signal })),
      'COLLECTION_CANCELLED',
    );
    expect(hanging).toHaveBeenCalledTimes(1);
  });

  it('cancels while waiting to retry', async () => {
    const controller = new AbortController();
    const graph = mockGraph({
      '/organization': () => {
        setTimeout(() => controller.abort(), 10);
        return json({ error: { code: 'TooManyRequests' } }, 429, { 'retry-after': '60' });
      },
    });
    const started = Date.now();
    await rejectsWith(
      collectEntra(
        options(graph.fetch, { signal: controller.signal, limits: { maxRetryDelayMs: 60_000 } }),
      ),
      'COLLECTION_CANCELLED',
    );
    expect(Date.now() - started).toBeLessThan(5000);
    expect(graph.calls).toHaveLength(1);
  });

  it('times out a hanging request and reports the dataset Failed', async () => {
    const graph = mockGraph({
      '/policies/identitySecurityDefaultsEnforcementPolicy': (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () =>
            reject(new DOMException('The operation was aborted.', 'AbortError')),
          );
        }),
    });
    const bundle = await collectEntra(options(graph.fetch, { limits: { requestTimeoutMs: 20 } }));
    expect(dataset(bundle, 'entra.securityDefaults').collectionStatus).toBe('Failed');
    expect(bundle.issues.some((i) => i.code === 'TIMEOUT')).toBe(true);
  });
});

describe('required permissions', () => {
  it('lists only permissions declared by the dataset definitions', () => {
    expect(ENTRA_REQUIRED_GRAPH_PERMISSIONS).toEqual(
      expect.arrayContaining([
        'Organization.Read.All',
        'Policy.Read.All',
        'RoleManagement.Read.Directory',
        'AuditLog.Read.All',
        'User.Read.All',
      ]),
    );
    for (const { permission, datasets } of ENTRA_GRAPH_PERMISSIONS) {
      expect(permission).toMatch(/^[A-Za-z]+(\.[A-Za-z]+)+$/);
      for (const id of datasets) {
        expect(
          getDatasetDefinition(id)?.permissions.some((p) => p.startsWith(`Graph: ${permission}`)),
        ).toBe(true);
      }
    }
    expect(ENTRA_REQUIRED_GRAPH_PERMISSIONS.some((p) => /Write/i.test(p))).toBe(false);
  });
});
