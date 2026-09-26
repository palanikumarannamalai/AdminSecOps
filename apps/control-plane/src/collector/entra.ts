import { AdminSecOpsError } from '@adminsecops/core';
import type { EvidenceBundle } from '@adminsecops/evidence/browser';
import {
  ENTRA_DATASETS,
  GuidSchema,
  entraAuthenticationMethodsPolicy,
  entraAuthorizationPolicy,
  entraConditionalAccessPolicies,
  entraGuestUsers,
  entraOrganization,
  entraRoleAssignments,
  entraRoleDefinitions,
  entraSecurityDefaults,
  entraSubscribedSkus,
  entraUserRegistrationDetails,
  type DatasetDefinition,
} from '@adminsecops/schemas';
import { GRAPH_BASE, GraphRequestError } from './graph-client.js';
import {
  HOSTED_COLLECTOR_NAME,
  HOSTED_COLLECTOR_VERSION,
  collectHostedEvidence,
  type CollectionPlan,
  type HostedCollectionOptions,
  type HostedCollectionResult,
} from './package.js';
import {
  HOSTED_PERMISSION_OVERRIDES,
  arr,
  getAll,
  getOne,
  hostedGraphPermissionsOf,
  licensed,
  safeId,
  message,
  firstOf,
  pick,
  pickOrNull,
  rec,
  val,
  type DatasetCollector,
  type DatasetState,
  type Rec,
} from './runtime.js';

export { HOSTED_COLLECTOR_NAME, HOSTED_COLLECTOR_VERSION };

/**
 * Datasets the Entra-only collection (collectEntra) produces, in collection order.
 * subscribedSkus is collected before the licence-dependent datasets. Every other Entra
 * dataset in the schema registry is left out of the package (absent), so controls needing
 * it are NOT_ASSESSED. The unified online collection (online.ts) adds entra.groupSettings.
 */
export const HOSTED_ENTRA_DATASETS = [
  entraOrganization,
  entraSubscribedSkus,
  entraSecurityDefaults,
  entraAuthorizationPolicy,
  entraAuthenticationMethodsPolicy,
  entraConditionalAccessPolicies,
  entraUserRegistrationDetails,
  entraRoleDefinitions,
  entraRoleAssignments,
  entraGuestUsers,
] as const satisfies readonly DatasetDefinition[];

const COLLECTED_IDS: ReadonlySet<string> = new Set(HOSTED_ENTRA_DATASETS.map((d) => d.id));

/** Entra datasets defined by the schema registry that collectEntra does not produce. */
export const HOSTED_ENTRA_UNSUPPORTED_DATASETS: readonly string[] = ENTRA_DATASETS.map(
  (d) => d.id,
).filter((id) => !COLLECTED_IDS.has(id));

export { HOSTED_PERMISSION_OVERRIDES };

export interface GraphPermissionRequirement {
  /** Microsoft Graph permission name, e.g. Policy.Read.All. */
  readonly permission: string;
  readonly datasets: readonly string[];
}

/**
 * Microsoft Graph permissions needed by a set of datasets, derived from the `permissions`
 * of the dataset definitions (the single source of truth) - nothing is added here.
 */
export function derivePermissions(
  definitions: readonly DatasetDefinition[],
): GraphPermissionRequirement[] {
  const byPermission = new Map<string, string[]>();
  for (const definition of definitions) {
    for (const permission of hostedGraphPermissionsOf(definition)) {
      const list = byPermission.get(permission) ?? [];
      list.push(definition.id);
      byPermission.set(permission, list);
    }
  }
  return [...byPermission.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([permission, datasets]) => ({ permission, datasets }));
}

/**
 * Microsoft Graph permissions needed by collectEntra. Entries that are not Graph
 * permissions (e.g. directory-role requirements) are listed in ENTRA_ADDITIONAL_REQUIREMENTS.
 */
export const ENTRA_GRAPH_PERMISSIONS: readonly GraphPermissionRequirement[] =
  derivePermissions(HOSTED_ENTRA_DATASETS);
export const ENTRA_REQUIRED_GRAPH_PERMISSIONS: readonly string[] = ENTRA_GRAPH_PERMISSIONS.map(
  (p) => p.permission,
);
export const ENTRA_ADDITIONAL_REQUIREMENTS: readonly {
  readonly datasetId: string;
  readonly requirement: string;
}[] = HOSTED_ENTRA_DATASETS.flatMap((d) =>
  d.permissions
    .filter((p) => !p.startsWith('Graph: '))
    .map((requirement) => ({ datasetId: d.id, requirement })),
);

/** Service plans that license a feature (same plan names as the PowerShell collector). */
const P1_PLANS = ['AAD_PREMIUM', 'AAD_PREMIUM_P2'];
/** Privileged Identity Management: Microsoft Entra ID P2 or Microsoft Entra ID Governance. */
const PIM_PLANS = ['AAD_PREMIUM_P2', 'Entra_Identity_Governance', 'ENTRA_IDENTITY_GOVERNANCE'];

/** Resource applications whose app-only grants are collected (same as the PowerShell collector). */
const GRANT_RESOURCE_APP_IDS = ['00000003-0000-0000-c000-000000000000', '00000002-0000-0ff1-ce00-000000000000'] as const;

export type CollectEntraOptions = HostedCollectionOptions;
export type EntraCollectionResult = HostedCollectionResult;

/**
 * Collect Microsoft Entra evidence read-only through Microsoft Graph v1.0 and return a
 * verified evidence bundle. Datasets that cannot be read are reported with an honest
 * status (Unauthorized / Failed / Partial / NotApplicable) and never as passing data.
 * Throws CollectionCancelledError when `signal` aborts. For the multi-workload online
 * assessment use collectOnline (online.ts).
 */
export async function collectEntra(options: CollectEntraOptions): Promise<EvidenceBundle> {
  return (await collectEntraEvidence(options)).bundle;
}

export async function collectEntraEvidence(
  options: CollectEntraOptions,
): Promise<EntraCollectionResult> {
  const plan: CollectionPlan = {
    datasets: HOSTED_ENTRA_DATASETS.map((definition) => ({
      definition,
      collector: entraCollector(definition.id),
    })),
    notCollected: new Map([['Entra', HOSTED_ENTRA_UNSUPPORTED_DATASETS]]),
    skippedModules: [],
  };
  return collectHostedEvidence(options, plan);
}

/** The hosted collector for an Entra dataset; throws for datasets without one. */
export function entraCollector(id: string): DatasetCollector {
  const collector = ENTRA_COLLECTORS[id];
  if (collector === undefined) throw new Error(`No hosted collector for ${id}`);
  return collector;
}

function principalType(odataType: unknown): string {
  if (typeof odataType !== 'string') return 'other';
  const t = odataType.replace(/^#?microsoft\.graph\./, '');
  return t === 'user' || t === 'group' || t === 'servicePrincipal' ? t : 'other';
}

const strings = (v: unknown): unknown[] | null => arr(v);

/** onPremisesDirectorySynchronizationFeature properties declared by the dataset schema. */
const SYNC_FEATURES = [
  'passwordSyncEnabled',
  'passwordWritebackEnabled',
  'blockSoftMatchEnabled',
  'blockCloudObjectTakeoverThroughHardMatchEnabled',
  'softMatchOnUpnEnabled',
  'userWritebackEnabled',
  'deviceWritebackEnabled',
  'passThroughAuthenticationEnabled',
  'synchronizeUpnForManagedUsersEnabled',
];

/**
 * Credential metadata only (key ID, name, validity, and key type/usage). Secret text, hints
 * and key material are never copied. A credential list that was not returned makes the
 * dataset Partial rather than looking like "no credentials".
 */
function credentials(state: DatasetState, owner: Rec | undefined, property: 'passwordCredentials' | 'keyCredentials', key: boolean): Rec[] {
  const list = arr(val(owner, property));
  if (list === null) {
    state.partial = true;
    state.errors.push(
      message('CREDENTIALS_MISSING', `The ${property} of an application object were not returned; credential coverage is incomplete.`, typeof owner?.['id'] === 'string' ? owner['id'] : null),
    );
    return [];
  }
  return list.map((c) => pick(rec(c), key ? ['keyId', 'displayName', 'startDateTime', 'endDateTime', 'type', 'usage'] : ['keyId', 'displayName', 'startDateTime', 'endDateTime']));
}

/**
 * Directory setting values that may be collected (same allowlist as the PowerShell
 * collector). Anything else - for example custom banned password lists - is dropped.
 */
const GROUP_SETTING_ALLOWLIST: ReadonlySet<string> = new Set([
  'EnableBannedPasswordCheckOnPremises',
  'BannedPasswordCheckOnPremisesMode',
  'EnableBannedPasswordCheck',
  'LockoutThreshold',
  'LockoutDurationInSeconds',
  'EnableGroupCreation',
  'AllowGuestsToAccessGroups',
  'AllowGuestsToBeGroupOwner',
  'AllowToAddGuests',
  'EnableMIPLabels',
  'EnableMSStandardBlockedWords',
  'NewUnifiedGroupWritebackDefault',
  'EnableGroupSpecificConsent',
  'BlockUserConsentForRiskyApps',
  'EnableAdminConsentRequests',
  'ConstrainGroupSpecificConsentToMembersOfGroupId',
]);

// ---------------------------------------------------------------------------------------------
// Dataset collectors
// ---------------------------------------------------------------------------------------------

const ENTRA_COLLECTORS: Record<string, DatasetCollector> = {
  'entra.organization': async (state, context) => {
    const orgs = await getAll(state, context, `${GRAPH_BASE}/organization`);
    const org = rec(orgs[0]);
    if (org === undefined)
      throw new GraphRequestError(
        'invalid-response',
        'The organization endpoint returned no tenant.',
      );
    const id = val(org, 'id');
    if (typeof id !== 'string' || !GuidSchema.safeParse(id).success)
      throw new GraphRequestError(
        'invalid-response',
        'The organization response did not contain a valid tenant ID.',
      );
    if (typeof id === 'string' && id.toLowerCase() !== context.tenantId) {
      throw new AdminSecOpsError(
        'TENANT_MISMATCH',
        'The access token belongs to a different tenant than the one requested. No evidence was produced.',
        { statusCode: 409 },
      );
    }
    const verifiedDomains =
      arr(val(org, 'verifiedDomains'))?.map((d) =>
        pick(rec(d), ['name', 'isDefault', 'isInitial', 'type', 'capabilities']),
      ) ?? null;
    const displayName = val(org, 'displayName');
    const primary = verifiedDomains?.find((d) => d['isDefault'] === true)?.['name'];
    context.organization = {
      displayName: typeof displayName === 'string' ? displayName.slice(0, 500) : null,
      primaryDomain: typeof primary === 'string' ? primary.slice(0, 500) : null,
    };
    context.verifiedDomains = (verifiedDomains ?? []).flatMap((d) =>
      typeof d['name'] === 'string'
        ? [{ name: d['name'], capabilities: typeof d['capabilities'] === 'string' ? d['capabilities'] : null }]
        : [],
    );
    return {
      id,
      displayName,
      createdDateTime: val(org, 'createdDateTime'),
      onPremisesSyncEnabled: val(org, 'onPremisesSyncEnabled'),
      onPremisesLastSyncDateTime: val(org, 'onPremisesLastSyncDateTime'),
      verifiedDomains,
    };
  },

  'entra.subscribedSkus': async (state, context) => {
    context.servicePlans = null;
    const skus = (await getAll(state, context, `${GRAPH_BASE}/subscribedSkus`)).map((s) => rec(s));
    if (skus.some((sku) => !Array.isArray(sku?.['servicePlans']))) {
      state.partial = true;
      state.errors.push(
        message(
          'SERVICE_PLANS_MISSING',
          'Service plan details were missing; licence availability could not be determined.',
        ),
      );
    }
    return skus.map((sku) => ({
      skuId: val(sku, 'skuId'),
      skuPartNumber: val(sku, 'skuPartNumber'),
      capabilityStatus: val(sku, 'capabilityStatus'),
      consumedUnits: val(sku, 'consumedUnits'),
      prepaidUnits: pickOrNull(val(sku, 'prepaidUnits'), ['enabled', 'suspended', 'warning']),
      servicePlans:
        arr(val(sku, 'servicePlans'))?.map((p) =>
          pick(rec(p), ['servicePlanId', 'servicePlanName', 'provisioningStatus', 'appliesTo']),
        ) ?? null,
    }));
  },

  'entra.securityDefaults': async (state, context) => {
    const policy = await getOne(
      state,
      context,
      `${GRAPH_BASE}/policies/identitySecurityDefaultsEnforcementPolicy`,
    );
    return { isEnabled: val(policy, 'isEnabled') };
  },

  'entra.authorizationPolicy': async (state, context) => {
    const response = await getOne(state, context, `${GRAPH_BASE}/policies/authorizationPolicy`);
    // v1.0 returns a single object; tolerate the collection form as well.
    const list = arr(response['value']);
    const policy = list !== null ? rec(list[0]) : response;
    if (policy === undefined)
      throw new GraphRequestError(
        'invalid-response',
        'The authorization policy response contained no policy.',
      );
    return {
      ...pick(policy, [
        'allowInvitesFrom',
        'allowedToSignUpEmailBasedSubscriptions',
        'allowEmailVerifiedUsersToJoinOrganization',
        'allowUserConsentForRiskyApps',
        'blockMsolPowerShell',
        'guestUserRoleId',
      ]),
      permissionGrantPolicyIdsAssignedToDefaultUserRole: strings(
        val(policy, 'permissionGrantPolicyIdsAssignedToDefaultUserRole'),
      ),
      defaultUserRolePermissions: pickOrNull(val(policy, 'defaultUserRolePermissions'), [
        'allowedToCreateApps',
        'allowedToCreateSecurityGroups',
        'allowedToCreateTenants',
        'allowedToReadBitlockerKeysForOwnedDevice',
        'allowedToReadOtherUsers',
      ]),
    };
  },

  'entra.authenticationMethodsPolicy': async (state, context) => {
    const policy = await getOne(
      state,
      context,
      `${GRAPH_BASE}/policies/authenticationMethodsPolicy`,
    );
    const configs = arr(val(policy, 'authenticationMethodConfigurations'));
    if (configs === null)
      throw new GraphRequestError(
        'invalid-response',
        'Authentication method configurations were absent from the response.',
      );
    const out: Rec[] = [];
    let lookups = 0;
    for (const raw of configs) {
      const config = rec(raw);
      const id = val(config, 'id');
      let source = config;
      if (config !== undefined && !('includeTargets' in config)) {
        // includeTargets is not always returned inline; read the individual configuration.
        if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,100}$/.test(id) || lookups >= 50) {
          state.errors.push(
            message(
              'METHOD_CONFIGURATION_UNREADABLE',
              'The targets of an authentication method configuration could not be read.',
              typeof id === 'string' ? id.slice(0, 100) : null,
            ),
          );
          state.partial = true;
        } else {
          lookups += 1;
          const url = `${GRAPH_BASE}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/${encodeURIComponent(id)}`;
          if (lookups === 1)
            state.operations.push(
              `GET ${GRAPH_BASE}/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/{id}`,
            );
          try {
            source = rec(await context.client.get(url)) ?? config;
          } catch (error) {
            if (!(error instanceof GraphRequestError)) throw error;
            state.errors.push(
              message(
                'METHOD_CONFIGURATION_UNREADABLE',
                `The targets of the '${id}' method could not be read. ${error.message}`,
                id,
              ),
            );
            state.partial = true;
          }
        }
      }
      if (!Array.isArray(source?.['includeTargets'])) {
        state.partial = true;
        state.errors.push(
          message(
            'METHOD_TARGETS_MISSING',
            'Authentication method targets were absent; coverage is incomplete.',
          ),
        );
      }
      out.push({
        id,
        state: val(config, 'state'),
        includeTargets:
          arr(val(source, 'includeTargets'))?.map((t) => pick(rec(t), ['targetType', 'id'])) ??
          null,
      });
    }
    return {
      policyMigrationState: val(policy, 'policyMigrationState'),
      authenticationMethodConfigurations: out,
    };
  },

  'entra.conditionalAccessPolicies': async (state, context) => {
    if (!licensed(state, context, P1_PLANS, 'Conditional Access (Microsoft Entra ID P1)'))
      return null;
    const policies = await getAll(
      state,
      context,
      `${GRAPH_BASE}/identity/conditionalAccess/policies`,
    );
    return policies.map((raw) => {
      const p = rec(raw);
      const cond = rec(val(p, 'conditions'));
      // Preserve uncertainty when Graph returns scope dimensions the evaluator does not model.
      const applications = rec(val(cond, 'applications'));
      const unsupportedScope =
        ['clientApplications', 'servicePrincipalRiskLevels', 'insiderRiskLevels'].some((key) => {
          const value = val(cond, key);
          return value !== null && (!Array.isArray(value) || value.length > 0);
        }) || val(applications, 'applicationFilter') !== null;
      if (unsupportedScope) {
        state.partial = true;
        state.warnings.push(
          message(
            'CA_SCOPE_NOT_MODELED',
            'A Conditional Access policy uses scope conditions not modeled by this evaluator; passing checks require review.',
          ),
        );
      }
      const users = rec(val(cond, 'users'));
      const grant = rec(val(p, 'grantControls'));
      const session = rec(val(p, 'sessionControls'));
      const flows = rec(val(cond, 'authenticationFlows'));
      return {
        ...pick(p, ['id', 'displayName', 'state', 'createdDateTime', 'modifiedDateTime']),
        conditions: {
          users:
            users === undefined
              ? null
              : {
                  ...pick(users, [
                    'includeUsers',
                    'excludeUsers',
                    'includeGroups',
                    'excludeGroups',
                    'includeRoles',
                    'excludeRoles',
                  ]),
                  includeGuestsOrExternalUsers: val(users, 'includeGuestsOrExternalUsers'),
                  excludeGuestsOrExternalUsers: val(users, 'excludeGuestsOrExternalUsers'),
                },
          applications: pickOrNull(val(cond, 'applications'), [
            'includeApplications',
            'excludeApplications',
            'includeUserActions',
            'includeAuthenticationContextClassReferences',
          ]),
          clientAppTypes: strings(val(cond, 'clientAppTypes')),
          signInRiskLevels: strings(val(cond, 'signInRiskLevels')),
          userRiskLevels: strings(val(cond, 'userRiskLevels')),
          platforms: pickOrNull(val(cond, 'platforms'), ['includePlatforms', 'excludePlatforms']),
          locations: pickOrNull(val(cond, 'locations'), ['includeLocations', 'excludeLocations']),
          devices: pickOrNull(val(cond, 'devices'), [
            'includeDevices',
            'excludeDevices',
            'deviceFilter',
          ]),
          authenticationFlows:
            flows === undefined ? null : { transferMethods: val(flows, 'transferMethods') },
        },
        grantControls:
          grant === undefined
            ? null
            : {
                ...pick(grant, [
                  'operator',
                  'builtInControls',
                  'customAuthenticationFactors',
                  'termsOfUse',
                ]),
                authenticationStrength: pickOrNull(val(grant, 'authenticationStrength'), [
                  'id',
                  'displayName',
                  'requirementsSatisfied',
                ]),
              },
        sessionControls:
          session === undefined
            ? null
            : {
                signInFrequency: pickOrNull(val(session, 'signInFrequency'), [
                  'isEnabled',
                  'value',
                  'type',
                  'frequencyInterval',
                ]),
                persistentBrowser: pickOrNull(val(session, 'persistentBrowser'), [
                  'isEnabled',
                  'mode',
                ]),
              },
      };
    });
  },

  'entra.userRegistrationDetails': async (state, context) => {
    if (
      !licensed(
        state,
        context,
        P1_PLANS,
        'Authentication methods activity reports (Microsoft Entra ID P1/P2)',
      )
    )
      return null;
    const items = await getAll(
      state,
      context,
      `${GRAPH_BASE}/reports/authenticationMethods/userRegistrationDetails`,
    );
    return items.map((raw) =>
      pick(rec(raw), [
        'id',
        'userPrincipalName',
        'userType',
        'isAdmin',
        'isMfaRegistered',
        'isMfaCapable',
        'isPasswordlessCapable',
        'isSsprRegistered',
        'methodsRegistered',
      ]),
    );
  },

  'entra.roleDefinitions': async (state, context) => {
    const items = await getAll(
      state,
      context,
      `${GRAPH_BASE}/roleManagement/directory/roleDefinitions`,
    );
    // isPrivileged is only returned by the beta endpoint; it stays null from v1.0.
    return items.map((raw) =>
      pick(rec(raw), ['id', 'displayName', 'templateId', 'isBuiltIn', 'isEnabled', 'isPrivileged']),
    );
  },

  'entra.roleAssignments': async (state, context) => {
    const items = await getAll(
      state,
      context,
      `${GRAPH_BASE}/roleManagement/directory/roleAssignments?$expand=principal`,
    );
    return items.map((raw) => {
      const a = rec(raw);
      const principal = rec(val(a, 'principal'));
      return {
        ...pick(a, ['id', 'roleDefinitionId', 'principalId', 'directoryScopeId']),
        principal:
          principal === undefined
            ? null
            : {
                ...pick(principal, [
                  'id',
                  'displayName',
                  'userPrincipalName',
                  'userType',
                  'accountEnabled',
                  'onPremisesSyncEnabled',
                ]),
                principalType: principalType(principal['@odata.type']),
              },
      };
    });
  },

  'entra.guestUsers': async (state, context) => {
    const base = `${GRAPH_BASE}/users?$filter=${encodeURIComponent("userType eq 'Guest'")}&$top=999&$select=`;
    const fields = 'id,userPrincipalName,accountEnabled,createdDateTime,externalUserState';
    let items: unknown[];
    let withActivity = true;
    try {
      items = await getAll(state, context, `${base}${fields},signInActivity`);
    } catch (error) {
      // signInActivity needs AuditLog.Read.All and Entra ID P1/P2; collect the rest and flag the gap.
      if (
        !(error instanceof GraphRequestError) ||
        error.kind !== 'http' ||
        !(error.status === 403 || error.licenceHint)
      )
        throw error;
      withActivity = false;
      items = await getAll(state, context, `${base}${fields}`);
      state.errors.push(
        message(
          'SIGNIN_ACTIVITY_UNAVAILABLE',
          `Last sign-in times are unavailable (${error.message} signInActivity requires AuditLog.Read.All and Microsoft Entra ID P1/P2). Guest accounts were collected without activity data.`,
        ),
      );
      state.partial = true;
    }
    return items.map((raw) => {
      const u = rec(raw);
      const activity = withActivity ? rec(val(u, 'signInActivity')) : undefined;
      return {
        ...pick(u, [
          'id',
          'userPrincipalName',
          'accountEnabled',
          'createdDateTime',
          'externalUserState',
        ]),
        lastSignInDateTime: val(activity, 'lastSignInDateTime'),
        lastNonInteractiveSignInDateTime: val(activity, 'lastNonInteractiveSignInDateTime'),
      };
    });
  },

  'entra.roleAssignmentScheduleInstances': async (state, context) => {
    if (!licensed(state, context, PIM_PLANS, 'Privileged Identity Management (Microsoft Entra ID P2 or ID Governance)')) return null;
    const items = await getAll(state, context, `${GRAPH_BASE}/roleManagement/directory/roleAssignmentScheduleInstances`);
    return items.map((raw) =>
      pick(rec(raw), ['id', 'roleDefinitionId', 'principalId', 'directoryScopeId', 'assignmentType', 'memberType', 'startDateTime', 'endDateTime']),
    );
  },

  'entra.roleEligibilitySchedules': async (state, context) => {
    if (!licensed(state, context, PIM_PLANS, 'Privileged Identity Management (Microsoft Entra ID P2 or ID Governance)')) return null;
    const items = await getAll(state, context, `${GRAPH_BASE}/roleManagement/directory/roleEligibilitySchedules`);
    return items.map((raw) => {
      const s = rec(raw);
      // v1.0 reports the schedule in scheduleInfo; a missing expiration end means "no expiration".
      const schedule = rec(val(s, 'scheduleInfo'));
      return {
        ...pick(s, ['id', 'roleDefinitionId', 'principalId', 'directoryScopeId', 'memberType']),
        startDateTime: firstOf(s, ['startDateTime']) ?? val(schedule, 'startDateTime'),
        endDateTime: firstOf(s, ['endDateTime']) ?? val(rec(val(schedule, 'expiration')), 'endDateTime'),
      };
    });
  },

  'entra.applications': async (state, context) => {
    const items = await getAll(
      state,
      context,
      `${GRAPH_BASE}/applications?$select=id,appId,displayName,signInAudience,createdDateTime,passwordCredentials,keyCredentials&$top=999`,
    );
    return items.map((raw) => {
      const app = rec(raw);
      return {
        ...pick(app, ['id', 'appId', 'displayName', 'signInAudience', 'createdDateTime']),
        passwordCredentials: credentials(state, app, 'passwordCredentials', false),
        keyCredentials: credentials(state, app, 'keyCredentials', true),
      };
    });
  },

  'entra.servicePrincipals': async (state, context) => {
    // The maximum page size of this list is 100, which is also the default.
    const items = await getAll(
      state,
      context,
      `${GRAPH_BASE}/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,passwordCredentials,keyCredentials`,
    );
    return items.map((raw) => {
      const sp = rec(raw);
      return {
        ...pick(sp, ['id', 'appId', 'displayName', 'servicePrincipalType', 'appOwnerOrganizationId', 'accountEnabled']),
        passwordCredentials: credentials(state, sp, 'passwordCredentials', false),
        keyCredentials: credentials(state, sp, 'keyCredentials', true),
      };
    });
  },

  'entra.apiPermissionGrants': async (state, context) => {
    const out: Rec[] = [];
    let readable = 0;
    for (const appId of GRANT_RESOURCE_APP_IDS) {
      context.client.throwIfCancelled();
      let resource: Rec;
      try {
        resource = await getOne(state, context, `${GRAPH_BASE}/servicePrincipals(appId='${appId}')?$select=id,appId,displayName,appRoles`);
      } catch (error) {
        if (!(error instanceof GraphRequestError)) throw error;
        // Denied access applies to the whole dataset; it is reported Unauthorized, not empty.
        if (error.kind === 'http' && (error.status === 401 || error.status === 403)) throw error;
        if (error.kind === 'http' && error.status === 404) {
          state.warnings.push(message('RESOURCE_NOT_PRESENT', 'The resource service principal does not exist in this tenant, so no application can hold its permissions.', appId));
          readable += 1;
        } else {
          state.partial = true;
          state.errors.push(message('RESOURCE_UNREADABLE', `The resource service principal could not be read; its grants are not included. ${error.message}`, appId));
        }
        continue;
      }
      const resourceId = safeId(val(resource, 'id'));
      if (resourceId === undefined) {
        state.partial = true;
        state.errors.push(message('RESOURCE_UNREADABLE', 'The resource service principal was returned without a valid identifier.', appId));
        continue;
      }
      readable += 1;
      const assignments = await getAll(
        state,
        context,
        `${GRAPH_BASE}/servicePrincipals/${encodeURIComponent(resourceId)}/appRoleAssignedTo`,
        context.client,
        `${GRAPH_BASE}/servicePrincipals/{resourceId}/appRoleAssignedTo`,
      );
      const roles = arr(val(resource, 'appRoles'));
      if (roles === null) {
        state.partial = true;
        state.errors.push(message('APP_ROLES_MISSING', 'The application roles of a resource were not returned; permission names cannot be resolved.', appId));
      }
      out.push({
        resourceAppId: appId,
        resourceDisplayName: val(resource, 'displayName'),
        appRoles: (roles ?? []).map((r) => pick(rec(r), ['id', 'value'])),
        assignments: assignments.map((a) =>
          pick(rec(a), ['id', 'principalId', 'principalType', 'principalDisplayName', 'appRoleId', 'createdDateTime']),
        ),
      });
    }
    if (readable === 0) {
      throw new GraphRequestError('invalid-response', 'None of the resource service principals could be read; application permission grants are unknown.');
    }
    return out;
  },

  'entra.onPremisesSynchronization': async (state, context) => {
    // Delegated only; Microsoft documents Global Administrator as the only supported role. Other
    // roles receive 403, which is reported Unauthorized (never as a passing configuration).
    const body = await getOne(state, context, `${GRAPH_BASE}/directory/onPremisesSynchronization`);
    const list = arr(body['value']) ?? [body];
    return list.map((raw) => {
      const item = rec(raw);
      const features = rec(val(item, 'features'));
      return {
        id: val(item, 'id'),
        // passThroughAuthenticationEnabled is not a property of this resource and stays null.
        features: features === undefined ? null : pick(features, SYNC_FEATURES),
      };
    });
  },

  'entra.groupSettings': async (state, context) => {
    const items = await getAll(state, context, `${GRAPH_BASE}/groupSettings`);
    let dropped = 0;
    const out = items.map((raw) => {
      const s = rec(raw);
      const values: Rec[] = [];
      const rawValues = arr(val(s, 'values'));
      if (rawValues === null) {
        state.partial = true;
        state.errors.push(
          message('SETTING_VALUES_MISSING', 'A directory settings object was returned without values.', typeof val(s, 'id') === 'string' ? (val(s, 'id') as string) : null),
        );
      }
      for (const v of rawValues ?? []) {
        const name = val(rec(v), 'name');
        if (typeof name !== 'string' || !GROUP_SETTING_ALLOWLIST.has(name)) {
          dropped += 1;
          continue;
        }
        values.push({ name, value: val(rec(v), 'value') });
      }
      return { ...pick(s, ['id', 'displayName', 'templateId']), values };
    });
    if (dropped > 0) {
      state.warnings.push(
        message(
          'SETTINGS_FILTERED',
          `${dropped} setting value(s) not on the allow-list (for example custom banned password lists) were not collected.`,
        ),
      );
    }
    return out;
  },
};
