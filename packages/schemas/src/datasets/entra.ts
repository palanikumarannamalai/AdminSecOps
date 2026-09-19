import { z } from 'zod';
import { GuidSchema, list, optBool, optNumber, optString, optTimestamp } from '../common.js';
import { defineDataset } from './define.js';

const GRAPH = 'https://graph.microsoft.com/v1.0';

export const entraOrganization = defineDataset({
  id: 'entra.organization',
  module: 'Entra',
  technology: 'entra',
  title: 'Tenant organization',
  description: 'Tenant identity, verified domains and directory synchronisation state.',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/organization`],
  permissions: ['Graph: Organization.Read.All'],
  personalData: 'none',
  schema: z.object({
    id: GuidSchema,
    displayName: z.string(),
    createdDateTime: optTimestamp,
    onPremisesSyncEnabled: optBool,
    onPremisesLastSyncDateTime: optTimestamp,
    verifiedDomains: list(
      z.object({
        name: z.string(),
        isDefault: z.boolean(),
        isInitial: z.boolean(),
        type: optString,
        capabilities: optString,
      }),
    ),
  }),
});

export const entraSubscribedSkus = defineDataset({
  id: 'entra.subscribedSkus',
  module: 'Entra',
  technology: 'entra',
  title: 'Licences (subscribed SKUs)',
  description: 'Licence SKUs and service plans, used to decide control applicability (e.g. Entra ID P2).',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/subscribedSkus`],
  permissions: ['Graph: Organization.Read.All'],
  personalData: 'none',
  schema: z.array(
    z.object({
      skuId: GuidSchema,
      skuPartNumber: z.string(),
      capabilityStatus: z.string(),
      consumedUnits: z.number().int().nonnegative(),
      prepaidUnits: z
        .object({ enabled: z.number().int(), suspended: optNumber, warning: optNumber })
        .nullish()
        .transform((v) => v ?? { enabled: 0, suspended: null, warning: null }),
      servicePlans: list(
        z.object({
          servicePlanId: GuidSchema,
          servicePlanName: z.string(),
          provisioningStatus: z.string(),
          appliesTo: optString,
        }),
      ),
    }),
  ),
});

export const entraSecurityDefaults = defineDataset({
  id: 'entra.securityDefaults',
  module: 'Entra',
  technology: 'entra',
  title: 'Security defaults',
  description: 'Whether Microsoft Entra security defaults are enabled.',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/policies/identitySecurityDefaultsEnforcementPolicy`],
  permissions: ['Graph: Policy.Read.All'],
  personalData: 'none',
  schema: z.object({ isEnabled: z.boolean() }),
});

export const entraAuthorizationPolicy = defineDataset({
  id: 'entra.authorizationPolicy',
  module: 'Entra',
  technology: 'entra',
  title: 'Authorization policy',
  description: 'Tenant-wide default user permissions, guest access, invitations and user consent.',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/policies/authorizationPolicy`],
  permissions: ['Graph: Policy.Read.All'],
  personalData: 'none',
  schema: z.object({
    allowInvitesFrom: z.string(),
    allowedToSignUpEmailBasedSubscriptions: optBool,
    allowEmailVerifiedUsersToJoinOrganization: optBool,
    allowUserConsentForRiskyApps: optBool,
    blockMsolPowerShell: optBool,
    guestUserRoleId: GuidSchema,
    permissionGrantPolicyIdsAssignedToDefaultUserRole: list(z.string()),
    defaultUserRolePermissions: z.object({
      allowedToCreateApps: z.boolean(),
      allowedToCreateSecurityGroups: z.boolean(),
      allowedToCreateTenants: optBool,
      allowedToReadBitlockerKeysForOwnedDevice: optBool,
      allowedToReadOtherUsers: z.boolean(),
    }),
  }),
});

const CaUsersSchema = z.object({
  includeUsers: list(z.string()),
  excludeUsers: list(z.string()),
  includeGroups: list(z.string()),
  excludeGroups: list(z.string()),
  includeRoles: list(z.string()),
  excludeRoles: list(z.string()),
  /** Non-null when guest/external user types are included; shape is kept opaque. */
  includeGuestsOrExternalUsers: z.unknown().nullish().transform((v) => (v === undefined ? null : v)),
  excludeGuestsOrExternalUsers: z.unknown().nullish().transform((v) => (v === undefined ? null : v)),
});

export const ConditionalAccessPolicySchema = z.object({
  id: GuidSchema,
  displayName: z.string(),
  /** enabled | disabled | enabledForReportingButNotEnforced */
  state: z.string(),
  createdDateTime: optTimestamp,
  modifiedDateTime: optTimestamp,
  conditions: z.object({
    users: CaUsersSchema.nullish().transform(
      (v) =>
        v ?? {
          includeUsers: [],
          excludeUsers: [],
          includeGroups: [],
          excludeGroups: [],
          includeRoles: [],
          excludeRoles: [],
          includeGuestsOrExternalUsers: null,
          excludeGuestsOrExternalUsers: null,
        },
    ),
    applications: z
      .object({
        includeApplications: list(z.string()),
        excludeApplications: list(z.string()),
        includeUserActions: list(z.string()),
        includeAuthenticationContextClassReferences: list(z.string()),
      })
      .nullish()
      .transform(
        (v) =>
          v ?? {
            includeApplications: [],
            excludeApplications: [],
            includeUserActions: [],
            includeAuthenticationContextClassReferences: [],
          },
      ),
    clientAppTypes: list(z.string()),
    signInRiskLevels: list(z.string()),
    userRiskLevels: list(z.string()),
    platforms: z
      .object({ includePlatforms: list(z.string()), excludePlatforms: list(z.string()) })
      .nullish()
      .transform((v) => v ?? null),
    locations: z
      .object({ includeLocations: list(z.string()), excludeLocations: list(z.string()) })
      .nullish()
      .transform((v) => v ?? null),
    /** e.g. { transferMethods: "deviceCodeFlow,authenticationTransfer" } */
    authenticationFlows: z
      .object({ transferMethods: optString })
      .nullish()
      .transform((v) => v ?? null),
  }),
  grantControls: z
    .object({
      operator: z.string(),
      builtInControls: list(z.string()),
      customAuthenticationFactors: list(z.string()),
      termsOfUse: list(z.string()),
      authenticationStrength: z
        .object({ id: z.string(), displayName: optString })
        .nullish()
        .transform((v) => v ?? null),
    })
    .nullish()
    .transform((v) => v ?? null),
  sessionControls: z
    .object({
      signInFrequency: z
        .object({ isEnabled: optBool, value: optNumber, type: optString, frequencyInterval: optString })
        .nullish()
        .transform((v) => v ?? null),
      persistentBrowser: z
        .object({ isEnabled: optBool, mode: optString })
        .nullish()
        .transform((v) => v ?? null),
    })
    .nullish()
    .transform((v) => v ?? null),
});
export type ConditionalAccessPolicy = z.output<typeof ConditionalAccessPolicySchema>;

export const entraConditionalAccessPolicies = defineDataset({
  id: 'entra.conditionalAccessPolicies',
  module: 'Entra',
  technology: 'entra',
  title: 'Conditional Access policies',
  description: 'All Conditional Access policies including disabled and report-only policies.',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/identity/conditionalAccess/policies`],
  permissions: ['Graph: Policy.Read.All', 'Directory role able to read CA policies (e.g. Global Reader or Security Reader)'],
  prerequisites: ['Microsoft Entra ID P1 (Conditional Access)'],
  personalData: 'identifiers',
  schema: z.array(ConditionalAccessPolicySchema),
});

export const entraRoleDefinitions = defineDataset({
  id: 'entra.roleDefinitions',
  module: 'Entra',
  technology: 'entra',
  title: 'Directory role definitions',
  description: 'Built-in and custom Microsoft Entra role definitions.',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/roleManagement/directory/roleDefinitions`],
  permissions: ['Graph: RoleManagement.Read.Directory'],
  personalData: 'none',
  schema: z.array(
    z.object({
      id: z.string(),
      displayName: z.string(),
      templateId: optString,
      isBuiltIn: z.boolean(),
      isEnabled: optBool,
      isPrivileged: optBool,
    }),
  ),
});

const PrincipalSchema = z.object({
  id: z.string(),
  /** user | group | servicePrincipal | other */
  principalType: z.string(),
  displayName: optString,
  userPrincipalName: optString,
  userType: optString,
  accountEnabled: optBool,
  onPremisesSyncEnabled: optBool,
});

export const entraRoleAssignments = defineDataset({
  id: 'entra.roleAssignments',
  module: 'Entra',
  technology: 'entra',
  title: 'Active directory role assignments',
  description:
    'Active Microsoft Entra role assignments (permanent and currently activated) with the assigned principal.',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/roleManagement/directory/roleAssignments?$expand=principal`],
  permissions: ['Graph: RoleManagement.Read.Directory', 'Graph: Directory.Read.All'],
  personalData: 'identifiers',
  schema: z.array(
    z.object({
      id: z.string(),
      roleDefinitionId: z.string(),
      principalId: z.string(),
      directoryScopeId: z.string(),
      principal: PrincipalSchema.nullish().transform((v) => v ?? null),
    }),
  ),
});

export const entraRoleAssignmentScheduleInstances = defineDataset({
  id: 'entra.roleAssignmentScheduleInstances',
  module: 'Entra',
  technology: 'entra',
  title: 'PIM active assignment instances',
  description:
    'Privileged Identity Management active role assignment instances, distinguishing permanent assignments from just-in-time activations.',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/roleManagement/directory/roleAssignmentScheduleInstances`],
  permissions: ['Graph: RoleAssignmentSchedule.Read.Directory'],
  prerequisites: ['Microsoft Entra ID P2 or Microsoft Entra ID Governance (PIM)'],
  personalData: 'identifiers',
  schema: z.array(
    z.object({
      id: z.string(),
      roleDefinitionId: z.string(),
      principalId: z.string(),
      directoryScopeId: z.string(),
      /** Assigned | Activated */
      assignmentType: z.string(),
      /** Direct | Group | Inherited */
      memberType: optString,
      startDateTime: optTimestamp,
      endDateTime: optTimestamp,
    }),
  ),
});

export const entraRoleEligibilitySchedules = defineDataset({
  id: 'entra.roleEligibilitySchedules',
  module: 'Entra',
  technology: 'entra',
  title: 'PIM eligible role assignments',
  description: 'Privileged Identity Management eligible role assignments.',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/roleManagement/directory/roleEligibilitySchedules`],
  permissions: ['Graph: RoleEligibilitySchedule.Read.Directory'],
  prerequisites: ['Microsoft Entra ID P2 or Microsoft Entra ID Governance (PIM)'],
  personalData: 'identifiers',
  schema: z.array(
    z.object({
      id: z.string(),
      roleDefinitionId: z.string(),
      principalId: z.string(),
      directoryScopeId: z.string(),
      memberType: optString,
      startDateTime: optTimestamp,
      endDateTime: optTimestamp,
    }),
  ),
});

export const entraUserRegistrationDetails = defineDataset({
  id: 'entra.userRegistrationDetails',
  module: 'Entra',
  technology: 'entra',
  title: 'Authentication method registration',
  description: 'Per-user authentication method registration state (MFA, passwordless, SSPR).',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/reports/authenticationMethods/userRegistrationDetails`],
  permissions: ['Graph: AuditLog.Read.All', 'Graph: UserAuthenticationMethod.Read.All'],
  prerequisites: ['Microsoft Entra ID P1 or P2'],
  personalData: 'identifiers',
  schema: z.array(
    z.object({
      id: z.string(),
      userPrincipalName: z.string(),
      userType: optString,
      isAdmin: optBool,
      isMfaRegistered: z.boolean(),
      isMfaCapable: optBool,
      isPasswordlessCapable: optBool,
      isSsprRegistered: optBool,
      methodsRegistered: list(z.string()),
    }),
  ),
});

export const entraAuthenticationMethodsPolicy = defineDataset({
  id: 'entra.authenticationMethodsPolicy',
  module: 'Entra',
  technology: 'entra',
  title: 'Authentication methods policy',
  description: 'Which authentication methods are enabled and for whom.',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/policies/authenticationMethodsPolicy`],
  permissions: ['Graph: Policy.Read.All'],
  personalData: 'none',
  schema: z.object({
    policyMigrationState: optString,
    authenticationMethodConfigurations: list(
      z.object({
        id: z.string(),
        state: z.string(),
        includeTargets: list(z.object({ targetType: optString, id: z.string() })),
      }),
    ),
  }),
});

const CredentialMetadataSchema = z.object({
  keyId: z.string(),
  displayName: optString,
  startDateTime: optTimestamp,
  endDateTime: optTimestamp,
});
const KeyCredentialMetadataSchema = CredentialMetadataSchema.extend({
  type: optString,
  usage: optString,
});

export const entraApplications = defineDataset({
  id: 'entra.applications',
  module: 'Entra',
  technology: 'entra',
  title: 'Application registrations',
  description:
    'App registrations with credential metadata only (key ID, name, validity). Secret values and hints are never collected.',
  source: 'MicrosoftGraph',
  operations: [
    `GET ${GRAPH}/applications?$select=id,appId,displayName,signInAudience,createdDateTime,passwordCredentials,keyCredentials`,
  ],
  permissions: ['Graph: Application.Read.All'],
  personalData: 'none',
  schema: z.array(
    z.object({
      id: z.string(),
      appId: GuidSchema,
      displayName: z.string(),
      signInAudience: optString,
      createdDateTime: optTimestamp,
      passwordCredentials: list(CredentialMetadataSchema),
      keyCredentials: list(KeyCredentialMetadataSchema),
    }),
  ),
});

export const entraServicePrincipals = defineDataset({
  id: 'entra.servicePrincipals',
  module: 'Entra',
  technology: 'entra',
  title: 'Service principals',
  description: 'Service principals (enterprise applications, managed identities) with credential metadata only.',
  source: 'MicrosoftGraph',
  operations: [
    `GET ${GRAPH}/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled,passwordCredentials,keyCredentials`,
  ],
  permissions: ['Graph: Application.Read.All'],
  personalData: 'none',
  schema: z.array(
    z.object({
      id: z.string(),
      appId: GuidSchema,
      displayName: z.string(),
      servicePrincipalType: optString,
      appOwnerOrganizationId: optString,
      accountEnabled: optBool,
      passwordCredentials: list(CredentialMetadataSchema),
      keyCredentials: list(KeyCredentialMetadataSchema),
    }),
  ),
});

export const entraApiPermissionGrants = defineDataset({
  id: 'entra.apiPermissionGrants',
  module: 'Entra',
  technology: 'entra',
  title: 'Application permission grants',
  description:
    'Application (app-only) permissions granted on key Microsoft APIs (Microsoft Graph, Exchange Online), from the resource service principal.',
  source: 'MicrosoftGraph',
  operations: [
    `GET ${GRAPH}/servicePrincipals(appId='00000003-0000-0000-c000-000000000000')`,
    `GET ${GRAPH}/servicePrincipals/{resourceId}/appRoleAssignedTo`,
  ],
  permissions: ['Graph: Application.Read.All'],
  personalData: 'none',
  schema: z.array(
    z.object({
      resourceAppId: GuidSchema,
      resourceDisplayName: z.string(),
      appRoles: list(z.object({ id: z.string(), value: optString })),
      assignments: list(
        z.object({
          id: z.string(),
          principalId: z.string(),
          principalType: optString,
          principalDisplayName: optString,
          appRoleId: z.string(),
          createdDateTime: optTimestamp,
        }),
      ),
    }),
  ),
});

export const entraGroupSettings = defineDataset({
  id: 'entra.groupSettings',
  module: 'Entra',
  technology: 'entra',
  title: 'Directory settings',
  description:
    'Tenant directory settings objects (e.g. Password Rule Settings). Custom banned password lists are not collected.',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/groupSettings`],
  permissions: ['Graph: Directory.Read.All'],
  personalData: 'none',
  schema: z.array(
    z.object({
      id: z.string(),
      displayName: optString,
      templateId: optString,
      values: list(z.object({ name: z.string(), value: optString })),
    }),
  ),
});

export const entraGuestUsers = defineDataset({
  id: 'entra.guestUsers',
  module: 'Entra',
  technology: 'entra',
  title: 'Guest users',
  description: 'Guest accounts with creation date, invitation state and last sign-in time.',
  source: 'MicrosoftGraph',
  operations: [
    `GET ${GRAPH}/users?$filter=userType eq 'Guest'&$select=id,userPrincipalName,accountEnabled,createdDateTime,externalUserState,signInActivity`,
  ],
  permissions: ['Graph: User.Read.All', 'Graph: AuditLog.Read.All (signInActivity)'],
  prerequisites: ['Microsoft Entra ID P1 or P2 for signInActivity'],
  personalData: 'identifiers-and-activity',
  schema: z.array(
    z.object({
      id: z.string(),
      userPrincipalName: z.string(),
      accountEnabled: optBool,
      createdDateTime: optTimestamp,
      externalUserState: optString,
      lastSignInDateTime: optTimestamp,
      lastNonInteractiveSignInDateTime: optTimestamp,
    }),
  ),
});

export const entraOnPremisesSynchronization = defineDataset({
  id: 'entra.onPremisesSynchronization',
  module: 'Entra',
  technology: 'hybrid',
  title: 'Directory synchronization settings',
  description: 'Microsoft Entra Connect / Cloud Sync tenant synchronization feature flags.',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/directory/onPremisesSynchronization`],
  permissions: ['Graph: OnPremDirectorySynchronization.Read.All'],
  personalData: 'none',
  schema: z.array(
    z.object({
      id: z.string(),
      features: z.object({
        passwordSyncEnabled: optBool,
        passwordWritebackEnabled: optBool,
        blockSoftMatchEnabled: optBool,
        blockCloudObjectTakeoverThroughHardMatchEnabled: optBool,
        softMatchOnUpnEnabled: optBool,
        userWritebackEnabled: optBool,
        deviceWritebackEnabled: optBool,
        passThroughAuthenticationEnabled: optBool,
        synchronizeUpnForManagedUsersEnabled: optBool,
      }),
    }),
  ),
});

export const ENTRA_DATASETS = [
  entraOrganization,
  entraSubscribedSkus,
  entraSecurityDefaults,
  entraAuthorizationPolicy,
  entraConditionalAccessPolicies,
  entraRoleDefinitions,
  entraRoleAssignments,
  entraRoleAssignmentScheduleInstances,
  entraRoleEligibilitySchedules,
  entraUserRegistrationDetails,
  entraAuthenticationMethodsPolicy,
  entraApplications,
  entraServicePrincipals,
  entraApiPermissionGrants,
  entraGroupSettings,
  entraGuestUsers,
  entraOnPremisesSynchronization,
] as const;
