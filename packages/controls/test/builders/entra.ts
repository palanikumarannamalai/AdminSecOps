/**
 * Builders for schema-valid Entra evidence used by control tests. Builders produce
 * collector-shaped input (what the PowerShell collector writes), which the test
 * inventory validates with the real dataset schemas.
 */

let counter = 0;
const nextGuid = (): string => {
  counter += 1;
  return `00000000-0000-4000-8000-${counter.toString(16).padStart(12, '0')}`;
};

export interface CaPolicyInput {
  id?: string;
  displayName?: string;
  state?: 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced';
  includeUsers?: string[];
  excludeUsers?: string[];
  excludeGroups?: string[];
  includeRoles?: string[];
  excludeRoles?: string[];
  includeApplications?: string[];
  clientAppTypes?: string[];
  signInRiskLevels?: string[];
  userRiskLevels?: string[];
  excludeLocations?: string[];
  transferMethods?: string | null;
  operator?: 'AND' | 'OR';
  builtInControls?: string[];
  authenticationStrengthId?: string | null;
}

export function caPolicy(input: CaPolicyInput = {}): Record<string, unknown> {
  return {
    id: input.id ?? nextGuid(),
    displayName: input.displayName ?? 'Test policy',
    state: input.state ?? 'enabled',
    conditions: {
      users: {
        includeUsers: input.includeUsers ?? ['All'],
        excludeUsers: input.excludeUsers ?? [],
        includeGroups: [],
        excludeGroups: input.excludeGroups ?? [],
        includeRoles: input.includeRoles ?? [],
        excludeRoles: input.excludeRoles ?? [],
        includeGuestsOrExternalUsers: null,
        excludeGuestsOrExternalUsers: null,
      },
      applications: {
        includeApplications: input.includeApplications ?? ['All'],
        excludeApplications: [],
        includeUserActions: [],
        includeAuthenticationContextClassReferences: [],
      },
      clientAppTypes: input.clientAppTypes ?? ['all'],
      signInRiskLevels: input.signInRiskLevels ?? [],
      userRiskLevels: input.userRiskLevels ?? [],
      platforms: null,
      locations: input.excludeLocations ? { includeLocations: ['All'], excludeLocations: input.excludeLocations } : null,
      authenticationFlows: input.transferMethods === undefined || input.transferMethods === null ? null : { transferMethods: input.transferMethods },
    },
    grantControls: {
      operator: input.operator ?? 'OR',
      builtInControls: input.builtInControls ?? ['mfa'],
      customAuthenticationFactors: [],
      termsOfUse: [],
      authenticationStrength:
        input.authenticationStrengthId === undefined || input.authenticationStrengthId === null
          ? null
          : { id: input.authenticationStrengthId, displayName: 'Strength' },
    },
    sessionControls: null,
  };
}

export interface PrincipalInput {
  id?: string;
  principalType?: 'user' | 'group' | 'servicePrincipal';
  displayName?: string;
  userPrincipalName?: string | null;
  userType?: string | null;
  accountEnabled?: boolean | null;
  onPremisesSyncEnabled?: boolean | null;
}

export function roleAssignment(roleTemplateId: string, principal: PrincipalInput = {}): Record<string, unknown> {
  const principalId = principal.id ?? nextGuid();
  return {
    id: nextGuid(),
    roleDefinitionId: roleTemplateId,
    principalId,
    directoryScopeId: '/',
    principal: {
      id: principalId,
      principalType: principal.principalType ?? 'user',
      displayName: principal.displayName ?? `User ${principalId.slice(-4)}`,
      userPrincipalName: principal.userPrincipalName === undefined ? `user${principalId.slice(-4)}@contoso.example` : principal.userPrincipalName,
      userType: principal.userType === undefined ? 'Member' : principal.userType,
      accountEnabled: principal.accountEnabled === undefined ? true : principal.accountEnabled,
      onPremisesSyncEnabled: principal.onPremisesSyncEnabled === undefined ? null : principal.onPremisesSyncEnabled,
    },
  };
}

export function authorizationPolicy(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const { defaultUserRolePermissions, ...rest } = overrides;
  return {
    allowInvitesFrom: 'adminsAndGuestInviters',
    allowedToSignUpEmailBasedSubscriptions: false,
    allowEmailVerifiedUsersToJoinOrganization: false,
    allowUserConsentForRiskyApps: false,
    blockMsolPowerShell: true,
    guestUserRoleId: '10dae51f-b6af-4016-8d66-8c2a99b929b3',
    permissionGrantPolicyIdsAssignedToDefaultUserRole: ['ManagePermissionGrantsForSelf.microsoft-user-default-low'],
    defaultUserRolePermissions: {
      allowedToCreateApps: false,
      allowedToCreateSecurityGroups: false,
      allowedToCreateTenants: false,
      allowedToReadBitlockerKeysForOwnedDevice: false,
      allowedToReadOtherUsers: true,
      ...(defaultUserRolePermissions as Record<string, unknown> | undefined),
    },
    ...rest,
  };
}

export function sku(servicePlanNames: string[], overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    skuId: nextGuid(),
    skuPartNumber: 'TEST_SKU',
    capabilityStatus: 'Enabled',
    consumedUnits: 10,
    prepaidUnits: { enabled: 25, suspended: 0, warning: 0 },
    servicePlans: servicePlanNames.map((name) => ({
      servicePlanId: nextGuid(),
      servicePlanName: name,
      provisioningStatus: 'Success',
      appliesTo: 'User',
    })),
    ...overrides,
  };
}

export { nextGuid };
