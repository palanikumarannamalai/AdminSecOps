import type { ConditionalAccessPolicy } from '@adminsecops/schemas';

/** Built-in authentication strength: "Phishing-resistant MFA". */
export const PHISHING_RESISTANT_STRENGTH_ID = '00000000-0000-0000-0000-000000000004';
/** Built-in authentication strength: "Multifactor authentication". */
export const MFA_STRENGTH_ID = '00000000-0000-0000-0000-000000000002';
/** Built-in authentication strength: "Passwordless MFA". */
export const PASSWORDLESS_STRENGTH_ID = '00000000-0000-0000-0000-000000000003';

/** Client app types that represent legacy authentication in Conditional Access. */
export const LEGACY_CLIENT_APP_TYPES = ['exchangeActiveSync', 'other'] as const;

export function isEnabled(policy: ConditionalAccessPolicy): boolean {
  return policy.state === 'enabled';
}

export function isReportOnly(policy: ConditionalAccessPolicy): boolean {
  return policy.state === 'enabledForReportingButNotEnforced';
}

export function includesAllUsers(policy: ConditionalAccessPolicy): boolean {
  return policy.conditions.users.includeUsers.some((u) => u.toLowerCase() === 'all');
}

export function includesAllApps(policy: ConditionalAccessPolicy): boolean {
  const apps = policy.conditions.applications;
  return (
    apps.excludeApplications.length === 0 &&
    apps.includeApplications.some((a) => a.toLowerCase() === 'all')
  );
}

/** Policy applies to all client app types (empty list or explicit 'all'). */
export function includesAllClientApps(policy: ConditionalAccessPolicy): boolean {
  const types = policy.conditions.clientAppTypes;
  return types.length === 0 || types.some((t) => t.toLowerCase() === 'all');
}

/** True when the policy has no conditions that narrow it beyond users/apps/client apps. */
export function hasNoNarrowingConditions(policy: ConditionalAccessPolicy): boolean {
  const c = policy.conditions;
  const platformsNarrow =
    c.platforms !== null &&
    (c.platforms.excludePlatforms.length > 0 ||
      (c.platforms.includePlatforms.length > 0 &&
        !c.platforms.includePlatforms.some((p) => p.toLowerCase() === 'all')));
  const locationsNarrow =
    c.locations !== null &&
    (c.locations.excludeLocations.length > 0 ||
      (c.locations.includeLocations.length > 0 &&
        !c.locations.includeLocations.some((l) => l.toLowerCase() === 'all')));
  const devicesNarrow =
    c.devices !== null &&
    (c.devices.includeDevices.length > 0 ||
      c.devices.excludeDevices.length > 0 ||
      c.devices.deviceFilter !== null);
  return (
    !platformsNarrow &&
    !locationsNarrow &&
    !devicesNarrow &&
    transferMethods(policy).length === 0 &&
    c.signInRiskLevels.length === 0 &&
    c.userRiskLevels.length === 0
  );
}

export function blocksAccess(policy: ConditionalAccessPolicy): boolean {
  return policy.grantControls?.builtInControls.some((c) => c.toLowerCase() === 'block') ?? false;
}

/**
 * How strongly the grant controls require MFA:
 * - 'required': MFA (or a strength known to require MFA) must always be satisfied;
 * - 'alternative': MFA is one of several OR-ed alternatives (e.g. MFA or compliant device);
 * - 'none': no MFA requirement.
 */
export function mfaRequirement(
  policy: ConditionalAccessPolicy,
): 'required' | 'alternative' | 'none' {
  const grant = policy.grantControls;
  if (grant === null) return 'none';
  const controls = grant.builtInControls.map((c) => c.toLowerCase());
  const strength = grant.authenticationStrength;
  const strengthRequiresMfa =
    strength !== null &&
    (strength.requirementsSatisfied === 'mfa' ||
      (strength.requirementsSatisfied === null &&
        [MFA_STRENGTH_ID, PASSWORDLESS_STRENGTH_ID, PHISHING_RESISTANT_STRENGTH_ID].includes(
          strength.id,
        )));
  const hasMfa = controls.includes('mfa') || strengthRequiresMfa;
  if (!hasMfa) return 'none';
  const nonMfaControls = controls.filter((c) => c !== 'mfa');
  const hasOtherAlternatives =
    nonMfaControls.length > 0 ||
    (strength !== null && !strengthRequiresMfa) ||
    grant.customAuthenticationFactors.length > 0 ||
    grant.termsOfUse.length > 0;
  if (grant.operator.toUpperCase() === 'OR' && hasOtherAlternatives) return 'alternative';
  return 'required';
}

/** True when the policy includes the given role template (directly or via All users) and does not exclude it. */
export function coversRole(policy: ConditionalAccessPolicy, roleTemplateId: string): boolean {
  const users = policy.conditions.users;
  const id = roleTemplateId.toLowerCase();
  if (users.excludeRoles.some((r) => r.toLowerCase() === id)) return false;
  return includesAllUsers(policy) || users.includeRoles.some((r) => r.toLowerCase() === id);
}

export interface PolicyExclusions {
  users: number;
  groups: number;
  roles: number;
  guestsOrExternal: boolean;
  total: number;
}

export function exclusions(policy: ConditionalAccessPolicy): PolicyExclusions {
  const u = policy.conditions.users;
  const guests = u.excludeGuestsOrExternalUsers !== null;
  return {
    users: u.excludeUsers.length,
    groups: u.excludeGroups.length,
    roles: u.excludeRoles.length,
    guestsOrExternal: guests,
    total:
      u.excludeUsers.length + u.excludeGroups.length + u.excludeRoles.length + (guests ? 1 : 0),
  };
}

export function blocksLegacyAuthentication(policy: ConditionalAccessPolicy): boolean {
  if (!blocksAccess(policy)) return false;
  const types = policy.conditions.clientAppTypes.map((t) => t.toLowerCase());
  return LEGACY_CLIENT_APP_TYPES.every((legacy) => types.includes(legacy.toLowerCase()));
}

/** Parse the comma-separated authenticationFlows.transferMethods condition. */
export function transferMethods(policy: ConditionalAccessPolicy): string[] {
  const raw = policy.conditions.authenticationFlows?.transferMethods;
  if (raw === null || raw === undefined) return [];
  return raw
    .split(',')
    .map((m) => m.trim())
    .filter((m) => m.length > 0);
}
