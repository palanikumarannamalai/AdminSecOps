import type { DatasetData } from '@adminsecops/schemas';
import type { Fact, Inventory } from '../inventory.js';

/**
 * Built-in Microsoft Entra role template IDs. Template IDs are identical in every
 * tenant. Source: "Microsoft Entra built-in roles" (Microsoft Learn).
 */
export const ENTRA_ROLE_TEMPLATES = {
  globalAdministrator: '62e90394-69f5-4237-9190-012177145e10',
  privilegedRoleAdministrator: 'e8611ab8-c189-46e8-94e1-60213ab1f814',
  privilegedAuthenticationAdministrator: '7be44c8a-adaf-4e2a-84d6-ab2649e08a13',
  securityAdministrator: '194ae4cb-b126-40b2-bd5b-6091b380977d',
  conditionalAccessAdministrator: 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9',
  exchangeAdministrator: '29232cdf-9323-42fd-ade2-1d097af3e4de',
  sharePointAdministrator: 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c',
  userAdministrator: 'fe930be7-5e62-47db-91af-98c3a49a38b1',
  applicationAdministrator: '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',
  cloudApplicationAdministrator: '158c047a-c907-4556-b7ef-446551a6b5f7',
  hybridIdentityAdministrator: '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2',
  authenticationAdministrator: 'c4e39bd9-1100-46d3-8c65-fb160da0071f',
  helpdeskAdministrator: '729827e3-9c14-49f7-bb1b-9608f156bbb8',
  passwordAdministrator: '966707d0-3269-4727-9be2-8c3a10f19b9d',
  billingAdministrator: 'b0f54661-2d74-4c50-afa3-1ec803f12efe',
  intuneAdministrator: '3a2c62db-5318-420d-8d74-23affee5d9d5',
  authenticationPolicyAdministrator: '0526716b-113d-4c15-b2c8-68e3c22b9f80',
  globalReader: 'f2ef992c-3afb-46b9-b7cf-a126ee74c451',
  directorySynchronizationAccounts: 'd29b2b05-8046-44ba-8758-1e26182fcf32',
} as const;

/**
 * Roles that allow control of the tenant, its identities or its security configuration
 * ("highly privileged"). Used for cloud-only, PIM and phishing-resistant MFA checks.
 */
export const HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS: ReadonlySet<string> = new Set([
  ENTRA_ROLE_TEMPLATES.globalAdministrator,
  ENTRA_ROLE_TEMPLATES.privilegedRoleAdministrator,
  ENTRA_ROLE_TEMPLATES.privilegedAuthenticationAdministrator,
  ENTRA_ROLE_TEMPLATES.securityAdministrator,
  ENTRA_ROLE_TEMPLATES.conditionalAccessAdministrator,
  ENTRA_ROLE_TEMPLATES.exchangeAdministrator,
  ENTRA_ROLE_TEMPLATES.sharePointAdministrator,
  ENTRA_ROLE_TEMPLATES.userAdministrator,
  ENTRA_ROLE_TEMPLATES.applicationAdministrator,
  ENTRA_ROLE_TEMPLATES.cloudApplicationAdministrator,
  ENTRA_ROLE_TEMPLATES.hybridIdentityAdministrator,
  ENTRA_ROLE_TEMPLATES.intuneAdministrator,
  ENTRA_ROLE_TEMPLATES.authenticationPolicyAdministrator,
]);

/**
 * The administrator roles targeted by Microsoft's "Require multifactor authentication
 * for admins" Conditional Access template.
 */
export const MFA_ADMIN_ROLE_TEMPLATE_IDS: readonly string[] = [
  ENTRA_ROLE_TEMPLATES.globalAdministrator,
  ENTRA_ROLE_TEMPLATES.applicationAdministrator,
  ENTRA_ROLE_TEMPLATES.authenticationAdministrator,
  ENTRA_ROLE_TEMPLATES.billingAdministrator,
  ENTRA_ROLE_TEMPLATES.cloudApplicationAdministrator,
  ENTRA_ROLE_TEMPLATES.conditionalAccessAdministrator,
  ENTRA_ROLE_TEMPLATES.exchangeAdministrator,
  ENTRA_ROLE_TEMPLATES.helpdeskAdministrator,
  ENTRA_ROLE_TEMPLATES.passwordAdministrator,
  ENTRA_ROLE_TEMPLATES.privilegedAuthenticationAdministrator,
  ENTRA_ROLE_TEMPLATES.privilegedRoleAdministrator,
  ENTRA_ROLE_TEMPLATES.securityAdministrator,
  ENTRA_ROLE_TEMPLATES.sharePointAdministrator,
  ENTRA_ROLE_TEMPLATES.userAdministrator,
];

export interface ResolvedRoleAssignment {
  assignmentId: string;
  roleDefinitionId: string;
  /** Template ID for built-in roles (equal to roleDefinitionId for built-in roles). */
  roleTemplateId: string;
  roleName: string;
  isHighlyPrivileged: boolean;
  directoryScopeId: string;
  principalId: string;
  /** user | group | servicePrincipal | unknown */
  principalType: string;
  principalName: string;
  userPrincipalName: string | null;
  userType: string | null;
  accountEnabled: boolean | null;
  onPremisesSyncEnabled: boolean | null;
}

type RoleDefinitions = DatasetData<'entra.roleDefinitions'>;
type RoleAssignments = DatasetData<'entra.roleAssignments'>;

/**
 * Join active role assignments with role definitions. Requires entra.roleAssignments;
 * entra.roleDefinitions is used for names when available (built-in role names are
 * otherwise resolved from the template catalog).
 */
export function resolveEntraRoleAssignments(inventory: Inventory): Fact<ResolvedRoleAssignment[]> {
  const assignments = inventory.get('entra.roleAssignments');
  if (!assignments.available) return assignments;
  const definitions = inventory.get('entra.roleDefinitions');
  const defs = definitions.available ? definitions.data : [];
  return { ...assignments, data: joinAssignments(assignments.data, defs) };
}

const TEMPLATE_NAMES: ReadonlyMap<string, string> = new Map(
  Object.entries(ENTRA_ROLE_TEMPLATES).map(([key, id]) => [id, humanize(key)]),
);

/** Display name of a built-in role from its template ID (falls back to the ID). */
export function builtInRoleName(templateId: string): string {
  return TEMPLATE_NAMES.get(templateId.toLowerCase()) ?? templateId;
}

function humanize(camel: string): string {
  const spaced = camel.replace(/([A-Z])/g, ' $1');
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export function joinAssignments(assignments: RoleAssignments, definitions: RoleDefinitions): ResolvedRoleAssignment[] {
  const defsById = new Map(definitions.map((d) => [d.id.toLowerCase(), d]));
  return assignments.map((assignment) => {
    const def = defsById.get(assignment.roleDefinitionId.toLowerCase());
    const templateId = (def?.templateId ?? assignment.roleDefinitionId).toLowerCase();
    const principal = assignment.principal;
    return {
      assignmentId: assignment.id,
      roleDefinitionId: assignment.roleDefinitionId,
      roleTemplateId: templateId,
      roleName: def?.displayName ?? TEMPLATE_NAMES.get(templateId) ?? assignment.roleDefinitionId,
      isHighlyPrivileged: HIGHLY_PRIVILEGED_ROLE_TEMPLATE_IDS.has(templateId),
      directoryScopeId: assignment.directoryScopeId,
      principalId: assignment.principalId,
      principalType: principal?.principalType ?? 'unknown',
      principalName: principal?.displayName ?? principal?.userPrincipalName ?? assignment.principalId,
      userPrincipalName: principal?.userPrincipalName ?? null,
      userType: principal?.userType ?? null,
      accountEnabled: principal?.accountEnabled ?? null,
      onPremisesSyncEnabled: principal?.onPremisesSyncEnabled ?? null,
    };
  });
}
