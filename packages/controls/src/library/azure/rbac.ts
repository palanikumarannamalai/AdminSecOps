import type { DatasetData } from '@adminsecops/schemas';
import { defineControl } from '../../define.js';
import { affected, eqi, fact, fail, notAssessed, pass, plural, review } from '../../helpers.js';
import { REF } from '../../references.js';
import { aggregateVerdicts, fail_, pass_, unknown_ } from '../shared/verdicts.js';
import { sameId, subscriptionSubject, subscriptionUniverse } from './common.js';
import { AZ_REF } from './references.js';

type RoleAssignment = DatasetData<'azure.roleAssignments'>[number];

/** Built-in role definition IDs (identical in every tenant), from "Azure built-in roles". */
export const AZURE_ROLE_IDS = {
  owner: '8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
  contributor: 'b24988ac-6180-42a0-ab88-20f7382dd24c',
  userAccessAdministrator: '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9',
  roleBasedAccessControlAdministrator: 'f58310d9-a9f6-439a-9e8d-f62e7b41a168',
} as const;

const PRIVILEGED_ROLES: readonly { name: string; id: string }[] = [
  { name: 'Owner', id: AZURE_ROLE_IDS.owner },
  { name: 'Contributor', id: AZURE_ROLE_IDS.contributor },
  { name: 'User Access Administrator', id: AZURE_ROLE_IDS.userAccessAdministrator },
  { name: 'Role Based Access Control Administrator', id: AZURE_ROLE_IDS.roleBasedAccessControlAdministrator },
];

function roleIs(assignment: RoleAssignment, role: { name: string; id: string }): boolean {
  if (eqi(assignment.roleDefinitionName, role.name)) return true;
  const defId = assignment.roleDefinitionId?.toLowerCase() ?? '';
  return defId !== '' && defId.endsWith(role.id);
}

function normalizeScope(scope: string): string {
  return scope.trim().toLowerCase().replace(/\/+$/, '');
}

/**
 * True when the assignment grants its role over the whole subscription: assigned at the
 * subscription itself or inherited from a management group or the root scope.
 */
export function coversWholeSubscription(assignment: RoleAssignment): boolean {
  const scope = normalizeScope(assignment.scope);
  if (scope === '' || scope === '/') return true;
  if (scope === `/subscriptions/${assignment.subscriptionId.toLowerCase()}`) return true;
  return scope.startsWith('/providers/microsoft.management/managementgroups/');
}

function principalLabel(a: RoleAssignment): string {
  return a.principalDisplayName ?? a.principalSignInName ?? a.principalId;
}

/** Guest (B2B) users have #EXT# in their user principal name. */
export function isGuestSignInName(signInName: string | null): boolean {
  return signInName !== null && signInName.toUpperCase().includes('#EXT#');
}

export const azRbacOwnerCount = defineControl({
  id: 'AZ-RBAC-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'No more than three Owner assignments per subscription',
  technology: 'azure',
  category: 'Privileged access',
  subcategory: 'Azure RBAC',
  description:
    'Counts the distinct principals that hold the Owner role over each Azure subscription (assigned at the subscription or inherited from a management group or the root scope) and checks that the number does not exceed the configured maximum.',
  rationale:
    'Owner grants full control of every resource in the subscription and the right to grant access to others. Each additional Owner is another account whose compromise gives an attacker complete control. Microsoft Defender for Cloud recommends designating a maximum of three subscription owners and using less privileged roles for day-to-day work.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Every Azure subscription the collector could read.' },
  requiredEvidence: ['azure.roleAssignments'],
  optionalEvidence: ['azure.subscriptions'],
  evaluation: {
    logic:
      'For each subscription (from azure.roleAssignments plus active subscriptions in azure.subscriptions when available) the control collects Owner role assignments (by role name or built-in role ID) whose scope is the subscription, a management group or the root scope, and counts distinct principal IDs. A group counts as one assignment; its members are not expanded and a note is added. FAIL when any subscription has more distinct Owner principals than maxOwners. A subscription with no role assignments at all in the evidence cannot be evaluated and is reported for review (never PASS). PASS when every subscription is at or below the limit.',
    parameters: { maxOwners: 3 },
  },
  expectedState: 'Each subscription has at most three Owner principals (ideally two or three, including an emergency access path), and day-to-day administration uses less privileged roles.',
  remediation: {
    summary: 'Remove unnecessary Owner assignments and replace them with less privileged roles or eligible (just-in-time) assignments in Privileged Identity Management.',
    steps: [
      'In the Azure portal open Subscriptions > (subscription) > Access control (IAM) > Role assignments and filter Role = Owner. Include inherited assignments (management group scope).',
      'For each Owner confirm with the person or team why full control is required. Prefer Contributor, a resource-specific role or a custom role for day-to-day work.',
      'Where Owner is still required, convert the permanent assignment to an eligible assignment in Microsoft Entra Privileged Identity Management (Azure resources) so it is activated only when needed.',
      'Remove the remaining unnecessary Owner assignments. Keep at least two Owners so a single account loss does not lock you out.',
      'For Owners granted through groups, review the group membership and make the group a role-assignable or PIM-managed group.',
    ],
    scriptExample:
      '# Review only: list Owner principals that apply to a subscription (Az PowerShell)\n$sub = "<subscription-id>"\nGet-AzRoleAssignment -Scope "/subscriptions/$sub" -RoleDefinitionName Owner |\n  Select-Object DisplayName, SignInName, ObjectType, Scope\n# Remove one assignment after review\n# Remove-AzRoleAssignment -ObjectId <principal-object-id> -RoleDefinitionName Owner -Scope "/subscriptions/$sub"',
    effort: 'medium',
  },
  implementationConsiderations: [
    'Assignments inherited from a management group are counted because they grant Owner over the subscription; remove them at the management group if they are not needed there either.',
    'Service principals and managed identities with Owner (for example deployment pipelines) count toward the limit. Grant pipelines a narrower role such as Contributor plus a constrained Role Based Access Control Administrator assignment where possible.',
    'Microsoft Defender for Cloud also recommends more than one Owner per subscription; keep an emergency access path before removing Owners.',
    'Classic Co-Administrators were converted to Owner assignments by Microsoft; review any that appeared this way.',
  ],
  impact: 'Removed Owners lose the ability to manage access and some settings; users who need to deploy resources keep that ability through the replacement role.',
  rollback: ['Re-add the Owner role assignment in Access control (IAM) or re-activate it through Privileged Identity Management.'],
  validation: [
    'Re-run the AdminSecOps Azure collector and confirm AZ-RBAC-001 is PASS.',
    'In Defender for Cloud confirm the recommendation "A maximum of 3 owners should be designated for subscriptions" is healthy.',
  ],
  references: [AZ_REF.defenderIdentityRecommendations, AZ_REF.rbacBestPractices, AZ_REF.rbacBuiltInRoles, REF.pimOverview],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-6(5)' },
    { framework: 'NIST-800-53r5', id: 'AC-2(7)' },
    { framework: 'MCSB', id: 'PA-1' },
    { framework: 'MITRE-ATTACK', id: 'T1078.004' },
  ],
  tags: ['privileged-access', 'azure-rbac', 'least-privilege'],
  evaluate: (ctx) => {
    const assignments = ctx.data('azure.roleAssignments');
    const max = ctx.num('maxOwners');
    const subscriptions = subscriptionUniverse(
      ctx,
      assignments.map((a) => a.subscriptionId),
    );
    const ownerRole = { name: 'Owner', id: AZURE_ROLE_IDS.owner };
    const ownersBySub = new Map<string, RoleAssignment[] | null>();
    const groupNotes: string[] = [];
    for (const sub of subscriptions) {
      const inSub = assignments.filter((a) => sameId(a.subscriptionId, sub.id));
      if (inSub.length === 0) {
        ownersBySub.set(sub.id, null);
        continue;
      }
      const owners = new Map<string, RoleAssignment>();
      for (const a of inSub) {
        if (roleIs(a, ownerRole) && coversWholeSubscription(a)) owners.set(a.principalId.toLowerCase(), a);
      }
      const list = [...owners.values()];
      ownersBySub.set(sub.id, list);
      for (const g of list.filter((a) => eqi(a.principalType, 'Group'))) {
        groupNotes.push(
          `Group "${principalLabel(g)}" holds Owner on ${sub.name}; it is counted as one assignment, but every member effectively has Owner. Review its membership.`,
        );
      }
    }
    return aggregateVerdicts({
      items: subscriptions,
      subject: subscriptionSubject,
      noun: ['subscription', 'subscriptions'],
      requirement: `no more than ${max} distinct principals hold Owner over the subscription`,
      empty: { status: 'NOT_ASSESSED', reason: 'The evidence contains no subscriptions or role assignments, so Owner assignments could not be counted.' },
      extraFacts: [fact('Maximum Owners (parameter)', max)],
      notes: groupNotes,
      classify: (sub) => {
        const list = ownersBySub.get(sub.id) ?? null;
        if (list === null) {
          return unknown_('No role assignments were collected for this subscription; confirm the collector account has Reader access.');
        }
        const names = list.map((a) => `${principalLabel(a)} (${a.principalType})`).join(', ');
        if (list.length > max) return fail_(`${list.length} Owner principals: ${names}.`);
        if (list.length === 0) return pass_('No Owner assignment at or above the subscription scope was found.');
        return pass_(`${plural(list.length, 'Owner principal')}: ${names}.`);
      },
    });
  },
});

export const azRbacGuestPrivileged = defineControl({
  id: 'AZ-RBAC-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Guest accounts do not hold privileged Azure roles',
  technology: 'azure',
  category: 'Privileged access',
  subcategory: 'Azure RBAC',
  description:
    'Checks that no guest (B2B external) user holds Owner, Contributor, User Access Administrator or Role Based Access Control Administrator at any Azure scope.',
  rationale:
    'Guest accounts are governed by another organization: their password policy, MFA, joiner/leaver process and device security are outside your control. A compromised or forgotten guest account with a privileged Azure role gives an outsider control of your resources or the ability to grant access to others. Microsoft Defender for Cloud recommends removing guest accounts with owner and write permissions.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Every Azure subscription the collector could read.' },
  requiredEvidence: ['azure.roleAssignments'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'Selects role assignments at any scope whose role is Owner, Contributor, User Access Administrator or Role Based Access Control Administrator (by name or built-in role ID). FAIL when any such assignment belongs to a principal whose sign-in name contains "#EXT#" (a Microsoft Entra B2B guest). REVIEW when a user principal holding one of these roles has no resolved sign-in name, because guest status cannot be determined. PASS otherwise. An evidence file with no role assignments at all is NOT_ASSESSED. Guests that receive a role through group membership are not detected (groups are not expanded).',
    parameters: {},
  },
  expectedState: 'No guest user holds Owner, Contributor, User Access Administrator or Role Based Access Control Administrator; external collaborators receive only the least privileged role they need, preferably time-bound.',
  remediation: {
    summary: 'Remove privileged Azure role assignments from guest accounts, or replace them with a narrowly scoped, time-bound role.',
    steps: [
      'For each affected assignment, confirm with the resource owner whether the external person still needs access.',
      'In the Azure portal open the scope shown (subscription, resource group or resource) > Access control (IAM) > Role assignments and remove the privileged role from the guest.',
      'If access is still required, grant a narrower built-in role at the smallest scope, as an eligible assignment in Privileged Identity Management with an expiry date.',
      'Consider creating a member account in your tenant for long-term administrators from partners, so your MFA and Conditional Access policies apply fully.',
      'Schedule access reviews for guests with Azure role assignments.',
    ],
    scriptExample:
      '# Review only: list privileged assignments held by guest users (Az PowerShell)\n$roles = "Owner","Contributor","User Access Administrator","Role Based Access Control Administrator"\nGet-AzRoleAssignment | Where-Object { $_.SignInName -like "*#EXT#*" -and $roles -contains $_.RoleDefinitionName } |\n  Select-Object SignInName, RoleDefinitionName, Scope\n# Remove-AzRoleAssignment -SignInName "<guest-upn>" -RoleDefinitionName "Owner" -Scope "<scope>"',
    effort: 'low',
  },
  implementationConsiderations: [
    'Managed service providers often use guest accounts; Azure Lighthouse delegation is a better-governed alternative for partner administration.',
    'Guests may also receive roles through groups. Review the members of groups that hold privileged roles (see AZ-RBAC-001 notes).',
    'Removing Contributor from a guest who deploys resources will stop their deployments; agree a replacement role first.',
  ],
  impact: 'The external user loses the ability to manage the affected resources or grant access.',
  rollback: ['Re-create the role assignment for the guest at the same scope in Access control (IAM).'],
  validation: [
    'Re-run the AdminSecOps Azure collector and confirm AZ-RBAC-002 is PASS.',
    'In Defender for Cloud confirm the recommendations about guest accounts with owner or write permissions are healthy.',
  ],
  references: [AZ_REF.defenderIdentityRecommendations, AZ_REF.rbacBestPractices, AZ_REF.rbacBuiltInRoles, REF.accessReviewsGuests],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-6' },
    { framework: 'NIST-800-53r5', id: 'AC-2' },
    { framework: 'MCSB', id: 'PA-1' },
    { framework: 'MCSB', id: 'PA-4' },
    { framework: 'MITRE-ATTACK', id: 'T1078.004' },
  ],
  tags: ['privileged-access', 'azure-rbac', 'guest-access', 'external-identities'],
  evaluate: (ctx) => {
    const assignments = ctx.data('azure.roleAssignments');
    if (assignments.length === 0) {
      return notAssessed({
        reason: 'The evidence contains no Azure role assignments, so guest access could not be evaluated. Confirm the collector account has Reader access to the subscriptions.',
        summary: 'No role assignments in evidence.',
        facts: [fact('Role assignments', 0)],
      });
    }
    const privileged = assignments.filter((a) => PRIVILEGED_ROLES.some((r) => roleIs(a, r)));
    const guests = privileged.filter((a) => isGuestSignInName(a.principalSignInName));
    const unresolved = privileged.filter((a) => eqi(a.principalType, 'User') && a.principalSignInName === null);
    const toObject = (a: RoleAssignment, detail: string) =>
      affected('roleAssignment', a.roleAssignmentId, `${principalLabel(a)} - ${a.roleDefinitionName}`, `${detail} Scope: ${a.scope}`);
    const facts = [
      fact('Role assignments', assignments.length),
      fact('Privileged role assignments', privileged.length),
      fact('Privileged assignments held by guests', guests.length),
      fact('Privileged user assignments without a resolved sign-in name', unresolved.length),
    ];
    const notes = ['Guests that receive a privileged role through group membership are not detected by this control; review groups that hold privileged roles.'];
    if (guests.length > 0) {
      return fail({
        reason: `${plural(guests.length, 'privileged role assignment')} belong to guest (external) accounts.`,
        summary: `Guest accounts hold ${[...new Set(guests.map((g) => g.roleDefinitionName))].join(', ')} in Azure.`,
        facts,
        affectedObjects: [
          ...guests.map((a) => toObject(a, `Guest account ${a.principalSignInName ?? ''} holds ${a.roleDefinitionName}.`)),
          ...unresolved.map((a) => toObject(a, 'Sign-in name was not resolved; guest status unknown.')),
        ],
        notes,
      });
    }
    if (unresolved.length > 0) {
      return review({
        reason: `No guest holds a privileged role, but ${plural(unresolved.length, 'privileged user assignment')} had no resolved sign-in name, so guest status could not be determined.`,
        summary: 'Some privileged user assignments could not be checked for guest status.',
        facts,
        affectedObjects: unresolved.map((a) => toObject(a, 'Sign-in name was not resolved; confirm whether this user is a guest.')),
        notes,
      });
    }
    return pass({
      reason: `None of the ${plural(privileged.length, 'privileged role assignment')} belong to guest accounts.`,
      summary: 'No guest account holds Owner, Contributor, User Access Administrator or Role Based Access Control Administrator.',
      facts,
      notes,
    });
  },
});
