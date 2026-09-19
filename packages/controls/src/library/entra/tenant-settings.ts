import { daysBetween, parseTimestamp } from '@adminsecops/core';
import { defineControl } from '../../define.js';
import { affected, eqi, fact, fail, pass, plural, review } from '../../helpers.js';
import { REF } from '../../references.js';

/** guestUserRoleId values documented by Microsoft. */
export const GUEST_ROLE = {
  sameAsMembers: 'a0b1b346-4d3e-4e8b-98f8-753987be4970',
  limited: '10dae51f-b6af-4016-8d66-8c2a99b929b3',
  restricted: '2af84b1e-32c8-42b7-82bc-daa82404023b',
} as const;

const LEGACY_CONSENT = 'microsoft-user-default-legacy';
const LOW_RISK_CONSENT = 'microsoft-user-default-low';

export const entraUsersCannotRegisterApps = defineControl({
  id: 'ENTRA-APP-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Only administrators can register applications',
  technology: 'entra',
  category: 'Applications',
  subcategory: 'App registration',
  description: 'Checks the tenant authorization policy setting that allows every user to create application registrations.',
  rationale:
    'When any user can register applications, attackers with a compromised user account can create apps that request consent to data, establish persistence with their own credentials, or impersonate trusted applications. Restricting registration to administrators (or the Application Developer role) keeps the application estate under control.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'All Microsoft Entra tenants.' },
  requiredEvidence: ['entra.authorizationPolicy'],
  evaluation: { logic: 'FAIL when defaultUserRolePermissions.allowedToCreateApps is true; PASS otherwise.', parameters: {} },
  expectedState: 'Users can register applications = No (defaultUserRolePermissions.allowedToCreateApps = false).',
  remediation: {
    summary: 'Turn off app registration for users and delegate it through the Application Developer role where needed.',
    steps: [
      'In the Microsoft Entra admin center go to Entra ID > Users > User settings.',
      'Set "Users can register applications" to No and save.',
      'Assign the Application Developer role to people who legitimately create app registrations.',
    ],
    scriptExample:
      "Connect-MgGraph -Scopes 'Policy.ReadWrite.Authorization'\nUpdate-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{ AllowedToCreateApps = $false }",
    effort: 'low',
  },
  implementationConsiderations: ['Developers who create app registrations need the Application Developer role before the change.'],
  impact: 'Regular users can no longer create app registrations; existing registrations are unaffected.',
  rollback: ['Set "Users can register applications" back to Yes in Entra ID > Users > User settings.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-APP-001 is PASS.'],
  references: [REF.restrictAppRegistration, REF.defaultUserPermissions],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'CM-11' },
    { framework: 'MCSB', id: 'IM-3' },
    { framework: 'CISA-SCuBA', id: 'MS.AAD.5.1v1' },
    { framework: 'MITRE-ATTACK', id: 'T1098' },
  ],
  tags: ['applications', 'identity'],
  evaluate: (ctx) => {
    const allowed = ctx.data('entra.authorizationPolicy').defaultUserRolePermissions.allowedToCreateApps;
    const facts = [fact('Users can register applications', allowed)];
    return allowed
      ? fail({ reason: 'All users are allowed to register applications.', summary: 'Any user can create application registrations.', facts })
      : pass({ reason: 'Users cannot register applications.', summary: 'App registration is restricted.', facts });
  },
});

export const entraUserConsentRestricted = defineControl({
  id: 'ENTRA-APP-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'User consent to applications is restricted',
  technology: 'entra',
  category: 'Applications',
  subcategory: 'Consent',
  description: 'Checks which permission grant policy governs user consent to applications.',
  rationale:
    'Illicit consent grant attacks trick users into granting a malicious app access to their mail, files or profile. The legacy setting lets users consent to any application for most permissions. Microsoft recommends allowing user consent only for apps from verified publishers requesting low-impact permissions, or disabling user consent and using the admin consent workflow.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'All Microsoft Entra tenants.' },
  requiredEvidence: ['entra.authorizationPolicy'],
  evaluation: {
    logic:
      'Inspect ManagePermissionGrantsForSelf.* entries in permissionGrantPolicyIdsAssignedToDefaultUserRole. FAIL when the legacy policy (microsoft-user-default-legacy) is assigned. PASS when no self-consent policy is assigned (user consent disabled) or only microsoft-user-default-low (verified publishers, low-impact permissions). REVIEW for any other (custom) policy.',
    parameters: {},
  },
  expectedState: 'User consent is disabled, or allowed only for verified publishers and low-impact permissions, with the admin consent workflow enabled.',
  remediation: {
    summary: 'Restrict user consent and enable the admin consent workflow.',
    steps: [
      'Go to Entra ID > Enterprise apps > Consent and permissions > User consent settings.',
      'Select "Allow user consent for apps from verified publishers, for selected permissions" (or "Do not allow user consent").',
      'Enable Entra ID > Enterprise apps > Admin consent settings > "Users can request admin consent to apps they are unable to consent to" and choose reviewers.',
      'Review existing delegated grants for unfamiliar applications.',
    ],
    effort: 'low',
  },
  implementationConsiderations: [
    'Users may be blocked from apps they currently self-approve; enable the admin consent workflow first so they can request access.',
    'Existing consent grants are not removed by this change; review them separately.',
  ],
  impact: 'Users can no longer consent to unverified or high-impact applications themselves.',
  rollback: ['Select the previous option in User consent settings.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-APP-002 is PASS.'],
  references: [REF.userConsent, REF.appPermissionRisk],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-6' },
    { framework: 'MCSB', id: 'IM-3' },
    { framework: 'CISA-SCuBA', id: 'MS.AAD.5.2v1', note: 'SCuBA requires disabling user consent entirely; verified-publisher low-impact consent passes this control' },
    { framework: 'MITRE-ATTACK', id: 'T1528' },
  ],
  tags: ['applications', 'identity', 'data-exfiltration'],
  evaluate: (ctx) => {
    const policies = ctx
      .data('entra.authorizationPolicy')
      .permissionGrantPolicyIdsAssignedToDefaultUserRole.filter((p) => p.toLowerCase().startsWith('managepermissiongrantsforself.'));
    const names = policies.map((p) => p.slice('ManagePermissionGrantsForSelf.'.length));
    const facts = [fact('User consent policies', names.length > 0 ? names.join(', ') : 'none (user consent disabled)')];
    if (names.some((n) => eqi(n, LEGACY_CONSENT))) {
      return fail({ reason: 'Users can consent to any application (legacy consent policy).', summary: 'User consent is unrestricted.', facts });
    }
    const custom = names.filter((n) => !eqi(n, LOW_RISK_CONSENT));
    if (custom.length > 0) {
      return review({
        reason: `A custom permission grant policy governs user consent (${custom.join(', ')}); its conditions are not in the evidence.`,
        summary: 'User consent uses a custom policy that must be reviewed.',
        facts,
      });
    }
    return pass({
      reason: names.length === 0 ? 'User consent is disabled.' : 'User consent is limited to verified publishers and low-impact permissions.',
      summary: 'User consent is restricted.',
      facts,
    });
  },
});

export const entraGuestAccessRestricted = defineControl({
  id: 'ENTRA-EXT-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Guest users have restricted directory access',
  technology: 'entra',
  category: 'External identities',
  subcategory: 'Guest access',
  description: 'Checks the guest user access level configured in the tenant authorization policy.',
  rationale:
    'When guests have the same access as members they can enumerate all users, groups and applications, which gives an attacker who compromises any partner account a full map of the organisation for phishing and privilege escalation.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'All Microsoft Entra tenants.' },
  requiredEvidence: ['entra.authorizationPolicy'],
  evaluation: {
    logic: `FAIL when guestUserRoleId is ${GUEST_ROLE.sameAsMembers} (same access as members). PASS for limited access (${GUEST_ROLE.limited}, the default) or restricted access (${GUEST_ROLE.restricted}). REVIEW for unknown values.`,
    parameters: {},
  },
  expectedState: 'Guest user access is "limited access" or "restricted access".',
  remediation: {
    summary: 'Restrict guest access to directory objects.',
    steps: [
      'Go to Entra ID > External Identities > External collaboration settings.',
      'Under Guest user access select "Guest users have limited access to properties and memberships of directory objects" or, preferably, "Guest user access is restricted to properties and memberships of their own directory objects".',
      'Save.',
    ],
    effort: 'low',
  },
  implementationConsiderations: ['Some collaboration scenarios (for example guests browsing the directory to find colleagues) stop working; test with a guest account.'],
  impact: 'Guests can no longer enumerate directory objects beyond what the selected level allows.',
  rollback: ['Select the previous option in External collaboration settings.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-EXT-001 is PASS.'],
  references: [REF.guestAccessRestrictions, REF.externalCollaborationSettings],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-6' },
    { framework: 'CISA-SCuBA', id: 'MS.AAD.8.1v1' },
    { framework: 'MITRE-ATTACK', id: 'T1087.004' },
  ],
  tags: ['external-identities', 'identity'],
  evaluate: (ctx) => {
    const id = ctx.data('entra.authorizationPolicy').guestUserRoleId.toLowerCase();
    const label = id === GUEST_ROLE.sameAsMembers ? 'Same as members' : id === GUEST_ROLE.limited ? 'Limited access' : id === GUEST_ROLE.restricted ? 'Restricted access' : `Unknown (${id})`;
    const facts = [fact('Guest user access level', label)];
    if (id === GUEST_ROLE.sameAsMembers) return fail({ reason: 'Guest users have the same directory access as members.', summary: 'Guests can enumerate the entire directory.', facts });
    if (id === GUEST_ROLE.limited || id === GUEST_ROLE.restricted) return pass({ reason: `Guest access level is "${label}".`, summary: 'Guest directory access is restricted.', facts });
    return review({ reason: 'The guest user role ID is not a documented value.', summary: 'Guest access level could not be interpreted.', facts });
  },
});

export const entraGuestInvitesRestricted = defineControl({
  id: 'ENTRA-EXT-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Guest invitations are restricted',
  technology: 'entra',
  category: 'External identities',
  subcategory: 'Guest invitations',
  description: 'Checks who is allowed to invite guest users into the tenant.',
  rationale:
    'If everyone, including existing guests, can invite guests, external accounts can be added without oversight, and a compromised guest can invite further attacker-controlled accounts.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'All Microsoft Entra tenants.' },
  requiredEvidence: ['entra.authorizationPolicy'],
  evaluation: {
    logic:
      'FAIL when allowInvitesFrom is "everyone" (guests can invite). PASS for "adminsAndGuestInviters" or "none". PASS with a note for "adminsGuestInvitersAndAllMembers" (members can invite; CISA SCuBA recommends limiting to the Guest Inviter role). REVIEW for unknown values.',
    parameters: {},
  },
  expectedState: 'Only administrators and users assigned the Guest Inviter role can invite guests.',
  remediation: {
    summary: 'Limit guest invitations to administrators and the Guest Inviter role.',
    steps: [
      'Go to Entra ID > External Identities > External collaboration settings.',
      'Under Guest invite settings select "Only users assigned to specific admin roles can invite guest users".',
      'Assign the Guest Inviter role to people who need to invite partners.',
    ],
    effort: 'low',
  },
  implementationConsiderations: ['Teams and SharePoint sharing that relies on users inviting guests will require the Guest Inviter role or an access package.'],
  impact: 'Regular users and guests can no longer invite external users directly.',
  rollback: ['Select the previous guest invite setting.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-EXT-002 is PASS.'],
  references: [REF.externalCollaborationSettings],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-2' },
    { framework: 'CISA-SCuBA', id: 'MS.AAD.8.2v1' },
  ],
  tags: ['external-identities', 'identity'],
  evaluate: (ctx) => {
    const value = ctx.data('entra.authorizationPolicy').allowInvitesFrom;
    const facts = [fact('Allow invites from', value)];
    const v = value.toLowerCase();
    if (v === 'everyone') return fail({ reason: 'Everyone, including guests, can invite guest users.', summary: 'Guest invitations are unrestricted.', facts });
    if (v === 'adminsandguestinviters' || v === 'none') return pass({ reason: `Guest invitations are limited (${value}).`, summary: 'Guest invitations are restricted.', facts });
    if (v === 'adminsguestinvitersandallmembers') {
      return pass({
        reason: 'Members (but not guests) can invite guest users.',
        summary: 'Guests cannot invite other guests.',
        facts,
        notes: ['All member users can invite guests. Consider limiting invitations to the Guest Inviter role (CISA SCuBA MS.AAD.8.2v1).'],
      });
    }
    return review({ reason: `Unrecognised allowInvitesFrom value "${value}".`, summary: 'Guest invite setting could not be interpreted.', facts });
  },
});

export const entraStaleGuests = defineControl({
  id: 'ENTRA-EXT-003',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Inactive guest accounts are removed',
  technology: 'entra',
  category: 'External identities',
  subcategory: 'Guest lifecycle',
  description: 'Finds enabled guest accounts that have not signed in (interactively or non-interactively) within the inactivity threshold, or never signed in since being created before it.',
  rationale:
    'Guest accounts that are no longer used keep access to Teams, SharePoint and applications. If the partner account is compromised or the person leaves the partner organisation, that access remains. Regularly removing inactive guests reduces this exposure.',
  severity: 'low',
  confidence: 'high',
  applicability: { description: 'Tenants with guest users. Sign-in activity requires Microsoft Entra ID P1 or P2.' },
  requiredEvidence: ['entra.guestUsers'],
  evaluation: {
    logic:
      'For enabled guests, take the most recent of lastSignInDateTime and lastNonInteractiveSignInDateTime. Inactive when that date is more than inactiveDays before the assessment date, or when there is no sign-in and the account was created more than inactiveDays before the assessment date. FAIL when any inactive guest exists.',
    parameters: { inactiveDays: 90 },
  },
  expectedState: 'No enabled guest account has been inactive for more than 90 days.',
  remediation: {
    summary: 'Review and remove inactive guest accounts, and automate this with access reviews.',
    steps: [
      'Review the listed guests with the sponsoring team.',
      'Block sign-in, then delete guests that are no longer needed.',
      'Configure a recurring access review for guests (Entra ID Governance) that removes denied or inactive guests automatically.',
    ],
    effort: 'low',
  },
  implementationConsiderations: ['Some guests collaborate rarely; confirm with the business owner before deletion. Deleted guests can be restored for 30 days.'],
  impact: 'Removed guests lose access to shared resources.',
  rollback: ['Restore the deleted guest from Entra ID > Users > Deleted users within 30 days.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-EXT-003 is PASS.'],
  references: [REF.accessReviewsGuests],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-2(3)' },
    { framework: 'MCSB', id: 'PA-4' },
  ],
  tags: ['external-identities', 'identity'],
  evaluate: (ctx) => {
    const threshold = ctx.num('inactiveDays');
    const guests = ctx.data('entra.guestUsers').filter((g) => g.accountEnabled !== false);
    const inactive = guests.flatMap((g) => {
      const signIns = [parseTimestamp(g.lastSignInDateTime), parseTimestamp(g.lastNonInteractiveSignInDateTime)].filter((d): d is Date => d !== undefined);
      const last = signIns.length > 0 ? new Date(Math.max(...signIns.map((d) => d.getTime()))) : undefined;
      if (last !== undefined) {
        const days = daysBetween(last, ctx.assessedAt);
        return days > threshold ? [affected('guestUser', g.id, g.userPrincipalName, `Last sign-in ${days} days ago`)] : [];
      }
      const created = parseTimestamp(g.createdDateTime);
      if (created !== undefined && daysBetween(created, ctx.assessedAt) > threshold) {
        return [affected('guestUser', g.id, g.userPrincipalName, `Never signed in; created ${daysBetween(created, ctx.assessedAt)} days ago`)];
      }
      return [];
    });
    const facts = [fact('Enabled guests', guests.length), fact('Inactive guests', inactive.length), fact('Inactivity threshold (days)', threshold)];
    if (inactive.length > 0) {
      return fail({ reason: `${plural(inactive.length, 'enabled guest')} inactive for more than ${threshold} days.`, summary: 'Inactive guest accounts retain access.', facts, affectedObjects: inactive });
    }
    return pass({ reason: `No enabled guest has been inactive for more than ${threshold} days.`, summary: 'Guest accounts are active.', facts });
  },
});

export const entraUsersCannotCreateTenants = defineControl({
  id: 'ENTRA-TEN-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Non-administrators cannot create new tenants',
  technology: 'entra',
  category: 'Tenant settings',
  subcategory: 'Default user permissions',
  description: 'Checks whether regular users can create new Microsoft Entra tenants (in which they become Global Administrator).',
  rationale:
    'Tenants created by users sit outside the organisation\'s governance and security controls, can be used for shadow IT or to host look-alike applications, and are hard to discover and recover later.',
  severity: 'low',
  confidence: 'high',
  applicability: { description: 'All Microsoft Entra tenants.' },
  requiredEvidence: ['entra.authorizationPolicy'],
  evaluation: {
    logic: 'FAIL when defaultUserRolePermissions.allowedToCreateTenants is true; PASS when false; REVIEW when the property was not returned (null).',
    parameters: {},
  },
  expectedState: 'Restrict non-admin users from creating tenants = Yes.',
  remediation: {
    summary: 'Prevent non-administrators from creating tenants.',
    steps: ['Go to Entra ID > Users > User settings.', 'Set "Restrict non-admin users from creating tenants" to Yes and save.'],
    scriptExample:
      "Connect-MgGraph -Scopes 'Policy.ReadWrite.Authorization'\nUpdate-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions @{ AllowedToCreateTenants = $false }",
    effort: 'low',
  },
  implementationConsiderations: ['Assign the Tenant Creator role to anyone who legitimately needs to create tenants.'],
  impact: 'Regular users can no longer create tenants.',
  rollback: ['Set the option back to No.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-TEN-001 is PASS.'],
  references: [REF.defaultUserPermissions],
  frameworkMappings: [{ framework: 'NIST-800-53r5', id: 'CM-11' }],
  tags: ['identity'],
  evaluate: (ctx) => {
    const value = ctx.data('entra.authorizationPolicy').defaultUserRolePermissions.allowedToCreateTenants;
    const facts = [fact('Users can create tenants', value)];
    if (value === true) return fail({ reason: 'Non-administrators can create tenants.', summary: 'Users can create unmanaged tenants.', facts });
    if (value === false) return pass({ reason: 'Non-administrators cannot create tenants.', summary: 'Tenant creation is restricted.', facts });
    return review({ reason: 'The allowedToCreateTenants property was not present in the evidence.', summary: 'Tenant creation setting could not be determined.', facts });
  },
});
