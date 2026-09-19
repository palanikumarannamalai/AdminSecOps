import type { Reference } from '@adminsecops/schemas';

/**
 * Shared catalog of authoritative references. Controls reference entries from here
 * so a URL is maintained in one place. Only titles and URLs are stored - never
 * copied third-party text. Entries were checked against Microsoft Learn and the
 * publishers' sites when added (see docs/CONTROL-MODEL.md, "References").
 */
const ms = (title: string, url: string): Reference => ({ title, url, publisher: 'Microsoft' });
const nist = (title: string, url: string): Reference => ({ title, url, publisher: 'NIST' });
const cisa = (title: string, url: string): Reference => ({ title, url, publisher: 'CISA' });
const mitre = (title: string, url: string): Reference => ({ title, url, publisher: 'MITRE' });

const LEARN = 'https://learn.microsoft.com/en-us';

export const REF = {
  // --- Microsoft Entra ---------------------------------------------------------
  securityDefaults: ms('Security defaults in Microsoft Entra ID', `${LEARN}/entra/fundamentals/security-defaults`),
  caRequireMfaAdmins: ms(
    'Require multifactor authentication for administrators',
    `${LEARN}/entra/identity/conditional-access/policy-old-require-mfa-admin`,
  ),
  caRequireMfaAllUsers: ms(
    'Require multifactor authentication for all users',
    `${LEARN}/entra/identity/conditional-access/policy-all-users-mfa-strength`,
  ),
  caBlockLegacyAuth: ms(
    'Block legacy authentication with Conditional Access',
    `${LEARN}/entra/identity/conditional-access/policy-block-legacy-authentication`,
  ),
  caPhishingResistantAdmins: ms(
    'Require phishing-resistant multifactor authentication for administrators',
    `${LEARN}/entra/identity/conditional-access/policy-admin-phish-resistant-mfa`,
  ),
  authenticationStrengths: ms(
    'Conditional Access authentication strength',
    `${LEARN}/entra/identity/authentication/concept-authentication-strengths`,
  ),
  caAuthenticationFlows: ms(
    'Block authentication flows with Conditional Access policy',
    `${LEARN}/entra/identity/conditional-access/policy-block-authentication-flows`,
  ),
  caSignInRisk: ms(
    'Require multifactor authentication for elevated sign-in risk',
    `${LEARN}/entra/identity/conditional-access/policy-risk-based-sign-in`,
  ),
  caUserRisk: ms(
    'Require a secure password change for elevated user risk',
    `${LEARN}/entra/identity/conditional-access/policy-risk-based-user`,
  ),
  emergencyAccess: ms(
    'Manage emergency access admin accounts in Microsoft Entra ID',
    `${LEARN}/entra/identity/role-based-access-control/security-emergency-access`,
  ),
  entraBuiltInRoles: ms('Microsoft Entra built-in roles', `${LEARN}/entra/identity/role-based-access-control/permissions-reference`),
  entraRoleBestPractices: ms(
    'Best practices for Microsoft Entra roles',
    `${LEARN}/entra/identity/role-based-access-control/best-practices`,
  ),
  protectM365FromOnPrem: ms(
    'Protecting Microsoft 365 from on-premises attacks',
    `${LEARN}/entra/architecture/protect-m365-from-on-premises-attacks`,
  ),
  pimOverview: ms(
    'What is Microsoft Entra Privileged Identity Management?',
    `${LEARN}/entra/id-governance/privileged-identity-management/pim-configure`,
  ),
  userConsent: ms(
    'Configure how users consent to applications',
    `${LEARN}/entra/identity/enterprise-apps/configure-user-consent`,
  ),
  defaultUserPermissions: ms(
    'What are the default user permissions in Microsoft Entra ID?',
    `${LEARN}/entra/fundamentals/users-default-permissions`,
  ),
  guestAccessRestrictions: ms(
    'Restrict guest access permissions in Microsoft Entra ID',
    `${LEARN}/entra/identity/users/users-restrict-guest-permissions`,
  ),
  externalCollaborationSettings: ms(
    'Configure external collaboration settings',
    `${LEARN}/entra/external-id/external-collaboration-settings-configure`,
  ),
  authMethodsManage: ms(
    'Manage authentication methods for Microsoft Entra ID',
    `${LEARN}/entra/identity/authentication/concept-authentication-methods-manage`,
  ),
  smsVoiceMethods: ms(
    'Phone authentication methods in Microsoft Entra ID',
    `${LEARN}/entra/identity/authentication/concept-authentication-phone-options`,
  ),
  userRegistrationDetails: ms(
    'userRegistrationDetails resource type (Microsoft Graph)',
    `${LEARN}/graph/api/resources/userregistrationdetails?view=graph-rest-1.0`,
  ),
  appCredentialBestPractices: ms(
    'Best practices for Microsoft Entra application credentials',
    `${LEARN}/entra/identity-platform/security-best-practices-for-app-registration`,
  ),
  restrictAppRegistration: ms(
    'Restrict who can create applications',
    `${LEARN}/entra/identity/role-based-access-control/delegate-app-roles#restrict-who-can-create-applications`,
  ),
  pimDeploymentPlan: ms(
    'Plan a Privileged Identity Management deployment',
    `${LEARN}/entra/id-governance/privileged-identity-management/pim-deployment-plan`,
  ),
  secretStandards: ms(
    'Enforce secret and certificate standards for applications',
    `${LEARN}/entra/identity/enterprise-apps/tutorial-enforce-secret-standards`,
  ),
  syncHealth: ms(
    'Monitor Microsoft Entra Connect sync with Microsoft Entra Connect Health',
    `${LEARN}/entra/identity/hybrid/connect/how-to-connect-health-sync`,
  ),
  graphPermissionsReference: ms('Microsoft Graph permissions reference', `${LEARN}/graph/permissions-reference`),
  appPermissionRisk: ms(
    'Enhance security with the principle of least privilege (overprivileged applications)',
    `${LEARN}/entra/identity-platform/secure-least-privileged-access#overprivileged-applications`,
  ),
  passwordProtectionOnPrem: ms(
    'Enforce on-premises Microsoft Entra Password Protection for AD DS',
    `${LEARN}/entra/identity/authentication/concept-password-ban-bad-on-premises`,
  ),
  accessReviewsGuests: ms(
    'Clean up stale guest accounts using access reviews',
    `${LEARN}/entra/identity/users/clean-up-stale-guest-accounts`,
  ),
  syncHardMatchSoftMatch: ms(
    'onPremisesDirectorySynchronizationFeature resource type (hard match and soft match blocking)',
    `${LEARN}/graph/api/resources/onpremisesdirectorysynchronizationfeature?view=graph-rest-1.0`,
  ),
  onPremisesSyncResource: ms(
    'onPremisesDirectorySynchronization resource type (Microsoft Graph)',
    `${LEARN}/graph/api/resources/onpremisesdirectorysynchronization?view=graph-rest-1.0`,
  ),
  syncTroubleshooting: ms(
    'Troubleshoot Microsoft Entra Connect sync',
    `${LEARN}/entra/identity/hybrid/connect/tshoot-connect-sync-errors`,
  ),

  // --- Standards ---------------------------------------------------------------
  nist80053: nist('NIST SP 800-53 Rev. 5', 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final'),
  nist80063b: nist('NIST SP 800-63B-4 Digital Identity Guidelines: Authentication and Authenticator Management', 'https://csrc.nist.gov/pubs/sp/800/63/b/4/final'),
  cisaScuba: cisa(
    'CISA Secure Cloud Business Applications (SCuBA) project',
    'https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications-scuba-project',
  ),
  scubaGearBaselines: cisa('ScubaGear baselines (GitHub)', 'https://github.com/cisagov/ScubaGear/tree/main/PowerShell/ScubaGear/baselines'),

  // --- MITRE ATT&CK --------------------------------------------------------------
  attackValidAccounts: mitre('MITRE ATT&CK T1078: Valid Accounts', 'https://attack.mitre.org/techniques/T1078/'),
  attackCloudAccounts: mitre('MITRE ATT&CK T1078.004: Cloud Accounts', 'https://attack.mitre.org/techniques/T1078/004/'),
  attackPasswordSpraying: mitre('MITRE ATT&CK T1110.003: Password Spraying', 'https://attack.mitre.org/techniques/T1110/003/'),
  attackStealAppToken: mitre('MITRE ATT&CK T1528: Steal Application Access Token', 'https://attack.mitre.org/techniques/T1528/'),
  attackAccountManipulation: mitre('MITRE ATT&CK T1098: Account Manipulation', 'https://attack.mitre.org/techniques/T1098/'),
} as const satisfies Record<string, Reference>;
