/**
 * Contoso - Microsoft Entra ID datasets.
 *
 * Intended state (initial assessment): security defaults off; an all-users MFA
 * policy that is only report-only; an admin MFA policy that misses several
 * administrator roles; legacy authentication blocked; no phishing-resistant MFA
 * policy for admins; device code flow not blocked; six Global Administrators (one
 * synchronised from AD); permanent highly privileged assignments; one admin without
 * MFA; users may register apps; legacy "allow all" user consent; everyone may
 * invite guests; stale guests; a 2-year client secret; an app with
 * RoleManagement.ReadWrite.Directory; SMS enabled; on-premises password protection
 * in Audit mode.
 */
import {
  type entraApiPermissionGrants,
  type entraApplications,
  type entraAuthenticationMethodsPolicy,
  type entraAuthorizationPolicy,
  type entraConditionalAccessPolicies,
  type entraGroupSettings,
  type entraGuestUsers,
  type entraOnPremisesSynchronization,
  type entraOrganization,
  type entraRoleAssignmentScheduleInstances,
  type entraRoleAssignments,
  type entraRoleDefinitions,
  type entraRoleEligibilitySchedules,
  type entraSecurityDefaults,
  type entraServicePrincipals,
  type entraSubscribedSkus,
  type entraUserRegistrationDetails,
} from '@adminsecops/schemas';
import type { z } from 'zod';
import { type Clock, guid, opaqueId } from '../common.js';
import {
  EXCHANGE_APP_ID,
  GRAPH_APP_ID,
  GROUPS,
  INITIAL_DOMAIN,
  MAIL_DOMAIN,
  MICROSOFT_TENANT_ID,
  PRIMARY_DOMAIN,
  ROLE,
  ROLE_NAMES,
  TENANT_ID,
  USERS,
  type CloudUser,
  staffUsers,
} from './identity.js';

type In<D extends { schema: z.ZodType }> = z.input<D['schema']>;
type CaPolicy = In<typeof entraConditionalAccessPolicies>[number];
type RoleAssignment = In<typeof entraRoleAssignments>[number];
type ScheduleInstance = In<typeof entraRoleAssignmentScheduleInstances>[number];

export interface ContosoEntraData {
  organization: In<typeof entraOrganization>;
  subscribedSkus: In<typeof entraSubscribedSkus>;
  securityDefaults: In<typeof entraSecurityDefaults>;
  authorizationPolicy: In<typeof entraAuthorizationPolicy>;
  conditionalAccessPolicies: CaPolicy[];
  roleDefinitions: In<typeof entraRoleDefinitions>;
  roleAssignments: RoleAssignment[];
  roleAssignmentScheduleInstances: ScheduleInstance[];
  roleEligibilitySchedules: In<typeof entraRoleEligibilitySchedules>;
  userRegistrationDetails: In<typeof entraUserRegistrationDetails>;
  authenticationMethodsPolicy: In<typeof entraAuthenticationMethodsPolicy>;
  applications: In<typeof entraApplications>;
  servicePrincipals: In<typeof entraServicePrincipals>;
  apiPermissionGrants: In<typeof entraApiPermissionGrants>;
  groupSettings: In<typeof entraGroupSettings>;
  guestUsers: In<typeof entraGuestUsers>;
  onPremisesSynchronization: In<typeof entraOnPremisesSynchronization>;
}

/** Stable Conditional Access policy IDs (used by the follow-up assessment). */
export const CA_POLICY = {
  mfaAllUsers: guid('contoso:ca:mfa-all-users'),
  mfaAdmins: guid('contoso:ca:mfa-admins'),
  blockLegacy: guid('contoso:ca:block-legacy'),
  compliantDevicePilot: guid('contoso:ca:compliant-device-pilot'),
  blockHighRiskCountries: guid('contoso:ca:block-countries'),
} as const;

export const NAMED_LOCATION_BLOCKED_COUNTRIES = guid('contoso:namedlocation:blocked-countries');

const SKU = {
  m365E3: guid('contoso:sku:spe-e3'),
  entraP2: guid('contoso:sku:aad-premium-p2'),
  powerBiFree: guid('contoso:sku:power-bi-standard'),
} as const;

function plan(name: string, status = 'Success', appliesTo = 'User') {
  return { servicePlanId: guid(`serviceplan:${name}`), servicePlanName: name, provisioningStatus: status, appliesTo };
}

type CaUsers = NonNullable<CaPolicy['conditions']['users']>;

function caUsers(overrides: Partial<CaUsers> = {}): CaUsers {
  return {
    includeUsers: [],
    excludeUsers: [],
    includeGroups: [],
    excludeGroups: [],
    includeRoles: [],
    excludeRoles: [],
    includeGuestsOrExternalUsers: null,
    excludeGuestsOrExternalUsers: null,
    ...overrides,
  };
}

const ALL_APPS = {
  includeApplications: ['All'],
  excludeApplications: [],
  includeUserActions: [],
  includeAuthenticationContextClassReferences: [],
};

function grant(builtInControls: string[], operator = 'OR'): NonNullable<CaPolicy['grantControls']> {
  return { operator, builtInControls, customAuthenticationFactors: [], termsOfUse: [], authenticationStrength: null };
}

function conditionalAccessPolicies(): CaPolicy[] {
  return [
    {
      id: CA_POLICY.mfaAllUsers,
      displayName: 'CA001 - Require MFA for all users',
      state: 'enabledForReportingButNotEnforced',
      createdDateTime: '2025-11-03T14:22:10Z',
      modifiedDateTime: '2026-06-18T09:41:55Z',
      conditions: {
        users: caUsers({ includeUsers: ['All'], excludeGroups: [GROUPS.breakGlass.id] }),
        applications: ALL_APPS,
        clientAppTypes: ['all'],
        signInRiskLevels: [],
        userRiskLevels: [],
        platforms: null,
        locations: null,
        authenticationFlows: null,
      },
      grantControls: grant(['mfa']),
      sessionControls: null,
    },
    {
      id: CA_POLICY.mfaAdmins,
      displayName: 'CA002 - Require MFA for administrators',
      state: 'enabled',
      createdDateTime: '2024-02-12T10:05:31Z',
      modifiedDateTime: '2024-02-12T10:18:02Z',
      conditions: {
        // Created before several roles were delegated; Application, Authentication, Billing,
        // Cloud Application, Helpdesk, Password and Privileged Authentication Administrator are missing.
        users: caUsers({
          includeRoles: [
            ROLE.globalAdministrator,
            ROLE.privilegedRoleAdministrator,
            ROLE.securityAdministrator,
            ROLE.conditionalAccessAdministrator,
            ROLE.exchangeAdministrator,
            ROLE.sharePointAdministrator,
            ROLE.userAdministrator,
          ],
          excludeGroups: [GROUPS.breakGlass.id],
        }),
        applications: ALL_APPS,
        clientAppTypes: ['all'],
        signInRiskLevels: [],
        userRiskLevels: [],
        platforms: null,
        locations: null,
        authenticationFlows: null,
      },
      grantControls: grant(['mfa']),
      sessionControls: {
        signInFrequency: { isEnabled: true, value: 12, type: 'hours', frequencyInterval: 'timeBased' },
        persistentBrowser: null,
      },
    },
    {
      id: CA_POLICY.blockLegacy,
      displayName: 'CA003 - Block legacy authentication',
      state: 'enabled',
      createdDateTime: '2023-09-04T08:12:44Z',
      modifiedDateTime: '2025-01-20T16:30:09Z',
      conditions: {
        users: caUsers({ includeUsers: ['All'], excludeGroups: [GROUPS.breakGlass.id] }),
        applications: ALL_APPS,
        clientAppTypes: ['exchangeActiveSync', 'other'],
        signInRiskLevels: [],
        userRiskLevels: [],
        platforms: null,
        locations: null,
        authenticationFlows: null,
      },
      grantControls: grant(['block']),
      sessionControls: null,
    },
    {
      id: CA_POLICY.compliantDevicePilot,
      displayName: 'CA004 - Require compliant or hybrid joined device (pilot)',
      state: 'disabled',
      createdDateTime: '2026-03-09T13:47:20Z',
      modifiedDateTime: '2026-03-09T13:47:20Z',
      conditions: {
        users: caUsers({ includeGroups: [GROUPS.deviceCompliancePilot.id] }),
        applications: { ...ALL_APPS, includeApplications: ['Office365'] },
        clientAppTypes: ['browser', 'mobileAppsAndDesktopClients'],
        signInRiskLevels: [],
        userRiskLevels: [],
        platforms: { includePlatforms: ['windows'], excludePlatforms: [] },
        locations: null,
        authenticationFlows: null,
      },
      grantControls: grant(['compliantDevice', 'domainJoinedDevice']),
      sessionControls: null,
    },
    {
      id: CA_POLICY.blockHighRiskCountries,
      displayName: 'CA005 - Block sign-ins from blocked countries',
      state: 'enabled',
      createdDateTime: '2024-05-27T11:02:37Z',
      modifiedDateTime: '2025-08-14T07:55:12Z',
      conditions: {
        users: caUsers({ includeUsers: ['All'], excludeGroups: [GROUPS.breakGlass.id] }),
        applications: ALL_APPS,
        clientAppTypes: ['all'],
        signInRiskLevels: [],
        userRiskLevels: [],
        platforms: null,
        locations: { includeLocations: [NAMED_LOCATION_BLOCKED_COUNTRIES], excludeLocations: [] },
        authenticationFlows: null,
      },
      grantControls: grant(['block']),
      sessionControls: null,
    },
  ];
}

function roleDefinitions(): In<typeof entraRoleDefinitions> {
  const builtIn = Object.values(ROLE).map((templateId) => ({
    id: templateId,
    displayName: ROLE_NAMES[templateId] ?? templateId,
    templateId,
    isBuiltIn: true,
    isEnabled: true,
    isPrivileged: null,
  }));
  const customId = guid('contoso:role:custom-helpdesk');
  return [
    ...builtIn,
    {
      id: customId,
      displayName: 'Contoso Helpdesk - Device Reader',
      templateId: customId,
      isBuiltIn: false,
      isEnabled: true,
      isPrivileged: null,
    },
  ];
}

interface AssignmentSpec {
  role: string;
  principal: CloudUser | { id: string; displayName: string; type: 'servicePrincipal' | 'group' };
  /** Permanent (Assigned, no end) or just-in-time activation (Activated, ends later). */
  kind: 'permanent' | 'activated';
  since: string;
}

function isUser(p: AssignmentSpec['principal']): p is CloudUser {
  return 'userPrincipalName' in p;
}

function assignmentSpecs(clock: Clock): AssignmentSpec[] {
  const u = USERS;
  const automation = { id: guid('contoso:sp:provisioning-automation'), displayName: 'Contoso Provisioning Automation', type: 'servicePrincipal' as const };
  return [
    { role: ROLE.globalAdministrator, principal: u.breakGlass1, kind: 'permanent', since: '2023-06-01T09:00:00Z' },
    { role: ROLE.globalAdministrator, principal: u.breakGlass2, kind: 'permanent', since: '2023-06-01T09:05:00Z' },
    { role: ROLE.globalAdministrator, principal: u.alexAdmin, kind: 'permanent', since: '2023-06-02T10:12:00Z' },
    { role: ROLE.globalAdministrator, principal: u.taylorOps, kind: 'permanent', since: '2024-01-15T08:30:00Z' },
    { role: ROLE.globalAdministrator, principal: u.jordanIt, kind: 'permanent', since: '2022-11-21T15:44:00Z' },
    { role: ROLE.globalAdministrator, principal: u.caseyExec, kind: 'permanent', since: '2025-04-07T12:00:00Z' },
    { role: ROLE.securityAdministrator, principal: u.samSecurity, kind: 'permanent', since: '2024-09-10T09:20:00Z' },
    { role: ROLE.exchangeAdministrator, principal: u.rileyMail, kind: 'permanent', since: '2025-10-02T14:10:00Z' },
    { role: ROLE.sharePointAdministrator, principal: u.quinnSites, kind: 'activated', since: clock.ago(0, 2) },
    { role: ROLE.applicationAdministrator, principal: u.jamieApps, kind: 'permanent', since: '2025-02-18T11:35:00Z' },
    { role: ROLE.intuneAdministrator, principal: u.morganDevices, kind: 'permanent', since: '2024-06-03T10:00:00Z' },
    { role: ROLE.helpdeskAdministrator, principal: u.averyHelpdesk, kind: 'permanent', since: '2024-03-11T08:00:00Z' },
    { role: ROLE.helpdeskAdministrator, principal: u.drewHelpdesk, kind: 'permanent', since: '2024-03-11T08:02:00Z' },
    { role: ROLE.globalReader, principal: u.patAuditor, kind: 'permanent', since: '2025-01-06T09:00:00Z' },
    { role: ROLE.directorySynchronizationAccounts, principal: u.syncAccount, kind: 'permanent', since: '2022-05-16T18:25:00Z' },
    { role: ROLE.userAdministrator, principal: automation, kind: 'permanent', since: '2025-07-22T13:15:00Z' },
  ];
}

function roleAssignments(clock: Clock): { assignments: RoleAssignment[]; instances: ScheduleInstance[] } {
  const assignments: RoleAssignment[] = [];
  const instances: ScheduleInstance[] = [];
  for (const spec of assignmentSpecs(clock)) {
    const p = spec.principal;
    const id = opaqueId(`contoso:roleassignment:${spec.role}:${p.id}`);
    assignments.push({
      id,
      roleDefinitionId: spec.role,
      principalId: p.id,
      directoryScopeId: '/',
      principal: isUser(p)
        ? {
            id: p.id,
            principalType: 'user',
            displayName: p.displayName,
            userPrincipalName: p.userPrincipalName,
            userType: 'Member',
            accountEnabled: true,
            onPremisesSyncEnabled: p.onPremisesSyncEnabled ? true : null,
          }
        : {
            id: p.id,
            principalType: p.type,
            displayName: p.displayName,
            userPrincipalName: null,
            userType: null,
            accountEnabled: true,
            onPremisesSyncEnabled: null,
          },
    });
    instances.push({
      id: opaqueId(`contoso:roleinstance:${spec.role}:${p.id}`),
      roleDefinitionId: spec.role,
      principalId: p.id,
      directoryScopeId: '/',
      assignmentType: spec.kind === 'permanent' ? 'Assigned' : 'Activated',
      memberType: 'Direct',
      startDateTime: spec.since,
      endDateTime: spec.kind === 'permanent' ? null : clock.ahead(0, 6),
    });
  }
  return { assignments, instances };
}

function roleEligibilitySchedules(): In<typeof entraRoleEligibilitySchedules> {
  const eligible: Array<[string, CloudUser, string, string | null]> = [
    [ROLE.privilegedRoleAdministrator, USERS.alexAdmin, '2025-03-03T09:00:00Z', null],
    [ROLE.securityAdministrator, USERS.taylorOps, '2025-03-03T09:05:00Z', null],
    [ROLE.sharePointAdministrator, USERS.quinnSites, '2025-05-12T10:30:00Z', '2027-05-12T10:30:00Z'],
    [ROLE.conditionalAccessAdministrator, USERS.samSecurity, '2025-03-03T09:10:00Z', null],
    [ROLE.exchangeAdministrator, USERS.taylorOps, '2025-06-23T14:00:00Z', '2026-12-23T14:00:00Z'],
  ];
  return eligible.map(([role, principal, start, end]) => ({
    id: opaqueId(`contoso:eligibility:${role}:${principal.id}`),
    roleDefinitionId: role,
    principalId: principal.id,
    directoryScopeId: '/',
    memberType: 'Direct',
    startDateTime: start,
    endDateTime: end,
  }));
}

const METHODS = {
  authenticatorAndOtp: ['microsoftAuthenticatorPush', 'softwareOneTimePasscode'],
  authenticatorAndSms: ['microsoftAuthenticatorPush', 'mobilePhone'],
  smsOnly: ['mobilePhone'],
  whfb: ['windowsHelloForBusiness', 'microsoftAuthenticatorPush'],
  fido2: ['fido2'],
  fido2AndAuthenticator: ['fido2', 'microsoftAuthenticatorPush'],
};

function userRegistrationDetails(): In<typeof entraUserRegistrationDetails> {
  const admins: Array<[CloudUser, string[]]> = [
    [USERS.breakGlass1, METHODS.fido2],
    [USERS.breakGlass2, METHODS.fido2],
    [USERS.alexAdmin, METHODS.fido2AndAuthenticator],
    [USERS.taylorOps, METHODS.authenticatorAndOtp],
    [USERS.jordanIt, METHODS.authenticatorAndSms],
    [USERS.caseyExec, METHODS.smsOnly],
    [USERS.samSecurity, METHODS.fido2AndAuthenticator],
    [USERS.rileyMail, []],
    [USERS.quinnSites, METHODS.authenticatorAndOtp],
    [USERS.jamieApps, METHODS.authenticatorAndOtp],
    [USERS.morganDevices, METHODS.whfb],
    [USERS.averyHelpdesk, METHODS.authenticatorAndSms],
    [USERS.drewHelpdesk, METHODS.authenticatorAndOtp],
  ];
  const rows: In<typeof entraUserRegistrationDetails> = admins.map(([user, methods]) => ({
    id: user.id,
    userPrincipalName: user.userPrincipalName,
    userType: 'member',
    isAdmin: true,
    isMfaRegistered: methods.length > 0,
    isMfaCapable: methods.length > 0,
    isPasswordlessCapable: methods.includes('fido2') || methods.includes('windowsHelloForBusiness'),
    isSsprRegistered: methods.length > 0,
    methodsRegistered: methods,
  }));
  const others: CloudUser[] = [USERS.patAuditor, USERS.robinSales];
  for (const user of others) {
    rows.push({
      id: user.id,
      userPrincipalName: user.userPrincipalName,
      userType: 'member',
      isAdmin: user === USERS.patAuditor,
      isMfaRegistered: true,
      isMfaCapable: true,
      isPasswordlessCapable: false,
      isSsprRegistered: true,
      methodsRegistered: METHODS.authenticatorAndOtp,
    });
  }
  for (const staff of staffUsers()) {
    // Deterministic distribution: ~9% not registered, ~20% SMS-based, a few Windows Hello users.
    const bucket = staff.index % 23;
    const methods =
      bucket === 0 || bucket === 7
        ? []
        : bucket % 5 === 1
          ? METHODS.authenticatorAndSms
          : bucket === 11
            ? METHODS.smsOnly
            : bucket === 19
              ? METHODS.whfb
              : METHODS.authenticatorAndOtp;
    rows.push({
      id: staff.id,
      userPrincipalName: staff.userPrincipalName,
      userType: 'member',
      isAdmin: false,
      isMfaRegistered: methods.length > 0,
      isMfaCapable: methods.length > 0,
      isPasswordlessCapable: methods.includes('windowsHelloForBusiness'),
      isSsprRegistered: methods.length > 0,
      methodsRegistered: methods,
    });
  }
  return rows;
}

export const APP = {
  hrConnector: { id: guid('contoso:app:hr-connector:object'), appId: guid('contoso:app:hr-connector'), sp: guid('contoso:sp:hr-connector') },
  graphAutomation: { id: guid('contoso:app:graph-automation:object'), appId: guid('contoso:app:graph-automation'), sp: guid('contoso:sp:graph-automation') },
  intranet: { id: guid('contoso:app:intranet:object'), appId: guid('contoso:app:intranet'), sp: guid('contoso:sp:intranet') },
  legacyReporting: { id: guid('contoso:app:legacy-reporting:object'), appId: guid('contoso:app:legacy-reporting'), sp: guid('contoso:sp:legacy-reporting') },
  mailArchiver: { id: guid('contoso:app:mail-archiver:object'), appId: guid('contoso:app:mail-archiver'), sp: guid('contoso:sp:mail-archiver') },
  provisioning: { id: guid('contoso:app:provisioning:object'), appId: guid('contoso:app:provisioning'), sp: guid('contoso:sp:provisioning-automation') },
} as const;

function applications(): In<typeof entraApplications> {
  return [
    {
      id: APP.hrConnector.id,
      appId: APP.hrConnector.appId,
      displayName: 'Contoso HR Connector',
      signInAudience: 'AzureADMyOrg',
      createdDateTime: '2025-03-01T10:14:22Z',
      passwordCredentials: [
        // Two-year client secret.
        { keyId: guid('contoso:cred:hr-connector'), displayName: 'hr-sync', startDateTime: '2025-03-01T10:20:00Z', endDateTime: '2027-03-01T10:20:00Z' },
      ],
      keyCredentials: [],
    },
    {
      id: APP.graphAutomation.id,
      appId: APP.graphAutomation.appId,
      displayName: 'Contoso Identity Automation',
      signInAudience: 'AzureADMyOrg',
      createdDateTime: '2024-10-14T09:02:51Z',
      passwordCredentials: [],
      keyCredentials: [
        {
          keyId: guid('contoso:cred:graph-automation'),
          displayName: 'CN=contoso-identity-automation',
          startDateTime: '2025-10-14T00:00:00Z',
          endDateTime: '2026-10-14T00:00:00Z',
          type: 'AsymmetricX509Cert',
          usage: 'Verify',
        },
      ],
    },
    {
      id: APP.intranet.id,
      appId: APP.intranet.appId,
      displayName: 'Contoso Intranet',
      signInAudience: 'AzureADMyOrg',
      createdDateTime: '2023-04-18T12:40:09Z',
      passwordCredentials: [],
      keyCredentials: [],
    },
    {
      id: APP.legacyReporting.id,
      appId: APP.legacyReporting.appId,
      displayName: 'Legacy Reporting Tool',
      signInAudience: 'AzureADMultipleOrgs',
      createdDateTime: '2021-08-30T15:27:43Z',
      passwordCredentials: [
        // Expired secret left in place.
        { keyId: guid('contoso:cred:legacy-reporting'), displayName: 'reporting', startDateTime: '2024-02-01T00:00:00Z', endDateTime: '2026-02-01T00:00:00Z' },
      ],
      keyCredentials: [],
    },
    {
      id: APP.mailArchiver.id,
      appId: APP.mailArchiver.appId,
      displayName: 'Contoso Mail Archiver',
      signInAudience: 'AzureADMyOrg',
      createdDateTime: '2025-01-09T08:55:30Z',
      passwordCredentials: [
        { keyId: guid('contoso:cred:mail-archiver'), displayName: 'archiver', startDateTime: '2026-01-09T09:00:00Z', endDateTime: '2026-07-08T09:00:00Z' },
        { keyId: guid('contoso:cred:mail-archiver-2'), displayName: 'archiver-2026h2', startDateTime: '2026-07-01T09:00:00Z', endDateTime: '2026-12-28T09:00:00Z' },
      ],
      keyCredentials: [],
    },
    {
      id: APP.provisioning.id,
      appId: APP.provisioning.appId,
      displayName: 'Contoso Provisioning Automation',
      signInAudience: 'AzureADMyOrg',
      createdDateTime: '2025-07-22T12:58:04Z',
      passwordCredentials: [],
      keyCredentials: [
        {
          keyId: guid('contoso:cred:provisioning'),
          displayName: 'CN=contoso-provisioning',
          startDateTime: '2025-07-22T00:00:00Z',
          endDateTime: '2026-07-22T00:00:00Z',
          type: 'AsymmetricX509Cert',
          usage: 'Verify',
        },
      ],
    },
  ];
}

function servicePrincipals(): In<typeof entraServicePrincipals> {
  const own = (key: keyof typeof APP, displayName: string) => ({
    id: APP[key].sp,
    appId: APP[key].appId,
    displayName,
    servicePrincipalType: 'Application',
    appOwnerOrganizationId: TENANT_ID,
    accountEnabled: true,
    passwordCredentials: [],
    keyCredentials: [],
  });
  return [
    {
      id: guid('contoso:sp:microsoft-graph'),
      appId: GRAPH_APP_ID,
      displayName: 'Microsoft Graph',
      servicePrincipalType: 'Application',
      appOwnerOrganizationId: MICROSOFT_TENANT_ID,
      accountEnabled: true,
      passwordCredentials: [],
      keyCredentials: [],
    },
    {
      id: guid('contoso:sp:exchange-online'),
      appId: EXCHANGE_APP_ID,
      displayName: 'Office 365 Exchange Online',
      servicePrincipalType: 'Application',
      appOwnerOrganizationId: MICROSOFT_TENANT_ID,
      accountEnabled: true,
      passwordCredentials: [],
      keyCredentials: [],
    },
    own('hrConnector', 'Contoso HR Connector'),
    own('graphAutomation', 'Contoso Identity Automation'),
    own('intranet', 'Contoso Intranet'),
    own('legacyReporting', 'Legacy Reporting Tool'),
    own('mailArchiver', 'Contoso Mail Archiver'),
    own('provisioning', 'Contoso Provisioning Automation'),
    {
      id: guid('contoso:sp:northwind-survey'),
      appId: guid('northwind:app:survey'),
      displayName: 'Northwind Survey Builder',
      servicePrincipalType: 'Application',
      appOwnerOrganizationId: guid('northwind:tenant'),
      accountEnabled: true,
      passwordCredentials: [],
      keyCredentials: [],
    },
    {
      id: guid('contoso:sp:mi-automation'),
      appId: guid('contoso:mi:automation-account'),
      displayName: 'aa-contoso-prod-automation',
      servicePrincipalType: 'ManagedIdentity',
      appOwnerOrganizationId: null,
      accountEnabled: true,
      passwordCredentials: [],
      keyCredentials: [],
    },
  ];
}

/** Microsoft Graph application permissions (app roles) referenced by the fixture. */
export const GRAPH_APP_ROLE = {
  roleManagementReadWriteDirectory: { id: '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8', value: 'RoleManagement.ReadWrite.Directory' },
  directoryReadAll: { id: '7ab1d382-f21e-4acd-a863-ba3e13f7da61', value: 'Directory.Read.All' },
  userReadAll: { id: 'df021288-bdef-4463-88db-98f22de89214', value: 'User.Read.All' },
  userReadWriteAll: { id: '741f803b-c850-494e-b5df-cde7c675a1ca', value: 'User.ReadWrite.All' },
  groupMemberReadWriteAll: { id: 'dbaae8cf-10b5-4b86-a4a1-f871c94c6695', value: 'GroupMember.ReadWrite.All' },
  applicationReadWriteAll: { id: '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9', value: 'Application.ReadWrite.All' },
  mailSend: { id: 'b633e1c5-b582-4048-a93e-9f11b44c7e96', value: 'Mail.Send' },
  sitesReadAll: { id: '332a536c-c7ef-4017-ab91-336970924f0d', value: 'Sites.Read.All' },
} as const;

export const EXCHANGE_APP_ROLE = {
  fullAccessAsApp: { id: 'dc890d15-9560-4a4c-9b7f-a736ec74ec40', value: 'full_access_as_app' },
  manageAsApp: { id: 'dc50a0fb-09a3-484d-be87-e023b12c6440', value: 'Exchange.ManageAsApp' },
} as const;

function apiPermissionGrants(): In<typeof entraApiPermissionGrants> {
  const graphSp = guid('contoso:sp:microsoft-graph');
  const exoSp = guid('contoso:sp:exchange-online');
  const assignment = (resource: string, sp: string, name: string, role: { id: string }, created: string) => ({
    id: opaqueId(`contoso:approle:${resource}:${sp}:${role.id}`),
    principalId: sp,
    principalType: 'ServicePrincipal',
    principalDisplayName: name,
    appRoleId: role.id,
    createdDateTime: created,
  });
  return [
    {
      resourceAppId: GRAPH_APP_ID,
      resourceDisplayName: 'Microsoft Graph',
      appRoles: Object.values(GRAPH_APP_ROLE).map((r) => ({ id: r.id, value: r.value })),
      assignments: [
        assignment(graphSp, APP.graphAutomation.sp, 'Contoso Identity Automation', GRAPH_APP_ROLE.roleManagementReadWriteDirectory, '2024-10-14T09:30:12Z'),
        assignment(graphSp, APP.graphAutomation.sp, 'Contoso Identity Automation', GRAPH_APP_ROLE.directoryReadAll, '2024-10-14T09:30:12Z'),
        assignment(graphSp, APP.hrConnector.sp, 'Contoso HR Connector', GRAPH_APP_ROLE.userReadWriteAll, '2025-03-01T10:31:47Z'),
        assignment(graphSp, APP.provisioning.sp, 'Contoso Provisioning Automation', GRAPH_APP_ROLE.groupMemberReadWriteAll, '2025-07-22T13:20:05Z'),
        assignment(graphSp, APP.legacyReporting.sp, 'Legacy Reporting Tool', GRAPH_APP_ROLE.sitesReadAll, '2021-08-30T15:40:00Z'),
        assignment(graphSp, APP.intranet.sp, 'Contoso Intranet', GRAPH_APP_ROLE.userReadAll, '2023-04-18T12:55:18Z'),
      ],
    },
    {
      resourceAppId: EXCHANGE_APP_ID,
      resourceDisplayName: 'Office 365 Exchange Online',
      appRoles: Object.values(EXCHANGE_APP_ROLE).map((r) => ({ id: r.id, value: r.value })),
      assignments: [
        assignment(exoSp, APP.mailArchiver.sp, 'Contoso Mail Archiver', EXCHANGE_APP_ROLE.fullAccessAsApp, '2025-01-09T09:12:40Z'),
      ],
    },
  ];
}

function guestUsers(clock: Clock): In<typeof entraGuestUsers> {
  const guest = (
    key: string,
    upnLocal: string,
    created: string,
    state: string,
    lastSignIn: string | null,
    lastNonInteractive: string | null,
    enabled = true,
  ) => ({
    id: guid(`contoso:guest:${key}`),
    userPrincipalName: `${upnLocal}#EXT#@${INITIAL_DOMAIN}`,
    accountEnabled: enabled,
    createdDateTime: created,
    externalUserState: state,
    lastSignInDateTime: lastSignIn,
    lastNonInteractiveSignInDateTime: lastNonInteractive,
  });
  return [
    guest('consultant-1', 'lee.consultant_partner-co.example', '2024-04-02T10:11:00Z', 'Accepted', clock.ago(3, 4), clock.ago(1, 2)),
    guest('consultant-2', 'kai.architect_partner-co.example', '2024-04-02T10:15:00Z', 'Accepted', clock.ago(12, 1), clock.ago(9)),
    guest('auditor', 'reese.audit_audit-firm.example', '2025-01-20T09:00:00Z', 'Accepted', clock.ago(41), clock.ago(38)),
    guest('vendor-1', 'charlie.support_vendor-one.example', '2023-02-14T13:20:00Z', 'Accepted', clock.ago(212), clock.ago(205)),
    guest('vendor-2', 'frankie.dev_vendor-two.example', '2022-09-05T08:45:00Z', 'Accepted', clock.ago(401), null),
    guest('agency', 'parker.design_creative-agency.example', '2024-11-11T16:05:00Z', 'Accepted', clock.ago(133), clock.ago(131)),
    guest('pending-1', 'jesse.sales_reseller.example', clock.ago(187, 3), 'PendingAcceptance', null, null),
    guest('pending-2', 'sam.contractor_personal-mail.example', clock.ago(9, 6), 'PendingAcceptance', null, null),
    guest('former', 'drew.intern_university.example', '2023-06-19T07:30:00Z', 'Accepted', clock.ago(344), null, false),
    guest('partner-2', 'robin.pm_partner-co.example', '2025-09-30T12:00:00Z', 'Accepted', clock.ago(6, 5), clock.ago(2)),
    guest('azure-owner', 'morgan.cloud_partner-co.example', '2024-08-08T09:40:00Z', 'Accepted', clock.ago(17), clock.ago(16)),
  ];
}

export const GUEST_AZURE_OWNER = {
  id: guid('contoso:guest:azure-owner'),
  userPrincipalName: `morgan.cloud_partner-co.example#EXT#@${INITIAL_DOMAIN}`,
};

export function contosoEntra(clock: Clock): ContosoEntraData {
  const { assignments, instances } = roleAssignments(clock);
  return {
    organization: {
      id: TENANT_ID,
      displayName: 'Contoso',
      createdDateTime: '2019-03-11T17:26:04Z',
      onPremisesSyncEnabled: true,
      onPremisesLastSyncDateTime: clock.ago(0, 0, 23),
      verifiedDomains: [
        { name: INITIAL_DOMAIN, isDefault: false, isInitial: true, type: 'Managed', capabilities: 'Email, OfficeCommunicationsOnline' },
        { name: PRIMARY_DOMAIN, isDefault: true, isInitial: false, type: 'Managed', capabilities: 'Email, OfficeCommunicationsOnline, Intune' },
        { name: MAIL_DOMAIN, isDefault: false, isInitial: false, type: 'Managed', capabilities: 'Email' },
      ],
    },
    subscribedSkus: [
      {
        skuId: SKU.m365E3,
        skuPartNumber: 'SPE_E3',
        capabilityStatus: 'Enabled',
        consumedUnits: 486,
        prepaidUnits: { enabled: 500, suspended: 0, warning: 0 },
        servicePlans: [
          plan('AAD_PREMIUM'),
          plan('MFA_PREMIUM'),
          plan('INTUNE_A'),
          plan('EXCHANGE_S_ENTERPRISE'),
          plan('SHAREPOINTENTERPRISE'),
          plan('TEAMS1'),
          plan('OFFICESUBSCRIPTION'),
          plan('MICROSOFTBOOKINGS', 'Disabled'),
        ],
      },
      {
        skuId: SKU.entraP2,
        skuPartNumber: 'AAD_PREMIUM_P2',
        capabilityStatus: 'Enabled',
        consumedUnits: 18,
        prepaidUnits: { enabled: 25, suspended: 0, warning: 0 },
        servicePlans: [plan('AAD_PREMIUM'), plan('AAD_PREMIUM_P2'), plan('MFA_PREMIUM')],
      },
      {
        skuId: SKU.powerBiFree,
        skuPartNumber: 'POWER_BI_STANDARD',
        capabilityStatus: 'Enabled',
        consumedUnits: 37,
        prepaidUnits: { enabled: 1000000, suspended: 0, warning: 0 },
        servicePlans: [plan('BI_AZURE_P0')],
      },
    ],
    securityDefaults: { isEnabled: false },
    authorizationPolicy: {
      allowInvitesFrom: 'everyone',
      allowedToSignUpEmailBasedSubscriptions: true,
      allowEmailVerifiedUsersToJoinOrganization: false,
      allowUserConsentForRiskyApps: null,
      blockMsolPowerShell: false,
      guestUserRoleId: '10dae51f-b6af-4016-8d66-8c2a99b929b3',
      permissionGrantPolicyIdsAssignedToDefaultUserRole: ['ManagePermissionGrantsForSelf.microsoft-user-default-legacy'],
      defaultUserRolePermissions: {
        allowedToCreateApps: true,
        allowedToCreateSecurityGroups: true,
        allowedToCreateTenants: false,
        allowedToReadBitlockerKeysForOwnedDevice: true,
        allowedToReadOtherUsers: true,
      },
    },
    conditionalAccessPolicies: conditionalAccessPolicies(),
    roleDefinitions: roleDefinitions(),
    roleAssignments: assignments,
    roleAssignmentScheduleInstances: instances,
    roleEligibilitySchedules: roleEligibilitySchedules(),
    userRegistrationDetails: userRegistrationDetails(),
    authenticationMethodsPolicy: {
      policyMigrationState: 'migrationInProgress',
      authenticationMethodConfigurations: [
        { id: 'Fido2', state: 'enabled', includeTargets: [{ targetType: 'group', id: 'all_users' }] },
        { id: 'MicrosoftAuthenticator', state: 'enabled', includeTargets: [{ targetType: 'group', id: 'all_users' }] },
        { id: 'Sms', state: 'enabled', includeTargets: [{ targetType: 'group', id: 'all_users' }] },
        { id: 'TemporaryAccessPass', state: 'enabled', includeTargets: [{ targetType: 'group', id: GROUPS.tapUsers.id }] },
        { id: 'SoftwareOath', state: 'enabled', includeTargets: [{ targetType: 'group', id: 'all_users' }] },
        { id: 'Voice', state: 'disabled', includeTargets: [] },
        { id: 'Email', state: 'enabled', includeTargets: [{ targetType: 'group', id: 'all_users' }] },
        { id: 'X509Certificate', state: 'disabled', includeTargets: [] },
      ],
    },
    applications: applications(),
    servicePrincipals: servicePrincipals(),
    apiPermissionGrants: apiPermissionGrants(),
    groupSettings: [
      {
        id: guid('contoso:groupsetting:password-rules'),
        displayName: 'Password Rule Settings',
        templateId: '5cf42378-d67d-4f36-ba46-e8b86229381d',
        values: [
          { name: 'BannedPasswordCheckOnPremisesMode', value: 'Audit' },
          { name: 'EnableBannedPasswordCheckOnPremises', value: 'True' },
          { name: 'EnableBannedPasswordCheck', value: 'True' },
          { name: 'LockoutDurationInSeconds', value: '60' },
          { name: 'LockoutThreshold', value: '10' },
        ],
      },
      {
        id: guid('contoso:groupsetting:group-unified'),
        displayName: 'Group.Unified',
        templateId: '62375ab9-6b52-47ed-826b-58e47e0e304b',
        values: [
          { name: 'EnableGroupCreation', value: 'true' },
          { name: 'AllowGuestsToBeGroupOwner', value: 'false' },
          { name: 'AllowGuestsToAccessGroups', value: 'true' },
          { name: 'AllowToAddGuests', value: 'true' },
          { name: 'EnableMIPLabels', value: 'false' },
        ],
      },
    ],
    guestUsers: guestUsers(clock),
    onPremisesSynchronization: [
      {
        id: TENANT_ID,
        features: {
          passwordSyncEnabled: true,
          passwordWritebackEnabled: true,
          blockSoftMatchEnabled: false,
          blockCloudObjectTakeoverThroughHardMatchEnabled: false,
          softMatchOnUpnEnabled: true,
          userWritebackEnabled: false,
          deviceWritebackEnabled: false,
          passThroughAuthenticationEnabled: false,
          synchronizeUpnForManagedUsersEnabled: true,
        },
      },
    ],
  };
}
