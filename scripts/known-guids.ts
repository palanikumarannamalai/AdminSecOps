/**
 * GUIDs the secret scan (`scripts/scan-secrets.ts`) accepts in tracked files. Any other GUID
 * fails the scan, so a real tenant, subscription, client, object or deployment ID cannot be
 * committed by accident.
 *
 * A GUID is accepted when it is:
 * 1. obviously fictional by shape (`isObviouslyFictionalGuid`), for example
 *    `aaaaaaaa-0000-4000-8000-000000000001` or `a1a1a1a1-0000-4000-8000-000000000001`;
 * 2. produced by the fixture generator's seeded `guid()` (checked by the scan itself);
 * 3. listed below: an identifier Microsoft publishes (the same in every tenant or
 *    forest), this project's own identifier, or a hand-written fictional test value.
 *
 * Before adding an entry, confirm it on the cited Microsoft page. Never add a tenant ID,
 * subscription ID, application (client) ID, object ID or deployment ID from a real
 * environment: use a fictional value or a placeholder such as `<client-id>` instead.
 */

/** GUIDs whose shape shows they are made up (repeated or zero-filled groups). */
export function isObviouslyFictionalGuid(value: string): boolean {
  const guid = value.toLowerCase();
  return (
    /^([0-9a-f])\1{7}-/.test(guid) || // aaaaaaaa-…, 11111111-…
    /^([0-9a-f]{2})\1{3}-/.test(guid) || // a1a1a1a1-…
    /^[0-9a-f]{8}-0000-[0-9a-f]000-[0-9a-f]000-/.test(guid) // …-0000-4000-8000-…
  );
}

const ENTRA_ROLES =
  'https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference';
const AZURE_ROLES = 'https://learn.microsoft.com/azure/role-based-access-control/built-in-roles';
const GRAPH_PERMISSIONS = 'https://learn.microsoft.com/graph/permissions-reference';
const AUTHORIZATION_POLICY = 'https://learn.microsoft.com/graph/api/resources/authorizationpolicy';
const GROUP_SETTINGS = 'https://learn.microsoft.com/entra/identity/users/groups-settings-cmdlets';
const LICENSING =
  'https://learn.microsoft.com/entra/identity/users/licensing-service-plan-reference';
const EXCHANGE_APP_ONLY =
  'https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2';
const EWS_OAUTH =
  'https://learn.microsoft.com/exchange/client-developer/exchange-web-services/how-to-authenticate-an-ews-application-by-using-oauth';
const SERVICE_PRINCIPALS =
  'https://learn.microsoft.com/entra/identity/monitoring-health/reference-service-principal-table';
const FIRST_PARTY =
  'https://learn.microsoft.com/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in';
const AD_EXTENDED_RIGHTS =
  'https://learn.microsoft.com/windows/win32/adschema/r-certificate-enrollment';
const CERTIFICATE_TEMPLATES =
  'https://learn.microsoft.com/openspecs/windows_protocols/ms-crtd/211ab1e3-bad6-416d-9d56-8480b42617a4';
const NAME_FLAG =
  'https://learn.microsoft.com/windows/win32/adschema/a-mspki-certificate-name-flag';
const DEFAULT_GPOS =
  'https://learn.microsoft.com/troubleshoot/windows-server/group-policy/rebuild-sysvol-tree-and-content-in-a-domain';
const AUDIT_SUBCATEGORIES =
  'https://learn.microsoft.com/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d';
const GPP_CLASSES =
  'https://learn.microsoft.com/openspecs/windows_protocols/ms-gppref/12512ed6-0632-4e90-a112-d3d2cd41df6c';

/** Identifiers Microsoft publishes; each is the same in every tenant, subscription or forest. */
export const MICROSOFT_PUBLISHED_GUIDS: Readonly<Record<string, { name: string; source: string }>> =
  {
    // Microsoft Entra built-in role template IDs
    '62e90394-69f5-4237-9190-012177145e10': { name: 'Global Administrator', source: ENTRA_ROLES },
    'f2ef992c-3afb-46b9-b7cf-a126ee74c451': { name: 'Global Reader', source: ENTRA_ROLES },
    '194ae4cb-b126-40b2-bd5b-6091b380977d': { name: 'Security Administrator', source: ENTRA_ROLES },
    '5d6b6bb7-de71-4623-b4af-96380a352509': { name: 'Security Reader', source: ENTRA_ROLES },
    'e8611ab8-c189-46e8-94e1-60213ab1f814': {
      name: 'Privileged Role Administrator',
      source: ENTRA_ROLES,
    },
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13': {
      name: 'Privileged Authentication Administrator',
      source: ENTRA_ROLES,
    },
    'c4e39bd9-1100-46d3-8c65-fb160da0071f': {
      name: 'Authentication Administrator',
      source: ENTRA_ROLES,
    },
    '0526716b-113d-4c15-b2c8-68e3c22b9f80': {
      name: 'Authentication Policy Administrator',
      source: ENTRA_ROLES,
    },
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': {
      name: 'Application Administrator',
      source: ENTRA_ROLES,
    },
    '158c047a-c907-4556-b7ef-446551a6b5f7': {
      name: 'Cloud Application Administrator',
      source: ENTRA_ROLES,
    },
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9': {
      name: 'Conditional Access Administrator',
      source: ENTRA_ROLES,
    },
    '29232cdf-9323-42fd-ade2-1d097af3e4de': { name: 'Exchange Administrator', source: ENTRA_ROLES },
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': {
      name: 'SharePoint Administrator',
      source: ENTRA_ROLES,
    },
    '3a2c62db-5318-420d-8d74-23affee5d9d5': { name: 'Intune Administrator', source: ENTRA_ROLES },
    'fe930be7-5e62-47db-91af-98c3a49a38b1': { name: 'User Administrator', source: ENTRA_ROLES },
    '729827e3-9c14-49f7-bb1b-9608f156bbb8': { name: 'Helpdesk Administrator', source: ENTRA_ROLES },
    '966707d0-3269-4727-9be2-8c3a10f19b9d': { name: 'Password Administrator', source: ENTRA_ROLES },
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2': {
      name: 'Hybrid Identity Administrator',
      source: ENTRA_ROLES,
    },
    'd29b2b05-8046-44ba-8758-1e26182fcf32': {
      name: 'Directory Synchronization Accounts',
      source: ENTRA_ROLES,
    },
    'b0f54661-2d74-4c50-afa3-1ec803f12efe': { name: 'Billing Administrator', source: ENTRA_ROLES },
    '4a5d8f65-41da-4de4-8968-e035b65339cf': { name: 'Reports Reader', source: ENTRA_ROLES },
    // Guest access role IDs (authorizationPolicy.guestUserRoleId)
    'a0b1b346-4d3e-4e8b-98f8-753987be4970': {
      name: 'User (guests same as members)',
      source: AUTHORIZATION_POLICY,
    },
    '10dae51f-b6af-4016-8d66-8c2a99b929b3': { name: 'Guest User', source: AUTHORIZATION_POLICY },
    '2af84b1e-32c8-42b7-82bc-daa82404023b': {
      name: 'Restricted Guest User',
      source: AUTHORIZATION_POLICY,
    },
    // Azure built-in role definition IDs
    'acdd72a7-3385-48ef-bd42-f606fba81ae7': { name: 'Reader', source: AZURE_ROLES },
    'b24988ac-6180-42a0-ab88-20f7382dd24c': { name: 'Contributor', source: AZURE_ROLES },
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635': { name: 'Owner', source: AZURE_ROLES },
    '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9': {
      name: 'User Access Administrator',
      source: AZURE_ROLES,
    },
    'f58310d9-a9f6-439a-9e8d-f62e7b41a168': {
      name: 'Role Based Access Control Administrator',
      source: AZURE_ROLES,
    },
    // Microsoft Graph application permission (app role) IDs
    '7ab1d382-f21e-4acd-a863-ba3e13f7da61': {
      name: 'Directory.Read.All',
      source: GRAPH_PERMISSIONS,
    },
    '19dbc75e-c2e2-444c-a770-ec69d8559fc7': {
      name: 'Directory.ReadWrite.All',
      source: GRAPH_PERMISSIONS,
    },
    '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9': {
      name: 'Application.ReadWrite.All',
      source: GRAPH_PERMISSIONS,
    },
    '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8': {
      name: 'RoleManagement.ReadWrite.Directory',
      source: GRAPH_PERMISSIONS,
    },
    'df021288-bdef-4463-88db-98f22de89214': { name: 'User.Read.All', source: GRAPH_PERMISSIONS },
    '741f803b-c850-494e-b5df-cde7c675a1ca': {
      name: 'User.ReadWrite.All',
      source: GRAPH_PERMISSIONS,
    },
    'dbaae8cf-10b5-4b86-a4a1-f871c94c6695': {
      name: 'GroupMember.ReadWrite.All',
      source: GRAPH_PERMISSIONS,
    },
    '332a536c-c7ef-4017-ab91-336970924f0d': { name: 'Sites.Read.All', source: GRAPH_PERMISSIONS },
    'b633e1c5-b582-4048-a93e-9f11b44c7e96': { name: 'Mail.Send', source: GRAPH_PERMISSIONS },
    'e2a3a72e-5f79-4c64-b1b1-878b674786c9': { name: 'Mail.ReadWrite', source: GRAPH_PERMISSIONS },
    // Office 365 Exchange Online application permission IDs
    'dc50a0fb-09a3-484d-be87-e023b12c6440': {
      name: 'Exchange.ManageAsApp',
      source: EXCHANGE_APP_ONLY,
    },
    'dc890d15-9560-4a4c-9b7f-a736ec74ec40': { name: 'full_access_as_app', source: EWS_OAUTH },
    // First-party application IDs and Microsoft's own tenant
    '00000002-0000-0ff1-ce00-000000000000': {
      name: 'Office 365 Exchange Online (application ID)',
      source: EXCHANGE_APP_ONLY,
    },
    '00000003-0000-0ff1-ce00-000000000000': {
      name: 'Office 365 SharePoint Online (application ID)',
      source: SERVICE_PRINCIPALS,
    },
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a': {
      name: 'Microsoft Services tenant (owner of first-party apps)',
      source: FIRST_PARTY,
    },
    // Directory setting templates
    '62375ab9-6b52-47ed-826b-58e47e0e304b': {
      name: 'Group.Unified setting template',
      source: GROUP_SETTINGS,
    },
    '5cf42378-d67d-4f36-ba46-e8b86229381d': {
      name: 'Password Rule Settings template',
      source: GROUP_SETTINGS,
    },
    // Licensing
    'c7df2760-2c81-4ef7-b578-5b5392b571df': {
      name: 'Office 365 E5 (ENTERPRISEPREMIUM) SKU',
      source: LICENSING,
    },
    '41781fb2-bc02-4b7c-bd55-b576c07bb09d': { name: 'AAD_PREMIUM service plan', source: LICENSING },
    // Active Directory Certificate Services
    '0e10c968-78fb-11d2-90d4-00c04f79dc55': {
      name: 'Certificate-Enrollment extended right',
      source: AD_EXTENDED_RIGHTS,
    },
    'a05b8cc2-17bc-4802-a710-e7c15ab866a2': {
      name: 'Certificate-AutoEnrollment extended right',
      source: CERTIFICATE_TEMPLATES,
    },
    'ea1dddc4-60ff-416e-8cc0-17cee534bce7': {
      name: 'ms-PKI-Certificate-Name-Flag attribute',
      source: NAME_FLAG,
    },
    // Group Policy
    '31b2f340-016d-11d2-945f-00c04fb984f9': { name: 'Default Domain Policy', source: DEFAULT_GPOS },
    '6ac1786c-016f-11d2-945f-00c04fb984f9': {
      name: 'Default Domain Controllers Policy',
      source: DEFAULT_GPOS,
    },
    '0cce923c-69ae-11d9-bed3-505054503030': {
      name: 'Audit subcategory GUID',
      source: AUDIT_SUBCATEGORIES,
    },
    '0cce923f-69ae-11d9-bed3-505054503030': {
      name: 'Audit subcategory GUID',
      source: AUDIT_SUBCATEGORIES,
    },
    '3125e937-eb16-4b4c-9934-544fc6d24d26': {
      name: 'Preferences Groups class',
      source: GPP_CLASSES,
    },
    '6d4a79e4-529c-4481-abd0-f5bd7ea93ba7': {
      name: 'Preferences Group class',
      source: GPP_CLASSES,
    },
    'df5f1855-51e5-4d24-8b1a-d9bde98ba1d1': { name: 'Preferences User class', source: GPP_CLASSES },
    'cc63f200-7309-4ba0-b154-a71cd118dbcc': {
      name: 'Preferences ScheduledTasks class',
      source: GPP_CLASSES,
    },
    'd8896631-b747-47a7-84a6-c155337f3bc8': {
      name: 'Preferences TaskV2 class',
      source: GPP_CLASSES,
    },
  };

/** This project's own identifiers and page identifiers inside cited Microsoft URLs. */
export const PROJECT_GUIDS: Readonly<Record<string, string>> = {
  '51822c08-c2b0-4339-b16f-c6ee6ed6fb0b': 'AdminSecOps.Collector module manifest GUID',
  'ad2c23b0-15d8-4340-a468-4d4f3b188f16': 'Part of the Microsoft support URL for KB5014754',
  '211ab1e3-bad6-416d-9d56-8480b42617a4': 'Microsoft Learn page ID in the MS-CRTD URL cited above',
  '77878370-0712-47cd-997d-b07053429f6d': 'Microsoft Learn page ID in the MS-GPAC URL cited above',
  '12512ed6-0632-4e90-a112-d3d2cd41df6c':
    'Microsoft Learn page ID in the MS-GPPREF URL cited above',
};

/** Hand-written fictional values in tests and replay data. */
export const FICTIONAL_TEST_GUIDS: Readonly<Record<string, string>> = {
  '3f2a9c1e-7b4d-4e8a-9c21-5d6e7f8a9b0c': 'Web test sample assessment ID',
  '8c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f': 'Web test follow-up assessment ID',
  '6f1c1a52-4b7e-4f8e-9a51-0c6f7d2b9e10': 'Control-plane test assessment ID',
  '7f1c1a52-4b7e-4f8e-9a51-0c6f7d2b9e10': 'Engine test assessment ID',
  '8f1c1a52-4b7e-4f8e-9a51-0c6f7d2b9e10': 'Engine test assessment ID',
  '4f3a9c21-7b6e-4d2a-9e11-5c0ffee00001': 'Replay-data fictional GPO ID',
};

export function isListedGuid(value: string): boolean {
  const guid = value.toLowerCase();
  return guid in MICROSOFT_PUBLISHED_GUIDS || guid in PROJECT_GUIDS || guid in FICTIONAL_TEST_GUIDS;
}
