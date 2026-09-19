/**
 * Fictional identities of the Contoso sample organisation, shared by the Entra,
 * Exchange, Azure and Active Directory datasets so the environment is internally
 * consistent. All names, domains and identifiers are fictional.
 */
import { guid } from '../common.js';

export const TENANT_ID = guid('contoso:tenant');
export const INITIAL_DOMAIN = 'contoso.onmicrosoft.com';
export const PRIMARY_DOMAIN = 'contoso.example';
export const MAIL_DOMAIN = 'mail.contoso.example';
export const AD_DOMAIN = 'corp.contoso.example';
export const AD_DOMAIN_DN = 'DC=corp,DC=contoso,DC=example';
export const AD_NETBIOS = 'CONTOSO';
export const DOMAIN_SID = 'S-1-5-21-1111111111-2222222222-3333333333';

export const sid = (rid: number): string => `${DOMAIN_SID}-${rid}`;

/** Microsoft first-party identifiers (public, identical in every tenant). */
export const MICROSOFT_TENANT_ID = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a';
export const GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000';
export const EXCHANGE_APP_ID = '00000002-0000-0ff1-ce00-000000000000';

/** Built-in Microsoft Entra role template IDs used by the fixture. */
export const ROLE = {
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
  securityReader: '5d6b6bb7-de71-4623-b4af-96380a352509',
  reportsReader: '4a5d8f65-41da-4de4-8968-e035b65339cf',
  directorySynchronizationAccounts: 'd29b2b05-8046-44ba-8758-1e26182fcf32',
} as const;

export const ROLE_NAMES: Readonly<Record<string, string>> = {
  [ROLE.globalAdministrator]: 'Global Administrator',
  [ROLE.privilegedRoleAdministrator]: 'Privileged Role Administrator',
  [ROLE.privilegedAuthenticationAdministrator]: 'Privileged Authentication Administrator',
  [ROLE.securityAdministrator]: 'Security Administrator',
  [ROLE.conditionalAccessAdministrator]: 'Conditional Access Administrator',
  [ROLE.exchangeAdministrator]: 'Exchange Administrator',
  [ROLE.sharePointAdministrator]: 'SharePoint Administrator',
  [ROLE.userAdministrator]: 'User Administrator',
  [ROLE.applicationAdministrator]: 'Application Administrator',
  [ROLE.cloudApplicationAdministrator]: 'Cloud Application Administrator',
  [ROLE.hybridIdentityAdministrator]: 'Hybrid Identity Administrator',
  [ROLE.authenticationAdministrator]: 'Authentication Administrator',
  [ROLE.helpdeskAdministrator]: 'Helpdesk Administrator',
  [ROLE.passwordAdministrator]: 'Password Administrator',
  [ROLE.billingAdministrator]: 'Billing Administrator',
  [ROLE.intuneAdministrator]: 'Intune Administrator',
  [ROLE.authenticationPolicyAdministrator]: 'Authentication Policy Administrator',
  [ROLE.globalReader]: 'Global Reader',
  [ROLE.securityReader]: 'Security Reader',
  [ROLE.reportsReader]: 'Reports Reader',
  [ROLE.directorySynchronizationAccounts]: 'Directory Synchronization Accounts',
};

export interface CloudUser {
  key: string;
  id: string;
  displayName: string;
  userPrincipalName: string;
  onPremisesSyncEnabled: boolean;
}

function user(key: string, displayName: string, userPrincipalName: string, synced = false): CloudUser {
  return { key, id: guid(`contoso:user:${key}`), displayName, userPrincipalName, onPremisesSyncEnabled: synced };
}

/** Administrative and notable accounts. */
export const USERS = {
  breakGlass1: user('breakglass01', 'Emergency Access 01', `breakglass01@${INITIAL_DOMAIN}`),
  breakGlass2: user('breakglass02', 'Emergency Access 02', `breakglass02@${INITIAL_DOMAIN}`),
  alexAdmin: user('adm-alex', 'Alex Admin (Admin)', `adm-alex@${PRIMARY_DOMAIN}`),
  taylorOps: user('adm-taylor', 'Taylor Ops (Admin)', `adm-taylor@${PRIMARY_DOMAIN}`),
  /** Everyday account synchronised from Active Directory that also holds Global Administrator. */
  jordanIt: user('jordan.it', 'Jordan IT', `jordan.it@${PRIMARY_DOMAIN}`, true),
  caseyExec: user('adm-casey', 'Casey Exec (Admin)', `adm-casey@${PRIMARY_DOMAIN}`),
  samSecurity: user('adm-sam', 'Sam Security (Admin)', `adm-sam@${PRIMARY_DOMAIN}`),
  /** Exchange administrator who never registered an MFA method. */
  rileyMail: user('adm-riley', 'Riley Mail (Admin)', `adm-riley@${PRIMARY_DOMAIN}`),
  quinnSites: user('adm-quinn', 'Quinn Sites (Admin)', `adm-quinn@${PRIMARY_DOMAIN}`),
  jamieApps: user('adm-jamie', 'Jamie Apps (Admin)', `adm-jamie@${PRIMARY_DOMAIN}`),
  morganDevices: user('adm-morgan', 'Morgan Devices (Admin)', `adm-morgan@${PRIMARY_DOMAIN}`),
  averyHelpdesk: user('hd-avery', 'Avery Helpdesk', `hd-avery@${PRIMARY_DOMAIN}`, true),
  drewHelpdesk: user('hd-drew', 'Drew Helpdesk', `hd-drew@${PRIMARY_DOMAIN}`, true),
  patAuditor: user('pat.auditor', 'Pat Auditor', `pat.auditor@${PRIMARY_DOMAIN}`, true),
  syncAccount: user(
    'sync',
    'On-Premises Directory Synchronization Service Account',
    `Sync_AADC01_4f2a9c1e7b3d@${INITIAL_DOMAIN}`,
  ),
  /** Sales user whose mailbox forwards to a personal address. */
  robinSales: user('robin.sales', 'Robin Sales', `robin.sales@${PRIMARY_DOMAIN}`, true),
} as const;

export type UserKey = keyof typeof USERS;

/** Security groups referenced by policies. */
export const GROUPS = {
  breakGlass: { id: guid('contoso:group:breakglass'), displayName: 'SG-Emergency-Access-Accounts' },
  deviceCompliancePilot: { id: guid('contoso:group:device-pilot'), displayName: 'SG-Device-Compliance-Pilot' },
  tapUsers: { id: guid('contoso:group:tap'), displayName: 'SG-Temporary-Access-Pass' },
  allWindowsDevices: { id: guid('contoso:group:windows-devices'), displayName: 'DG-All-Windows-Devices' },
  azureReaders: { id: guid('contoso:group:azure-readers'), displayName: 'SG-Azure-Readers' },
} as const;

const FIRST_NAMES = [
  'Alex', 'Taylor', 'Jordan', 'Morgan', 'Casey', 'Riley', 'Jamie', 'Avery', 'Quinn', 'Drew',
  'Robin', 'Sam', 'Pat', 'Charlie', 'Frankie', 'Jesse', 'Kai', 'Lee', 'Parker', 'Reese',
] as const;
const LAST_NAMES = [
  'Adams', 'Baker', 'Clark', 'Davis', 'Evans', 'Foster', 'Garcia', 'Hughes', 'Irwin', 'Jones',
  'King', 'Lopez', 'Miller', 'Nash', 'Owens', 'Price', 'Quinn', 'Reed', 'Scott', 'Turner',
  'Usher', 'Vance', 'Walker', 'Young', 'Zimmer',
] as const;

export interface StaffUser {
  index: number;
  id: string;
  displayName: string;
  userPrincipalName: string;
}

/** 480 fictional synchronised staff accounts (20 x 24 name combinations). */
export function staffUsers(): StaffUser[] {
  const users: StaffUser[] = [];
  let index = 0;
  for (const last of LAST_NAMES.slice(0, 24)) {
    for (const first of FIRST_NAMES) {
      index += 1;
      users.push({
        index,
        id: guid(`contoso:staff:${index}`),
        displayName: `${first} ${last}`,
        userPrincipalName: `${first.toLowerCase()}.${last.toLowerCase()}@${PRIMARY_DOMAIN}`,
      });
    }
  }
  return users;
}
