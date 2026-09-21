/**
 * Builders for schema-valid Active Directory evidence used by control tests. They
 * produce collector-shaped input that the test inventory validates with the real
 * dataset schemas. The default assessment date of the test inventory is
 * 2026-09-01T12:00:00Z.
 */

export const CONTOSO_SID = 'S-1-5-21-1111111111-2222222222-3333333333';
export const CHILD_SID = 'S-1-5-21-4444444444-5555555555-6666666666';
export const CONTOSO = 'contoso.com';
export const CHILD = 'emea.contoso.com';

/** ISO timestamp `days` days before the default assessment date. */
export function daysAgo(days: number): string {
  return new Date(Date.parse('2026-09-01T12:00:00Z') - days * 86_400_000).toISOString();
}

let rid = 5000;
export const nextSid = (domainSid = CONTOSO_SID): string => {
  rid += 1;
  return `${domainSid}-${rid}`;
};

export interface UserInput {
  domain?: string;
  samAccountName?: string;
  sid?: string;
  enabled?: boolean;
  adminCount?: boolean;
  lastLogonTimestamp?: string | null;
  pwdLastSet?: string | null;
  whenCreated?: string | null;
  passwordNeverExpires?: boolean;
  passwordNotRequired?: boolean;
  doesNotRequirePreAuth?: boolean;
  allowReversiblePasswordEncryption?: boolean;
  accountNotDelegated?: boolean;
  trustedForDelegation?: boolean;
  trustedToAuthForDelegation?: boolean;
  servicePrincipalNameCount?: number;
  memberOfProtectedUsers?: boolean;
}

export function adUser(input: UserInput = {}): Record<string, unknown> {
  const sid = input.sid ?? nextSid();
  return {
    domain: input.domain ?? CONTOSO,
    samAccountName: input.samAccountName ?? `user${sid.split('-').pop() ?? ''}`,
    sid,
    enabled: input.enabled ?? true,
    adminCount: input.adminCount ?? false,
    lastLogonTimestamp: input.lastLogonTimestamp === undefined ? daysAgo(3) : input.lastLogonTimestamp,
    pwdLastSet: input.pwdLastSet === undefined ? daysAgo(30) : input.pwdLastSet,
    whenCreated: input.whenCreated === undefined ? daysAgo(400) : input.whenCreated,
    passwordNeverExpires: input.passwordNeverExpires ?? false,
    passwordNotRequired: input.passwordNotRequired ?? false,
    doesNotRequirePreAuth: input.doesNotRequirePreAuth ?? false,
    allowReversiblePasswordEncryption: input.allowReversiblePasswordEncryption ?? false,
    accountNotDelegated: input.accountNotDelegated ?? false,
    trustedForDelegation: input.trustedForDelegation ?? false,
    trustedToAuthForDelegation: input.trustedToAuthForDelegation ?? false,
    servicePrincipalNameCount: input.servicePrincipalNameCount ?? 0,
    memberOfProtectedUsers: input.memberOfProtectedUsers ?? false,
  };
}

/** ad.users payload. */
export function adUsers(users: Record<string, unknown>[], domains: string[] = [CONTOSO]): Record<string, unknown> {
  return {
    domains: domains.map((d) => ({ domain: d, totalUsers: 100, enabledUsers: 90, protectedUsersGroupSids: [] })),
    users,
  };
}

export interface MemberInput {
  samAccountName: string;
  sid: string;
  objectClass?: string;
}

export function privilegedGroup(
  groupName: string,
  groupSid: string,
  members: MemberInput[],
  domain = CONTOSO,
): Record<string, unknown> {
  return {
    domain,
    groupName,
    groupSid,
    members: members.map((m) => ({ samAccountName: m.samAccountName, sid: m.sid, objectClass: m.objectClass ?? 'user' })),
  };
}

/** Domain Admins group of a domain SID containing the given users (taken from adUser output). */
export function domainAdmins(users: Record<string, unknown>[], domainSid = CONTOSO_SID, domain = CONTOSO): Record<string, unknown> {
  return privilegedGroup(
    'Domain Admins',
    `${domainSid}-512`,
    users.map((u) => ({ samAccountName: u.samAccountName as string, sid: u.sid as string })),
    domain,
  );
}

export interface PolicyInput {
  minPasswordLength?: number;
  reversibleEncryptionEnabled?: boolean;
  lockoutThreshold?: number;
}

function policyFields(input: PolicyInput) {
  return {
    minPasswordLength: input.minPasswordLength ?? 15,
    passwordHistoryCount: 24,
    maxPasswordAgeDays: null,
    complexityEnabled: true,
    reversibleEncryptionEnabled: input.reversibleEncryptionEnabled ?? false,
    lockoutThreshold: input.lockoutThreshold ?? 10,
    lockoutDurationMinutes: 15,
  };
}

export function passwordPolicy(
  domain: string,
  input: PolicyInput = {},
  psos: (PolicyInput & { name: string; appliesToCount?: number })[] = [],
): Record<string, unknown> {
  return {
    domain,
    defaultPolicy: policyFields(input),
    fineGrainedPolicies: psos.map((p, i) => ({ name: p.name, precedence: 10 + i, appliesToCount: p.appliesToCount ?? 1, ...policyFields(p) })),
  };
}

export function adDomain(dnsRoot: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const label = dnsRoot.split('.')[0] ?? dnsRoot;
  return {
    dnsRoot,
    netBIOSName: label.toUpperCase(),
    domainSid: dnsRoot === CHILD ? CHILD_SID : CONTOSO_SID,
    distinguishedName: dnsRoot
      .split('.')
      .map((p) => `DC=${p}`)
      .join(','),
    domainMode: 'Windows2016Domain',
    machineAccountQuota: 0,
    ...overrides,
  };
}

export function adForest(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { name: CONTOSO, forestMode: 'Windows2016Forest', rootDomain: CONTOSO, domains: [CONTOSO], recycleBinEnabled: true, ...overrides };
}

export interface ComputerInput {
  domain?: string;
  name?: string;
  enabled?: boolean;
  operatingSystem?: string | null;
  isDomainController?: boolean;
  trustedForDelegation?: boolean;
  trustedToAuthForDelegation?: boolean;
  lastLogonTimestamp?: string | null;
  legacyLapsExpiration?: string | null;
  windowsLapsExpiration?: string | null;
}

let computerCounter = 0;
export function adComputer(input: ComputerInput = {}): Record<string, unknown> {
  computerCounter += 1;
  const name = input.name ?? `PC${computerCounter.toString().padStart(4, '0')}`;
  const domain = input.domain ?? CONTOSO;
  return {
    domain,
    name,
    dnsHostName: `${name.toLowerCase()}.${domain}`,
    enabled: input.enabled ?? true,
    operatingSystem: input.operatingSystem === undefined ? 'Windows 11 Enterprise' : input.operatingSystem,
    operatingSystemVersion: '10.0 (26100)',
    isDomainController: input.isDomainController ?? false,
    trustedForDelegation: input.trustedForDelegation ?? false,
    trustedToAuthForDelegation: input.trustedToAuthForDelegation ?? false,
    allowedToDelegateToCount: 0,
    lastLogonTimestamp: input.lastLogonTimestamp === undefined ? daysAgo(2) : input.lastLogonTimestamp,
    legacyLapsExpiration: input.legacyLapsExpiration === undefined ? null : input.legacyLapsExpiration,
    windowsLapsExpiration: input.windowsLapsExpiration === undefined ? daysAgo(-20) : input.windowsLapsExpiration,
  };
}

export function domainController(hostName: string, operatingSystem: string | null = 'Windows Server 2022 Datacenter', domain = CONTOSO): Record<string, unknown> {
  return { domain, hostName, site: 'Default-First-Site-Name', operatingSystem, operatingSystemVersion: null, isGlobalCatalog: true, isReadOnly: false };
}

export interface DcSettingInput {
  readStatus?: 'Success' | 'Failed';
  ldapServerIntegrity?: number | null;
  ldapEnforceChannelBinding?: number | null;
  smbRequireSecuritySignature?: number | null;
  smb1Enabled?: number | null;
}

export function dcSetting(hostName: string, input: DcSettingInput = {}): Record<string, unknown> {
  const failed = input.readStatus === 'Failed';
  const pick = (value: number | null | undefined, fallback: number) => (failed ? null : value === undefined ? fallback : value);
  return {
    hostName,
    readStatus: input.readStatus ?? 'Success',
    ldapServerIntegrity: pick(input.ldapServerIntegrity, 2),
    ldapEnforceChannelBinding: pick(input.ldapEnforceChannelBinding, 2),
    smbRequireSecuritySignature: pick(input.smbRequireSecuritySignature, 1),
    smb1Enabled: pick(input.smb1Enabled, 0),
  };
}

export function adTrust(target: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    domain: CONTOSO,
    target,
    direction: 'BiDirectional',
    trustType: 'Uplevel',
    forestTransitive: false,
    intraForest: false,
    sidFilteringQuarantined: true,
    sidFilteringForestAware: false,
    selectiveAuthentication: false,
    tgtDelegation: null,
    ...overrides,
  };
}
