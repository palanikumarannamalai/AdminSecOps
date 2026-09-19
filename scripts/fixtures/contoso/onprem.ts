/**
 * Contoso - Active Directory, AD CS, Group Policy and Windows host datasets.
 *
 * Intended state: minimum password length 8 and no account lockout; KRBTGT password
 * 400 days old; one account without Kerberos pre-authentication; a Domain Admin
 * service account with an SPN plus a non-privileged SPN service account; a server
 * trusted for unconstrained delegation; MachineAccountQuota 10; recycle bin enabled;
 * domain/forest functional level 2016; ~60% Windows LAPS coverage; a Windows Server
 * 2012 R2 member server; DCs on 2019 and 2022; domain controller settings not
 * collected; an external trust without SID filtering (quarantine); an ESC1-vulnerable
 * certificate template; a GPP cpassword artifact (path only); an unlinked GPO; a GPO
 * setting LmCompatibilityLevel 3; one member server with several host weaknesses.
 */
import {
  type adComputers,
  type adDomainControllers,
  type adDomains,
  type adForest,
  type adKrbtgt,
  type adPasswordPolicies,
  type adPrivilegedGroups,
  type adTrusts,
  type adUsers,
  type adcsCertificateAuthorities,
  type adcsCertificateTemplates,
  type gpoGroupPolicyObjects,
  type gpoSysvolPasswordArtifacts,
  type windowsHosts,
} from '@adminsecops/schemas';
import type { z } from 'zod';
import { type Clock, guid } from '../common.js';
import { AUTOENROLL, DomainPrincipals, ENROLL, OID, ace, adminAcl, builtInTemplates, hardenedServer } from '../onprem.js';
import { AD_DOMAIN, AD_DOMAIN_DN, AD_NETBIOS, DOMAIN_SID, sid } from './identity.js';

type In<D extends { schema: z.ZodType }> = z.input<D['schema']>;
type AdUser = NonNullable<In<typeof adUsers>['users']>[number];
type Computer = In<typeof adComputers>[number];
type Template = In<typeof adcsCertificateTemplates>[number];
type Gpo = In<typeof gpoGroupPolicyObjects>[number];

export interface ContosoOnPremData {
  forest: In<typeof adForest>;
  domains: In<typeof adDomains>;
  passwordPolicies: In<typeof adPasswordPolicies>;
  privilegedGroups: In<typeof adPrivilegedGroups>;
  users: In<typeof adUsers> & { users: AdUser[] };
  krbtgt: In<typeof adKrbtgt>;
  computers: Computer[];
  trusts: In<typeof adTrusts>;
  domainControllers: In<typeof adDomainControllers>;
  certificateAuthorities: In<typeof adcsCertificateAuthorities>;
  certificateTemplates: Template[];
  groupPolicyObjects: Gpo[];
  sysvolPasswordArtifacts: In<typeof gpoSysvolPasswordArtifacts>;
  windowsHosts: z.input<(typeof windowsHosts)['schema']>;
}

export const PRINCIPALS = new DomainPrincipals(AD_NETBIOS, DOMAIN_SID);
export const ESC1_TEMPLATE = 'ContosoWebClientLegacy';
export const GPO = {
  defaultDomain: '31b2f340-016d-11d2-945f-00c04fb984f9',
  defaultDomainControllers: '6ac1786c-016f-11d2-945f-00c04fb984f9',
  workstationBaseline: guid('contoso:gpo:workstation-baseline'),
  serverBaseline: guid('contoso:gpo:server-baseline'),
  localAdmins: guid('contoso:gpo:local-admins'),
  oldTest: guid('contoso:gpo:old-test'),
  powershellLogging: guid('contoso:gpo:powershell-logging'),
} as const;

const DOMAIN_ROOT = AD_DOMAIN_DN;
const OU = {
  workstations: `OU=Workstations,OU=Contoso,${AD_DOMAIN_DN}`,
  servers: `OU=Servers,OU=Contoso,${AD_DOMAIN_DN}`,
  domainControllers: `OU=Domain Controllers,${AD_DOMAIN_DN}`,
  pilot: `OU=Pilot,OU=Workstations,OU=Contoso,${AD_DOMAIN_DN}`,
} as const;

function adUser(samAccountName: string, rid: number, overrides: Partial<AdUser>): AdUser {
  return {
    domain: AD_DOMAIN,
    samAccountName,
    sid: sid(rid),
    enabled: true,
    adminCount: false,
    lastLogonTimestamp: null,
    pwdLastSet: null,
    whenCreated: null,
    passwordNeverExpires: false,
    passwordNotRequired: false,
    doesNotRequirePreAuth: false,
    allowReversiblePasswordEncryption: false,
    accountNotDelegated: false,
    trustedForDelegation: false,
    trustedToAuthForDelegation: false,
    servicePrincipalNameCount: 0,
    memberOfProtectedUsers: false,
    ...overrides,
  };
}

const LAPS_WORKSTATIONS = 26;
const WORKSTATIONS = 41;

function computers(clock: Clock): Computer[] {
  const host = (name: string, os: string, osVersion: string, overrides: Partial<Computer> = {}): Computer => ({
    domain: AD_DOMAIN,
    name,
    dnsHostName: `${name}.${AD_DOMAIN}`,
    enabled: true,
    operatingSystem: os,
    operatingSystemVersion: osVersion,
    isDomainController: false,
    trustedForDelegation: false,
    trustedToAuthForDelegation: false,
    allowedToDelegateToCount: 0,
    lastLogonTimestamp: clock.ago(2, 3),
    legacyLapsExpiration: null,
    windowsLapsExpiration: null,
    ...overrides,
  });
  const ws2019 = ['Windows Server 2019 Datacenter', '10.0 (17763)'] as const;
  const ws2022 = ['Windows Server 2022 Standard', '10.0 (20348)'] as const;
  const legacyLaps = { legacyLapsExpiration: clock.ahead(21) };
  const result: Computer[] = [
    host('DC01', ...ws2019, { isDomainController: true, trustedForDelegation: true, lastLogonTimestamp: clock.ago(1) }),
    host('DC02', ws2022[0].replace('Standard', 'Datacenter'), ws2022[1], { isDomainController: true, trustedForDelegation: true, lastLogonTimestamp: clock.ago(1) }),
    host('APP01', ...ws2022, legacyLaps),
    host('SQL01', ...ws2019, legacyLaps),
    host('WEB01', ...ws2022, { ...legacyLaps, trustedToAuthForDelegation: false, allowedToDelegateToCount: 2 }),
    host('FS01', 'Windows Server 2016 Standard', '10.0 (14393)', legacyLaps),
    host('PRINT01', 'Windows Server 2016 Standard', '10.0 (14393)', { trustedForDelegation: true }),
    host('LEGACY01', 'Windows Server 2012 R2 Standard', '6.3 (9600)', { lastLogonTimestamp: clock.ago(5, 1) }),
    host('AADC01', ...ws2019),
    host('CA01', ...ws2019),
  ];
  for (let i = 1; i <= WORKSTATIONS; i += 1) {
    const name = `WS-${String(i).padStart(4, '0')}`;
    const stale = i === 38 || i === 41;
    result.push(
      host(name, 'Windows 11 Enterprise', i % 7 === 0 ? '10.0 (22621)' : '10.0 (22631)', {
        enabled: i !== 41,
        lastLogonTimestamp: stale ? clock.ago(143 + i) : clock.ago(i % 9, i % 5),
        windowsLapsExpiration: i <= LAPS_WORKSTATIONS ? clock.ahead(30 - (i % 20)) : null,
      }),
    );
  }
  return result;
}

function certificateTemplates(): Template[] {
  const p = PRINCIPALS;
  return [
    ...builtInTemplates(p),
    {
      // ESC1: enrollee supplies subject + client authentication + Domain Users may enroll + no approval.
      name: ESC1_TEMPLATE,
      displayName: 'Contoso Web Client (Legacy)',
      schemaVersion: 2,
      certificateNameFlag: 1,
      enrollmentFlag: 0,
      raSignature: 0,
      extendedKeyUsage: [OID.serverAuthentication, OID.clientAuthentication],
      applicationPolicies: [OID.serverAuthentication, OID.clientAuthentication],
      permissions: [...adminAcl(p), ace(p.domainUsers, ['ExtendedRight'], ENROLL)],
    },
    {
      name: 'ContosoVPNUser',
      displayName: 'Contoso VPN User',
      schemaVersion: 2,
      certificateNameFlag: -2113929216, // 0x82000000: subject and UPN from AD
      enrollmentFlag: 41,
      raSignature: 0,
      extendedKeyUsage: [OID.clientAuthentication],
      applicationPolicies: [OID.clientAuthentication],
      permissions: [...adminAcl(p), ace(p.domainUsers, ['ExtendedRight'], ENROLL), ace(p.domainUsers, ['ExtendedRight'], AUTOENROLL)],
    },
  ];
}

function gpos(): Gpo[] {
  const link = (somPath: string, enabled = true, enforced = false) => ({ somPath, enabled, enforced });
  const computer = (category: string, name: string, value: string | number | boolean | string[]) => ({ scope: 'Computer', category, name, value });
  return [
    {
      id: GPO.defaultDomain,
      displayName: 'Default Domain Policy',
      domain: AD_DOMAIN,
      gpoStatus: 'AllSettingsEnabled',
      createdTime: '2016-05-11T09:14:02Z',
      modifiedTime: '2023-02-06T15:40:18Z',
      wmiFilter: null,
      links: [link(DOMAIN_ROOT)],
      settings: [
        computer('AccountPolicy', 'MinimumPasswordLength', 8),
        computer('AccountPolicy', 'PasswordComplexity', true),
        computer('AccountPolicy', 'PasswordHistorySize', 24),
        computer('AccountPolicy', 'MaximumPasswordAge', 90),
        computer('AccountPolicy', 'LockoutBadCount', 0),
        computer('AccountPolicy', 'ClearTextPassword', false),
      ],
    },
    {
      id: GPO.defaultDomainControllers,
      displayName: 'Default Domain Controllers Policy',
      domain: AD_DOMAIN,
      gpoStatus: 'AllSettingsEnabled',
      createdTime: '2016-05-11T09:14:02Z',
      modifiedTime: '2024-10-01T12:03:45Z',
      wmiFilter: null,
      links: [link(OU.domainControllers)],
      settings: [
        computer('UserRightsAssignment', 'SeDebugPrivilege', ['BUILTIN\\Administrators']),
        computer('UserRightsAssignment', 'SeRemoteInteractiveLogonRight', ['BUILTIN\\Administrators']),
        computer('AuditPolicy', 'Audit Credential Validation', 'Success and Failure'),
        computer('AuditPolicy', 'Audit Security Group Management', 'Success'),
        computer('AuditPolicy', 'Audit Directory Service Changes', 'No Auditing'),
        computer('SecurityOptions', 'MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity', 1),
      ],
    },
    {
      id: GPO.workstationBaseline,
      displayName: 'CONTOSO - Workstation Baseline',
      domain: AD_DOMAIN,
      gpoStatus: 'UserSettingsDisabled',
      createdTime: '2021-03-22T10:31:57Z',
      modifiedTime: '2025-11-19T08:12:30Z',
      wmiFilter: null,
      links: [link(OU.workstations)],
      settings: [
        computer('SecurityOptions', 'MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel', 5),
        computer('SecurityOptions', 'MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous', 1),
        computer('RegistryPolicy', 'Turn on PowerShell Script Block Logging', 'Enabled'),
        computer('RegistryPolicy', 'Windows Defender Firewall: Protect all network connections', 'Enabled'),
        computer('RegistryValue', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential', 0),
      ],
    },
    {
      id: GPO.serverBaseline,
      displayName: 'CONTOSO - Server Baseline',
      domain: AD_DOMAIN,
      gpoStatus: 'UserSettingsDisabled',
      createdTime: '2019-07-08T13:05:41Z',
      modifiedTime: '2022-04-27T17:22:09Z',
      wmiFilter: null,
      links: [link(OU.servers)],
      settings: [
        // Kept at 3 for an old line-of-business application: LM responses refused only from level 5.
        computer('SecurityOptions', 'MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel', 3),
        computer('SecurityOptions', 'MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature', 0),
        computer('UserRightsAssignment', 'SeRemoteInteractiveLogonRight', ['BUILTIN\\Administrators', 'BUILTIN\\Remote Desktop Users']),
      ],
    },
    {
      id: GPO.localAdmins,
      displayName: 'CONTOSO - Local Administrators (Legacy GPP)',
      domain: AD_DOMAIN,
      gpoStatus: 'UserSettingsDisabled',
      createdTime: '2014-10-02T11:48:20Z',
      modifiedTime: '2014-10-02T11:52:07Z',
      wmiFilter: null,
      links: [link(OU.workstations)],
      settings: [computer('Other', 'Preferences: Local Users and Groups', 'Configured')],
    },
    {
      id: GPO.oldTest,
      displayName: 'Old - Test Policy (do not use)',
      domain: AD_DOMAIN,
      gpoStatus: 'AllSettingsEnabled',
      createdTime: '2018-01-15T16:20:44Z',
      modifiedTime: '2018-01-15T16:27:31Z',
      wmiFilter: null,
      links: [],
      settings: [computer('RegistryPolicy', 'Turn off Windows Defender Antivirus', 'Enabled')],
    },
    {
      id: GPO.powershellLogging,
      displayName: 'CONTOSO - PowerShell Logging (Pilot)',
      domain: AD_DOMAIN,
      gpoStatus: 'UserSettingsDisabled',
      createdTime: '2026-04-02T09:00:12Z',
      modifiedTime: '2026-04-02T09:07:40Z',
      wmiFilter: 'Windows 11 only',
      links: [link(OU.pilot, true, false)],
      settings: [
        computer('RegistryPolicy', 'Turn on PowerShell Script Block Logging', 'Enabled'),
        computer('RegistryPolicy', 'Turn on Module Logging', 'Enabled'),
      ],
    },
  ];
}

export const KRBTGT_PWD_LAST_SET = '2025-07-06T09:12:44Z';

export function contosoOnPrem(clock: Clock): ContosoOnPremData {
  const member = (samAccountName: string, rid: number, objectClass = 'user') => ({ samAccountName, sid: sid(rid), objectClass });
  const domainAdmins = [member('Administrator', 500), member('adm-alex', 1104), member('adm-taylor', 1105), member('svc-backup', 1311)];

  return {
    forest: {
      name: AD_DOMAIN,
      forestMode: 'Windows2016Forest',
      rootDomain: AD_DOMAIN,
      domains: [AD_DOMAIN],
      recycleBinEnabled: true,
    },
    domains: [
      {
        dnsRoot: AD_DOMAIN,
        netBIOSName: AD_NETBIOS,
        domainSid: DOMAIN_SID,
        distinguishedName: AD_DOMAIN_DN,
        domainMode: 'Windows2016Domain',
        machineAccountQuota: 10,
      },
    ],
    passwordPolicies: [
      {
        domain: AD_DOMAIN,
        defaultPolicy: {
          minPasswordLength: 8,
          passwordHistoryCount: 24,
          maxPasswordAgeDays: 90,
          complexityEnabled: true,
          reversibleEncryptionEnabled: false,
          lockoutThreshold: 0,
          lockoutDurationMinutes: 10,
        },
        fineGrainedPolicies: [
          {
            name: 'PSO-Tier0-Admins',
            precedence: 10,
            appliesToCount: 1,
            minPasswordLength: 15,
            passwordHistoryCount: 24,
            maxPasswordAgeDays: 180,
            complexityEnabled: true,
            reversibleEncryptionEnabled: false,
            lockoutThreshold: 5,
            lockoutDurationMinutes: 30,
          },
        ],
      },
    ],
    privilegedGroups: [
      { domain: AD_DOMAIN, groupName: 'Domain Admins', groupSid: sid(512), members: domainAdmins },
      { domain: AD_DOMAIN, groupName: 'Schema Admins', groupSid: sid(518), members: [member('Administrator', 500)] },
      { domain: AD_DOMAIN, groupName: 'Enterprise Admins', groupSid: sid(519), members: [member('Administrator', 500), member('adm-alex', 1104)] },
      { domain: AD_DOMAIN, groupName: 'Key Admins', groupSid: sid(526), members: [] },
      { domain: AD_DOMAIN, groupName: 'Enterprise Key Admins', groupSid: sid(527), members: [] },
      { domain: AD_DOMAIN, groupName: 'Administrators', groupSid: 'S-1-5-32-544', members: domainAdmins },
      { domain: AD_DOMAIN, groupName: 'Account Operators', groupSid: 'S-1-5-32-548', members: [member('hd-avery', 1210)] },
      { domain: AD_DOMAIN, groupName: 'Server Operators', groupSid: 'S-1-5-32-549', members: [] },
      { domain: AD_DOMAIN, groupName: 'Print Operators', groupSid: 'S-1-5-32-550', members: [] },
      { domain: AD_DOMAIN, groupName: 'Backup Operators', groupSid: 'S-1-5-32-551', members: [member('svc-backup', 1311)] },
    ],
    users: {
      domains: [{ domain: AD_DOMAIN, totalUsers: 612, enabledUsers: 548, protectedUsersGroupSids: [sid(525)] }],
      users: [
        adUser('Administrator', 500, {
          adminCount: true,
          lastLogonTimestamp: clock.ago(97),
          pwdLastSet: '2022-01-10T08:30:00Z',
          whenCreated: '2016-05-11T09:02:13Z',
          passwordNeverExpires: true,
        }),
        adUser('adm-alex', 1104, {
          adminCount: true,
          lastLogonTimestamp: clock.ago(1, 2),
          pwdLastSet: '2026-03-02T07:45:00Z',
          whenCreated: '2019-02-04T10:00:00Z',
          accountNotDelegated: true,
          memberOfProtectedUsers: true,
        }),
        adUser('adm-taylor', 1105, {
          adminCount: true,
          lastLogonTimestamp: clock.ago(4),
          pwdLastSet: '2025-12-15T12:10:00Z',
          whenCreated: '2019-02-04T10:05:00Z',
        }),
        adUser('svc-backup', 1311, {
          // Domain Admin service account with an SPN (Kerberoastable privileged account).
          adminCount: true,
          lastLogonTimestamp: clock.ago(0, 5),
          pwdLastSet: '2018-06-21T14:02:00Z',
          whenCreated: '2018-06-21T14:00:00Z',
          passwordNeverExpires: true,
          servicePrincipalNameCount: 1,
        }),
        adUser('svc-sql', 1320, {
          lastLogonTimestamp: clock.ago(0, 9),
          pwdLastSet: '2020-09-14T09:30:00Z',
          whenCreated: '2020-09-14T09:25:00Z',
          passwordNeverExpires: true,
          servicePrincipalNameCount: 2,
        }),
        adUser('svc-legacyapp', 1402, {
          // Kerberos pre-authentication disabled (AS-REP roastable).
          lastLogonTimestamp: clock.ago(6),
          pwdLastSet: '2017-11-03T16:45:00Z',
          whenCreated: '2017-11-03T16:40:00Z',
          passwordNeverExpires: true,
          doesNotRequirePreAuth: true,
        }),
        adUser('hd-avery', 1210, {
          adminCount: true,
          lastLogonTimestamp: clock.ago(0, 20),
          pwdLastSet: '2026-05-20T08:00:00Z',
          whenCreated: '2021-04-12T09:00:00Z',
        }),
        adUser('j.former', 1188, {
          // Former administrator: adminCount still set after removal from Domain Admins.
          enabled: false,
          adminCount: true,
          lastLogonTimestamp: '2024-02-29T17:05:00Z',
          pwdLastSet: '2023-10-01T09:00:00Z',
          whenCreated: '2019-08-19T09:00:00Z',
        }),
        adUser('MSOL_4f2a9c1e7b3d', 1250, {
          lastLogonTimestamp: clock.ago(0, 1),
          pwdLastSet: '2022-05-16T18:20:00Z',
          whenCreated: '2022-05-16T18:20:00Z',
          passwordNeverExpires: true,
        }),
      ],
    },
    krbtgt: [{ domain: AD_DOMAIN, pwdLastSet: KRBTGT_PWD_LAST_SET }],
    computers: computers(clock),
    trusts: [
      {
        domain: AD_DOMAIN,
        target: 'legacy.northwind.example',
        direction: 'BiDirectional',
        trustType: 'Uplevel',
        forestTransitive: false,
        intraForest: false,
        sidFilteringQuarantined: false,
        sidFilteringForestAware: false,
        selectiveAuthentication: false,
        tgtDelegation: false,
      },
    ],
    domainControllers: [
      {
        domain: AD_DOMAIN,
        hostName: `DC01.${AD_DOMAIN}`,
        site: 'HQ-Site',
        operatingSystem: 'Windows Server 2019 Datacenter',
        operatingSystemVersion: '10.0 (17763)',
        isGlobalCatalog: true,
        isReadOnly: false,
      },
      {
        domain: AD_DOMAIN,
        hostName: `DC02.${AD_DOMAIN}`,
        site: 'HQ-Site',
        operatingSystem: 'Windows Server 2022 Datacenter',
        operatingSystemVersion: '10.0 (20348)',
        isGlobalCatalog: true,
        isReadOnly: false,
      },
    ],
    certificateAuthorities: [
      {
        name: 'Contoso Issuing CA 01',
        dnsHostName: `CA01.${AD_DOMAIN}`,
        certificateTemplates: ['User', 'Machine', 'DomainController', 'WebServer', ESC1_TEMPLATE, 'ContosoVPNUser'],
        caCertificateNotAfter: '2029-04-30T12:00:00Z',
      },
    ],
    certificateTemplates: certificateTemplates(),
    groupPolicyObjects: gpos(),
    sysvolPasswordArtifacts: {
      filesScanned: 43,
      artifacts: [
        {
          domain: AD_DOMAIN,
          gpoId: GPO.localAdmins,
          relativePath: `{${GPO.localAdmins.toUpperCase()}}/Machine/Preferences/Groups/Groups.xml`,
          fileName: 'Groups.xml',
        },
      ],
    },
    windowsHosts: [
      hardenedServer(`APP01.${AD_DOMAIN}`, {
        firewallProfiles: [
          { name: 'Domain', enabled: false, defaultInboundAction: 'Block' },
          { name: 'Private', enabled: true, defaultInboundAction: 'Block' },
          { name: 'Public', enabled: true, defaultInboundAction: 'Block' },
        ],
        smb: { smb1ServerEnabled: false, serverRequireSecuritySignature: false },
        rdp: { enabled: true, nlaRequired: true },
        lsa: { runAsPPL: null, lmCompatibilityLevel: 3, wdigestUseLogonCredential: null },
        credentialGuard: { running: false, vbsStatus: 0 },
        powershell: { scriptBlockLoggingEnabled: false },
        defender: {
          available: true,
          antivirusEnabled: true,
          realTimeProtectionEnabled: true,
          isTamperProtected: true,
          antivirusSignatureAgeDays: 1,
        },
      }),
    ],
  };
}
