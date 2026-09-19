/**
 * Fabrikam sample environment: a small on-premises-only organisation (AD, AD CS,
 * Group Policy and Windows modules; the Entra, Microsoft 365 and Azure modules were
 * not run). Mostly well configured, with two intentional issues: a certificate
 * template whose ACL lets Authenticated Users modify it (ESC4) and SMBv1 enabled on
 * a file server.
 */
import {
  adComputers,
  adDomainControllerSettings,
  adDomainControllers,
  adDomains,
  adForest,
  adKrbtgt,
  adPasswordPolicies,
  adPrivilegedGroups,
  adTrusts,
  adUsers,
  adcsCertificateAuthorities,
  adcsCertificateTemplates,
  gpoGroupPolicyObjects,
  gpoSysvolPasswordArtifacts,
  windowsHosts,
} from '@adminsecops/schemas';
import type { z } from 'zod';
import { Clock, type EnvironmentFixture, collected, guid } from './common.js';
import { DomainPrincipals, ENROLL, AUTOENROLL, OID, ace, adminAcl, builtInTemplates, hardenedServer } from './onprem.js';

type In<D extends { schema: z.ZodType }> = z.input<D['schema']>;
type AdUser = NonNullable<In<typeof adUsers>['users']>[number];
type Computer = In<typeof adComputers>[number];

export const FABRIKAM_ASSESSMENT_ID = guid('fabrikam:assessment:2026-09');
const DOMAIN = 'corp.fabrikam.example';
const DOMAIN_DN = 'DC=corp,DC=fabrikam,DC=example';
const NETBIOS = 'FABRIKAM';
const DOMAIN_SID = 'S-1-5-21-4444444444-5555555555-6666666666';
const sid = (rid: number) => `${DOMAIN_SID}-${rid}`;
export const ESC4_TEMPLATE = 'FabrikamWorkstationAuth';

function adUser(samAccountName: string, rid: number, overrides: Partial<AdUser>): AdUser {
  return {
    domain: DOMAIN,
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

export function fabrikamEnvironment(): EnvironmentFixture {
  const clock = Clock.of('2026-09-05T14:20:00Z');
  const p = new DomainPrincipals(NETBIOS, DOMAIN_SID);
  const member = (samAccountName: string, rid: number) => ({ samAccountName, sid: sid(rid), objectClass: 'user' });
  const admins = [member('adm-lee', 1103)];

  const computer = (name: string, os: string, version: string, overrides: Partial<Computer> = {}): Computer => ({
    domain: DOMAIN,
    name,
    dnsHostName: `${name}.${DOMAIN}`,
    enabled: true,
    operatingSystem: os,
    operatingSystemVersion: version,
    isDomainController: false,
    trustedForDelegation: false,
    trustedToAuthForDelegation: false,
    allowedToDelegateToCount: 0,
    lastLogonTimestamp: clock.ago(1, 4),
    legacyLapsExpiration: null,
    windowsLapsExpiration: clock.ahead(25),
    ...overrides,
  });
  const computers: Computer[] = [
    computer('FAB-DC01', 'Windows Server 2022 Datacenter', '10.0 (20348)', {
      isDomainController: true,
      trustedForDelegation: true,
      windowsLapsExpiration: null,
    }),
    computer('FAB-FS01', 'Windows Server 2019 Standard', '10.0 (17763)'),
    computer('FAB-APP01', 'Windows Server 2022 Standard', '10.0 (20348)'),
  ];
  for (let i = 1; i <= 12; i += 1) {
    computers.push(computer(`FAB-WS-${String(i).padStart(3, '0')}`, 'Windows 11 Pro', '10.0 (22631)', { lastLogonTimestamp: clock.ago(i % 6) }));
  }

  const link = (somPath: string) => ({ somPath, enabled: true, enforced: false });
  const setting = (category: string, name: string, value: string | number | boolean | string[]) => ({ scope: 'Computer', category, name, value });

  const datasets = [
    collected(adForest, { name: DOMAIN, forestMode: 'Windows2016Forest', rootDomain: DOMAIN, domains: [DOMAIN], recycleBinEnabled: true }),
    collected(adDomains, [
      { dnsRoot: DOMAIN, netBIOSName: NETBIOS, domainSid: DOMAIN_SID, distinguishedName: DOMAIN_DN, domainMode: 'Windows2016Domain', machineAccountQuota: 0 },
    ]),
    collected(adPasswordPolicies, [
      {
        domain: DOMAIN,
        defaultPolicy: {
          minPasswordLength: 14,
          passwordHistoryCount: 24,
          maxPasswordAgeDays: null,
          complexityEnabled: true,
          reversibleEncryptionEnabled: false,
          lockoutThreshold: 10,
          lockoutDurationMinutes: 15,
        },
        fineGrainedPolicies: [],
      },
    ]),
    collected(adPrivilegedGroups, [
      { domain: DOMAIN, groupName: 'Domain Admins', groupSid: sid(512), members: admins },
      { domain: DOMAIN, groupName: 'Schema Admins', groupSid: sid(518), members: [] },
      { domain: DOMAIN, groupName: 'Enterprise Admins', groupSid: sid(519), members: [] },
      { domain: DOMAIN, groupName: 'Key Admins', groupSid: sid(526), members: [] },
      { domain: DOMAIN, groupName: 'Enterprise Key Admins', groupSid: sid(527), members: [] },
      { domain: DOMAIN, groupName: 'Administrators', groupSid: 'S-1-5-32-544', members: [member('Administrator', 500), ...admins] },
      { domain: DOMAIN, groupName: 'Account Operators', groupSid: 'S-1-5-32-548', members: [] },
      { domain: DOMAIN, groupName: 'Server Operators', groupSid: 'S-1-5-32-549', members: [] },
      { domain: DOMAIN, groupName: 'Print Operators', groupSid: 'S-1-5-32-550', members: [] },
      { domain: DOMAIN, groupName: 'Backup Operators', groupSid: 'S-1-5-32-551', members: [] },
    ]),
    collected(adUsers, {
      domains: [{ domain: DOMAIN, totalUsers: 64, enabledUsers: 58, protectedUsersGroupSids: [sid(525)] }],
      users: [
        adUser('Administrator', 500, {
          enabled: false,
          adminCount: true,
          lastLogonTimestamp: '2025-02-11T10:00:00Z',
          pwdLastSet: '2025-02-11T09:55:00Z',
          whenCreated: '2021-06-01T08:00:00Z',
          accountNotDelegated: true,
        }),
        adUser('adm-lee', 1103, {
          adminCount: true,
          lastLogonTimestamp: clock.ago(0, 3),
          pwdLastSet: '2026-06-30T08:15:00Z',
          whenCreated: '2021-06-01T08:30:00Z',
          accountNotDelegated: true,
          memberOfProtectedUsers: true,
        }),
        adUser('svc-fab-web', 1140, {
          lastLogonTimestamp: clock.ago(0, 12),
          pwdLastSet: '2026-05-04T11:00:00Z',
          whenCreated: '2022-03-14T13:00:00Z',
          servicePrincipalNameCount: 1,
        }),
      ],
    }),
    collected(adKrbtgt, [{ domain: DOMAIN, pwdLastSet: clock.ago(92, 5) }]),
    collected(adComputers, computers),
    collected(adTrusts, []),
    collected(adDomainControllers, [
      {
        domain: DOMAIN,
        hostName: `FAB-DC01.${DOMAIN}`,
        site: 'Default-First-Site-Name',
        operatingSystem: 'Windows Server 2022 Datacenter',
        operatingSystemVersion: '10.0 (20348)',
        isGlobalCatalog: true,
        isReadOnly: false,
      },
    ]),
    collected(adDomainControllerSettings, [
      {
        hostName: `FAB-DC01.${DOMAIN}`,
        readStatus: 'Success',
        ldapServerIntegrity: 2,
        ldapEnforceChannelBinding: 2,
        smbRequireSecuritySignature: 1,
        smb1Enabled: 0,
      },
    ]),
    collected(adcsCertificateAuthorities, [
      {
        name: 'Fabrikam Issuing CA',
        dnsHostName: `FAB-APP01.${DOMAIN}`,
        certificateTemplates: ['User', 'Machine', 'DomainController', ESC4_TEMPLATE],
        caCertificateNotAfter: '2031-01-15T00:00:00Z',
      },
    ]),
    collected(adcsCertificateTemplates, [
      ...builtInTemplates(p).filter((t) => t.name !== 'WebServer' && t.name !== 'SubCA'),
      {
        // ESC4: Authenticated Users can modify the template (write properties and its DACL).
        name: ESC4_TEMPLATE,
        displayName: 'Fabrikam Workstation Authentication',
        schemaVersion: 2,
        certificateNameFlag: 134217728, // 0x08000000: DNS name from AD
        enrollmentFlag: 32,
        raSignature: 0,
        extendedKeyUsage: [OID.clientAuthentication],
        applicationPolicies: [OID.clientAuthentication],
        permissions: [
          ...adminAcl(p),
          ace(p.authenticatedUsers, ['WriteProperty', 'WriteDacl']),
          ace(p.domainComputers, ['ExtendedRight'], ENROLL),
          ace(p.domainComputers, ['ExtendedRight'], AUTOENROLL),
        ],
      },
    ]),
    collected(gpoGroupPolicyObjects, [
      {
        id: '31b2f340-016d-11d2-945f-00c04fb984f9',
        displayName: 'Default Domain Policy',
        domain: DOMAIN,
        gpoStatus: 'AllSettingsEnabled',
        createdTime: '2021-06-01T08:00:00Z',
        modifiedTime: '2025-01-13T10:30:00Z',
        wmiFilter: null,
        links: [link(DOMAIN_DN)],
        settings: [
          setting('AccountPolicy', 'MinimumPasswordLength', 14),
          setting('AccountPolicy', 'PasswordComplexity', true),
          setting('AccountPolicy', 'PasswordHistorySize', 24),
          setting('AccountPolicy', 'LockoutBadCount', 10),
        ],
      },
      {
        id: '6ac1786c-016f-11d2-945f-00c04fb984f9',
        displayName: 'Default Domain Controllers Policy',
        domain: DOMAIN,
        gpoStatus: 'AllSettingsEnabled',
        createdTime: '2021-06-01T08:00:00Z',
        modifiedTime: '2025-01-13T10:42:00Z',
        wmiFilter: null,
        links: [link(`OU=Domain Controllers,${DOMAIN_DN}`)],
        settings: [
          setting('SecurityOptions', 'MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity', 2),
          setting('AuditPolicy', 'Audit Credential Validation', 'Success and Failure'),
          setting('AuditPolicy', 'Audit Directory Service Changes', 'Success'),
        ],
      },
      {
        id: guid('fabrikam:gpo:security-baseline'),
        displayName: 'FAB - Security Baseline',
        domain: DOMAIN,
        gpoStatus: 'UserSettingsDisabled',
        createdTime: '2021-06-02T09:00:00Z',
        modifiedTime: '2026-03-18T15:12:00Z',
        wmiFilter: null,
        links: [link(DOMAIN_DN)],
        settings: [
          setting('SecurityOptions', 'MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel', 5),
          setting('SecurityOptions', 'MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RunAsPPL', 1),
          setting('RegistryPolicy', 'Turn on PowerShell Script Block Logging', 'Enabled'),
        ],
      },
    ]),
    collected(gpoSysvolPasswordArtifacts, { filesScanned: 11, artifacts: [] }),
    collected(windowsHosts, [
      hardenedServer(`FAB-DC01.${DOMAIN}`, { osCaption: 'Microsoft Windows Server 2022 Datacenter', isDomainController: true, rdp: { enabled: false, nlaRequired: true } }),
      hardenedServer(`FAB-FS01.${DOMAIN}`, {
        osCaption: 'Microsoft Windows Server 2019 Standard',
        osVersion: '10.0.17763',
        osBuild: '17763',
        // SMBv1 left enabled for an old multifunction scanner.
        smb: { smb1ServerEnabled: true, serverRequireSecuritySignature: true },
      }),
    ]),
  ];

  const adPrereqs = [{ name: 'ActiveDirectory module (RSAT)', satisfied: true, detail: null }];
  return {
    directory: 'fabrikam',
    assessmentId: FABRIKAM_ASSESSMENT_ID,
    clock,
    environment: {
      label: 'Fabrikam (sample) - on-premises only',
      tenantId: null,
      tenantDisplayName: null,
      primaryDomain: 'fabrikam.example',
      adForestName: DOMAIN,
      adDomainName: DOMAIN,
    },
    options: {
      modules: ['AD', 'ADCS', 'GPO', 'Windows'],
      includeDomainControllerSettings: true,
      windowsHostScope: 'ComputerList',
      windowsHosts: [`FAB-DC01.${DOMAIN}`, `FAB-FS01.${DOMAIN}`],
    },
    modules: [
      {
        module: 'AD',
        status: 'Completed',
        startedOffset: -12,
        completedOffset: -8,
        prerequisites: [...adPrereqs, { name: 'Administrative read access to domain controllers', satisfied: true, detail: null }],
      },
      { module: 'ADCS', status: 'Completed', startedOffset: -8, completedOffset: -7, prerequisites: adPrereqs },
      {
        module: 'GPO',
        status: 'Completed',
        startedOffset: -7,
        completedOffset: -5,
        prerequisites: [{ name: 'GroupPolicy module (GPMC)', satisfied: true, detail: null }],
      },
      {
        module: 'Windows',
        status: 'Completed',
        startedOffset: -5,
        completedOffset: -1,
        prerequisites: [{ name: 'WinRM access to listed hosts', satisfied: true, detail: '2 hosts' }],
      },
    ],
    datasets,
  };
}
