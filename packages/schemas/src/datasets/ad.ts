import { z } from 'zod';
import { list, optBool, optNumber, optString, optTimestamp } from '../common.js';
import { defineDataset } from './define.js';

const DOMAIN_USER = 'Active Directory: authenticated domain user (read access to directory objects)';

export const adForest = defineDataset({
  id: 'ad.forest',
  module: 'AD',
  technology: 'ad',
  title: 'Forest',
  description: 'Forest functional level, domains and optional features.',
  source: 'ActiveDirectory',
  operations: ['Get-ADForest', "Get-ADOptionalFeature -Filter \"name -eq 'Recycle Bin Feature'\""],
  permissions: [DOMAIN_USER],
  personalData: 'none',
  schema: z.object({
    name: z.string(),
    forestMode: z.string(),
    rootDomain: z.string(),
    domains: list(z.string()),
    recycleBinEnabled: z.boolean(),
  }),
});

export const adDomains = defineDataset({
  id: 'ad.domains',
  module: 'AD',
  technology: 'ad',
  title: 'Domains',
  description: 'Domain functional level and machine account quota.',
  source: 'ActiveDirectory',
  operations: ['Get-ADDomain', 'Get-ADObject <domain DN> -Properties ms-DS-MachineAccountQuota'],
  permissions: [DOMAIN_USER],
  personalData: 'none',
  schema: z.array(
    z.object({
      dnsRoot: z.string(),
      netBIOSName: z.string(),
      domainSid: z.string(),
      distinguishedName: z.string(),
      domainMode: z.string(),
      machineAccountQuota: optNumber,
    }),
  ),
});

const PasswordPolicyFields = {
  minPasswordLength: z.number().int().nonnegative(),
  passwordHistoryCount: z.number().int().nonnegative(),
  /** null when passwords never expire */
  maxPasswordAgeDays: optNumber,
  complexityEnabled: z.boolean(),
  reversibleEncryptionEnabled: z.boolean(),
  /** 0 means accounts never lock out */
  lockoutThreshold: z.number().int().nonnegative(),
  lockoutDurationMinutes: optNumber,
};

export const adPasswordPolicies = defineDataset({
  id: 'ad.passwordPolicies',
  module: 'AD',
  technology: 'ad',
  title: 'Password policies',
  description: 'Default domain password policy and fine-grained password policies (PSOs).',
  source: 'ActiveDirectory',
  operations: ['Get-ADDefaultDomainPasswordPolicy', 'Get-ADFineGrainedPasswordPolicy -Filter *'],
  permissions: [DOMAIN_USER, 'Reading PSOs may require delegated read on the Password Settings Container'],
  personalData: 'none',
  schema: z.array(
    z.object({
      domain: z.string(),
      defaultPolicy: z.object(PasswordPolicyFields),
      fineGrainedPolicies: list(
        z.object({
          name: z.string(),
          precedence: z.number().int(),
          appliesToCount: z.number().int().nonnegative(),
          ...PasswordPolicyFields,
        }),
      ),
    }),
  ),
});

export const adPrivilegedGroups = defineDataset({
  id: 'ad.privilegedGroups',
  module: 'AD',
  technology: 'ad',
  title: 'Privileged group membership',
  description: 'Recursive membership of built-in privileged groups (Domain Admins, Enterprise Admins, etc.).',
  source: 'ActiveDirectory',
  operations: ['Get-ADGroup -Identity <well-known SID>', 'Get-ADGroupMember -Recursive'],
  permissions: [DOMAIN_USER],
  personalData: 'identifiers',
  schema: z.array(
    z.object({
      domain: z.string(),
      groupName: z.string(),
      groupSid: z.string(),
      members: list(
        z.object({
          samAccountName: z.string(),
          sid: z.string(),
          /** user | computer | msDS-GroupManagedServiceAccount | ... */
          objectClass: z.string(),
        }),
      ),
    }),
  ),
});

export const adUsers = defineDataset({
  id: 'ad.users',
  module: 'AD',
  technology: 'ad',
  title: 'Security-relevant user accounts',
  description:
    'User accounts that are privileged (adminCount=1), have a service principal name, or carry risky account flags, plus domain-wide user counts. Password material is never read.',
  source: 'ActiveDirectory',
  operations: [
    'Get-ADUser -LDAPFilter "(|(adminCount=1)(servicePrincipalName=*)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(userAccountControl:1.2.840.113556.1.4.803:=32)(userAccountControl:1.2.840.113556.1.4.803:=128)(userAccountControl:1.2.840.113556.1.4.803:=524288))"',
  ],
  permissions: [DOMAIN_USER],
  personalData: 'identifiers-and-activity',
  schema: z.object({
    domains: list(
      z.object({
        domain: z.string(),
        totalUsers: z.number().int().nonnegative(),
        enabledUsers: z.number().int().nonnegative(),
        protectedUsersGroupSids: list(z.string()),
      }),
    ),
    users: list(
      z.object({
        domain: z.string(),
        samAccountName: z.string(),
        sid: z.string(),
        enabled: z.boolean(),
        adminCount: z.boolean(),
        lastLogonTimestamp: optTimestamp,
        pwdLastSet: optTimestamp,
        whenCreated: optTimestamp,
        passwordNeverExpires: z.boolean(),
        passwordNotRequired: z.boolean(),
        doesNotRequirePreAuth: z.boolean(),
        allowReversiblePasswordEncryption: z.boolean(),
        accountNotDelegated: z.boolean(),
        trustedForDelegation: z.boolean(),
        trustedToAuthForDelegation: z.boolean(),
        servicePrincipalNameCount: z.number().int().nonnegative(),
        memberOfProtectedUsers: z.boolean(),
      }),
    ),
  }),
});

export const adKrbtgt = defineDataset({
  id: 'ad.krbtgt',
  module: 'AD',
  technology: 'ad',
  title: 'KRBTGT account',
  description: 'Password age of the KRBTGT account in each domain (timestamp only).',
  source: 'ActiveDirectory',
  operations: ['Get-ADUser krbtgt -Properties pwdLastSet'],
  permissions: [DOMAIN_USER],
  personalData: 'none',
  schema: z.array(
    z.object({
      domain: z.string(),
      pwdLastSet: optTimestamp,
    }),
  ),
});

export const adComputers = defineDataset({
  id: 'ad.computers',
  module: 'AD',
  technology: 'ad',
  title: 'Computer accounts',
  description:
    'Computer accounts with operating system, delegation flags and LAPS password expiry timestamps. LAPS passwords are never read.',
  source: 'ActiveDirectory',
  operations: [
    'Get-ADComputer -Filter * -Properties OperatingSystem,OperatingSystemVersion,LastLogonTimestamp,TrustedForDelegation,TrustedToAuthForDelegation,msDS-AllowedToDelegateTo,PrimaryGroupID,ms-Mcs-AdmPwdExpirationTime,msLAPS-PasswordExpirationTime',
  ],
  permissions: [DOMAIN_USER],
  personalData: 'identifiers-and-activity',
  schema: z.array(
    z.object({
      domain: z.string(),
      name: z.string(),
      dnsHostName: optString,
      enabled: z.boolean(),
      operatingSystem: optString,
      operatingSystemVersion: optString,
      /** primaryGroupID 516 (DC) or 521 (RODC) */
      isDomainController: z.boolean(),
      trustedForDelegation: z.boolean(),
      trustedToAuthForDelegation: z.boolean(),
      allowedToDelegateToCount: z.number().int().nonnegative(),
      lastLogonTimestamp: optTimestamp,
      legacyLapsExpiration: optTimestamp,
      windowsLapsExpiration: optTimestamp,
    }),
  ),
});

export const adTrusts = defineDataset({
  id: 'ad.trusts',
  module: 'AD',
  technology: 'ad',
  title: 'Trusts',
  description: 'Domain and forest trusts with SID filtering and authentication settings.',
  source: 'ActiveDirectory',
  operations: ['Get-ADTrust -Filter *'],
  permissions: [DOMAIN_USER],
  personalData: 'none',
  schema: z.array(
    z.object({
      domain: z.string(),
      target: z.string(),
      /** Inbound | Outbound | BiDirectional */
      direction: z.string(),
      /** Uplevel | Downlevel | MIT | ... */
      trustType: z.string(),
      forestTransitive: z.boolean(),
      intraForest: z.boolean(),
      sidFilteringQuarantined: z.boolean(),
      sidFilteringForestAware: z.boolean(),
      selectiveAuthentication: z.boolean(),
      tgtDelegation: optBool,
    }),
  ),
});

export const adDomainControllers = defineDataset({
  id: 'ad.domainControllers',
  module: 'AD',
  technology: 'ad',
  title: 'Domain controllers',
  description: 'Domain controllers with operating system and role information.',
  source: 'ActiveDirectory',
  operations: ['Get-ADDomainController -Filter *'],
  permissions: [DOMAIN_USER],
  personalData: 'none',
  schema: z.array(
    z.object({
      domain: z.string(),
      hostName: z.string(),
      site: optString,
      operatingSystem: optString,
      operatingSystemVersion: optString,
      isGlobalCatalog: z.boolean(),
      isReadOnly: z.boolean(),
    }),
  ),
});

export const adDomainControllerSettings = defineDataset({
  id: 'ad.domainControllerSettings',
  module: 'AD',
  technology: 'ad',
  title: 'Domain controller security settings',
  description:
    'Registry-based LDAP signing, LDAP channel binding and SMB signing settings read from each domain controller. Optional: requires -IncludeDomainControllerSettings and administrative read access.',
  source: 'ActiveDirectory',
  operations: [
    'Remote registry read: HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters (LDAPServerIntegrity, LdapEnforceChannelBinding)',
    'Remote registry read: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters (RequireSecuritySignature, SMB1)',
  ],
  permissions: ['Local administrator (read-only registry access) on domain controllers'],
  personalData: 'none',
  schema: z.array(
    z.object({
      hostName: z.string(),
      /** Success | Failed for this host */
      readStatus: z.enum(['Success', 'Failed']),
      /** 0 none, 1 negotiate (default), 2 require signing */
      ldapServerIntegrity: optNumber,
      /** 0 never, 1 when supported, 2 always */
      ldapEnforceChannelBinding: optNumber,
      smbRequireSecuritySignature: optNumber,
      smb1Enabled: optNumber,
    }),
  ),
});

export const AD_DATASETS = [
  adForest,
  adDomains,
  adPasswordPolicies,
  adPrivilegedGroups,
  adUsers,
  adKrbtgt,
  adComputers,
  adTrusts,
  adDomainControllers,
  adDomainControllerSettings,
] as const;
