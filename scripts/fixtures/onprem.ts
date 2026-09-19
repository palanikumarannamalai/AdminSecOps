/**
 * Shared builders for on-premises fixture data (AD CS templates, Windows hosts),
 * parameterised by domain so Contoso and Fabrikam stay consistent.
 */
import type { adcsCertificateTemplates, windowsHosts } from '@adminsecops/schemas';
import type { z } from 'zod';

type Template = z.input<(typeof adcsCertificateTemplates)['schema']>[number];
type Ace = NonNullable<Template['permissions']>[number];
export type WindowsHost = z.input<(typeof windowsHosts)['schema']>[number];

export const ALL_OBJECTS = '00000000-0000-0000-0000-000000000000';
export const ENROLL = '0e10c968-78fb-11d2-90d4-00c04f79dc55';
export const AUTOENROLL = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2';

export const OID = {
  clientAuthentication: '1.3.6.1.5.5.7.3.2',
  serverAuthentication: '1.3.6.1.5.5.7.3.1',
  secureEmail: '1.3.6.1.5.5.7.3.4',
  encryptingFileSystem: '1.3.6.1.4.1.311.10.3.4',
  smartCardLogon: '1.3.6.1.4.1.311.20.2.2',
  kdcAuthentication: '1.3.6.1.5.2.3.5',
} as const;

/** Well-known principals for one domain. */
export class DomainPrincipals {
  constructor(
    readonly netbios: string,
    readonly domainSid: string,
  ) {}

  private named(rid: number, name: string) {
    return { sid: `${this.domainSid}-${rid}`, name: `${this.netbios}\\${name}` };
  }

  get domainAdmins() {
    return this.named(512, 'Domain Admins');
  }
  get domainUsers() {
    return this.named(513, 'Domain Users');
  }
  get domainComputers() {
    return this.named(515, 'Domain Computers');
  }
  get domainControllers() {
    return this.named(516, 'Domain Controllers');
  }
  get enterpriseAdmins() {
    return this.named(519, 'Enterprise Admins');
  }
  get authenticatedUsers() {
    return { sid: 'S-1-5-11', name: 'NT AUTHORITY\\Authenticated Users' };
  }
  get enterpriseDomainControllers() {
    return { sid: 'S-1-5-9', name: 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS' };
  }
}

export function ace(principal: { sid: string; name: string }, rights: string[], objectType: string = ALL_OBJECTS): Ace {
  return { principalSid: principal.sid, principalName: principal.name, accessControlType: 'Allow', rights, objectType };
}

/** Default template ACL: Authenticated Users read, Domain/Enterprise Admins full control and enroll. */
export function adminAcl(p: DomainPrincipals): Ace[] {
  const write = ['CreateChild', 'DeleteChild', 'Self', 'WriteProperty', 'DeleteTree', 'Delete', 'GenericRead', 'WriteDacl', 'WriteOwner'];
  return [
    ace(p.authenticatedUsers, ['GenericRead']),
    ace(p.domainAdmins, write),
    ace(p.domainAdmins, ['ExtendedRight'], ENROLL),
    ace(p.enterpriseAdmins, write),
    ace(p.enterpriseAdmins, ['ExtendedRight'], ENROLL),
  ];
}

/** Built-in templates as they appear in a default AD CS installation. */
export function builtInTemplates(p: DomainPrincipals): Template[] {
  return [
    {
      name: 'User',
      displayName: 'User',
      schemaVersion: 1,
      certificateNameFlag: -1509949440, // 0xA6000000: subject built from AD (UPN, e-mail, DNS as required)
      enrollmentFlag: 41,
      raSignature: 0,
      extendedKeyUsage: [OID.encryptingFileSystem, OID.secureEmail, OID.clientAuthentication],
      applicationPolicies: [],
      permissions: [...adminAcl(p), ace(p.domainUsers, ['ExtendedRight'], ENROLL)],
    },
    {
      name: 'Machine',
      displayName: 'Computer',
      schemaVersion: 1,
      certificateNameFlag: 402653184, // 0x18000000: DNS name from AD
      enrollmentFlag: 0,
      raSignature: 0,
      extendedKeyUsage: [OID.clientAuthentication, OID.serverAuthentication],
      applicationPolicies: [],
      permissions: [...adminAcl(p), ace(p.domainComputers, ['ExtendedRight'], ENROLL)],
    },
    {
      name: 'DomainController',
      displayName: 'Domain Controller',
      schemaVersion: 1,
      certificateNameFlag: 419430400, // 0x19000000
      enrollmentFlag: 0,
      raSignature: 0,
      extendedKeyUsage: [OID.clientAuthentication, OID.serverAuthentication],
      applicationPolicies: [],
      permissions: [
        ...adminAcl(p),
        ace(p.domainControllers, ['ExtendedRight'], ENROLL),
        ace(p.enterpriseDomainControllers, ['ExtendedRight'], ENROLL),
      ],
    },
    {
      name: 'WebServer',
      displayName: 'Web Server',
      schemaVersion: 1,
      // Enrollee supplies subject, but only administrators may enroll and the EKU is server authentication only.
      certificateNameFlag: 1,
      enrollmentFlag: 0,
      raSignature: 0,
      extendedKeyUsage: [OID.serverAuthentication],
      applicationPolicies: [],
      permissions: adminAcl(p),
    },
    {
      name: 'SubCA',
      displayName: 'Subordinate Certification Authority',
      schemaVersion: 1,
      certificateNameFlag: 1,
      enrollmentFlag: 0,
      raSignature: 0,
      extendedKeyUsage: [],
      applicationPolicies: [],
      permissions: adminAcl(p),
    },
  ];
}

/** Baseline of a well configured Windows Server host; callers override deviations. */
export function hardenedServer(hostName: string, overrides: Partial<WindowsHost> = {}): WindowsHost {
  return {
    hostName,
    osCaption: 'Microsoft Windows Server 2022 Standard',
    osVersion: '10.0.20348',
    osBuild: '20348',
    isServer: true,
    isDomainController: false,
    domainJoined: true,
    firewallProfiles: [
      { name: 'Domain', enabled: true, defaultInboundAction: 'Block' },
      { name: 'Private', enabled: true, defaultInboundAction: 'Block' },
      { name: 'Public', enabled: true, defaultInboundAction: 'Block' },
    ],
    smb: { smb1ServerEnabled: false, serverRequireSecuritySignature: true },
    rdp: { enabled: true, nlaRequired: true },
    lsa: { runAsPPL: 1, lmCompatibilityLevel: 5, wdigestUseLogonCredential: 0 },
    credentialGuard: { running: true, vbsStatus: 2 },
    powershell: { scriptBlockLoggingEnabled: true },
    defender: {
      available: true,
      antivirusEnabled: true,
      realTimeProtectionEnabled: true,
      isTamperProtected: true,
      antivirusSignatureAgeDays: 0,
    },
    ...overrides,
  };
}
