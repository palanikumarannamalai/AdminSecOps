/**
 * Builder for schema-valid Windows host evidence (collector-shaped input). The default
 * host is a hardened, domain-joined Windows Server 2022 member server; tests override
 * only the properties they exercise.
 */

type Section = Record<string, unknown>;

export interface HostInput {
  hostName?: string;
  osCaption?: string | null;
  osVersion?: string | null;
  osBuild?: string | null;
  isServer?: boolean;
  isDomainController?: boolean;
  domainJoined?: boolean | null;
  firewallProfiles?: Section[];
  smb?: Section;
  rdp?: Section;
  lsa?: Section;
  credentialGuard?: Section;
  powershell?: Section;
  defender?: Section;
}

export function firewallProfile(name: string, enabled: boolean | null = true, defaultInboundAction: string | null = 'Block'): Section {
  return { name, enabled, defaultInboundAction };
}

export function host(input: HostInput = {}): Record<string, unknown> {
  return {
    hostName: input.hostName ?? 'SRV01',
    osCaption: input.osCaption === undefined ? 'Microsoft Windows Server 2022 Standard' : input.osCaption,
    osVersion: input.osVersion === undefined ? '10.0.20348' : input.osVersion,
    osBuild: input.osBuild === undefined ? '20348' : input.osBuild,
    isServer: input.isServer ?? true,
    isDomainController: input.isDomainController ?? false,
    domainJoined: input.domainJoined === undefined ? true : input.domainJoined,
    firewallProfiles: input.firewallProfiles ?? [firewallProfile('Domain'), firewallProfile('Private'), firewallProfile('Public')],
    smb: { smb1ServerEnabled: false, serverRequireSecuritySignature: true, ...input.smb },
    rdp: { enabled: true, nlaRequired: true, ...input.rdp },
    lsa: { runAsPPL: 1, lmCompatibilityLevel: 5, wdigestUseLogonCredential: 0, ...input.lsa },
    credentialGuard: { running: true, vbsStatus: 2, ...input.credentialGuard },
    powershell: { scriptBlockLoggingEnabled: true, ...input.powershell },
    defender: {
      available: true,
      antivirusEnabled: true,
      realTimeProtectionEnabled: true,
      isTamperProtected: true,
      antivirusSignatureAgeDays: 0,
      ...input.defender,
    },
  };
}

export const WIN11_ENTERPRISE_24H2: HostInput = {
  osCaption: 'Microsoft Windows 11 Enterprise',
  osVersion: '10.0.26100',
  osBuild: '26100',
  isServer: false,
};
