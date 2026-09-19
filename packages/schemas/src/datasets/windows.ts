import { z } from 'zod';
import { list, optBool, optNumber, optString, optTimestamp } from '../common.js';
import { defineDataset } from './define.js';

export const gpoGroupPolicyObjects = defineDataset({
  id: 'gpo.groupPolicyObjects',
  module: 'GPO',
  technology: 'gpo',
  title: 'Group Policy objects',
  description:
    'Group Policy objects with status, links and a flattened list of configured security-relevant settings parsed from the GPO XML report.',
  source: 'GroupPolicy',
  operations: ['Get-GPO -All', 'Get-GPOReport -ReportType Xml'],
  permissions: ['Active Directory: authenticated domain user (GPO read)'],
  personalData: 'none',
  schema: z.array(
    z.object({
      id: z.string(),
      displayName: z.string(),
      domain: z.string(),
      /** AllSettingsEnabled | UserSettingsDisabled | ComputerSettingsDisabled | AllSettingsDisabled */
      gpoStatus: z.string(),
      createdTime: optTimestamp,
      modifiedTime: optTimestamp,
      wmiFilter: optString,
      links: list(
        z.object({
          somPath: z.string(),
          enabled: z.boolean(),
          enforced: z.boolean(),
        }),
      ),
      /**
       * Flattened settings parsed from the GPO XML report. Naming convention:
       * - SecurityOptions: name = registry KeyName as in the report
       *   (e.g. MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel), value = number|string
       * - AccountPolicy: name = policy Name (e.g. MinimumPasswordLength), value = number|boolean
       * - UserRightsAssignment: name = right constant (e.g. SeDebugPrivilege), value = member names/SIDs
       * - AuditPolicy: name = audit (sub)category, value = Success | Failure | Success and Failure | No Auditing
       * - RegistryPolicy (Administrative Templates): name = policy name as displayed, value = Enabled | Disabled
       * - RegistryValue: name = full registry path incl. value name, value = number|string
       */
      settings: list(
        z.object({
          /** Computer | User */
          scope: z.string(),
          /** SecurityOptions | AccountPolicy | UserRightsAssignment | AuditPolicy | RegistryPolicy | RegistryValue | Other */
          category: z.string(),
          name: z.string(),
          value: z.union([z.string(), z.number(), z.boolean(), z.array(z.string())]).nullable(),
        }),
      ),
    }),
  ),
});

export const gpoSysvolPasswordArtifacts = defineDataset({
  id: 'gpo.sysvolPasswordArtifacts',
  module: 'GPO',
  technology: 'gpo',
  title: 'Group Policy Preferences password artifacts',
  description:
    'Group Policy Preferences XML files in SYSVOL that contain a non-empty cpassword attribute. Only the file location is recorded; the value is never read into evidence.',
  source: 'GroupPolicy',
  operations: ['Get-ChildItem \\\\<domain>\\SYSVOL\\<domain>\\Policies -Recurse -Include *.xml (content scanned in memory)'],
  permissions: ['Active Directory: authenticated domain user (SYSVOL read)'],
  personalData: 'none',
  schema: z.object({
    filesScanned: z.number().int().nonnegative(),
    artifacts: list(
      z.object({
        domain: z.string(),
        gpoId: optString,
        /** Path relative to the domain Policies folder */
        relativePath: z.string(),
        /** Groups.xml | Services.xml | ScheduledTasks.xml | DataSources.xml | Drives.xml | Printers.xml */
        fileName: z.string(),
      }),
    ),
  }),
});

export const windowsHosts = defineDataset({
  id: 'windows.hosts',
  module: 'Windows',
  technology: 'windows',
  title: 'Windows host security configuration',
  description:
    'Effective security configuration of assessed Windows hosts (firewall, SMB, RDP, LSA, credential protection, PowerShell logging, Defender).',
  source: 'WindowsHost',
  operations: [
    'Get-CimInstance Win32_OperatingSystem',
    'Get-NetFirewallProfile',
    'Get-SmbServerConfiguration',
    'Registry reads under HKLM (Terminal Server, Lsa, WDigest, PowerShell policies)',
    'Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard Win32_DeviceGuard',
    'Get-MpComputerStatus',
  ],
  permissions: ['Local administrator on the assessed host (some values are only readable when elevated)'],
  personalData: 'none',
  schema: z.array(
    z.object({
      hostName: z.string(),
      osCaption: optString,
      osVersion: optString,
      osBuild: optString,
      isServer: z.boolean(),
      isDomainController: z.boolean(),
      domainJoined: optBool,
      firewallProfiles: list(
        z.object({
          name: z.string(),
          enabled: optBool,
          defaultInboundAction: optString,
        }),
      ),
      smb: z.object({
        smb1ServerEnabled: optBool,
        serverRequireSecuritySignature: optBool,
      }),
      rdp: z.object({
        /** true when fDenyTSConnections = 0 */
        enabled: optBool,
        /** UserAuthentication = 1 */
        nlaRequired: optBool,
      }),
      lsa: z.object({
        runAsPPL: optNumber,
        lmCompatibilityLevel: optNumber,
        wdigestUseLogonCredential: optNumber,
      }),
      credentialGuard: z.object({
        /** Win32_DeviceGuard.SecurityServicesRunning contains 1 */
        running: optBool,
        /** Win32_DeviceGuard.VirtualizationBasedSecurityStatus (0 off, 1 configured, 2 running) */
        vbsStatus: optNumber,
      }),
      powershell: z.object({
        scriptBlockLoggingEnabled: optBool,
      }),
      defender: z.object({
        available: z.boolean(),
        antivirusEnabled: optBool,
        realTimeProtectionEnabled: optBool,
        isTamperProtected: optBool,
        antivirusSignatureAgeDays: optNumber,
      }),
    }),
  ),
});

export const WINDOWS_DATASETS = [gpoGroupPolicyObjects, gpoSysvolPasswordArtifacts, windowsHosts] as const;
