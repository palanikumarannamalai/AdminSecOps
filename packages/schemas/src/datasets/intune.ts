import { z } from 'zod';
import { list, optBool, optNumber, optString, optTimestamp } from '../common.js';
import { defineDataset } from './define.js';

const GRAPH = 'https://graph.microsoft.com/v1.0';

export const intuneSettings = defineDataset({
  id: 'intune.settings',
  module: 'Intune',
  technology: 'intune',
  title: 'Intune tenant compliance settings',
  description: 'Tenant-wide device compliance settings, including how devices without a compliance policy are treated.',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/deviceManagement?$select=settings`],
  permissions: ['Graph: DeviceManagementConfiguration.Read.All'],
  prerequisites: ['Microsoft Intune'],
  personalData: 'none',
  schema: z.object({
    secureByDefault: z.boolean(),
    deviceComplianceCheckinThresholdDays: optNumber,
    isScheduledActionEnabled: optBool,
  }),
});

export const intuneDeviceOverview = defineDataset({
  id: 'intune.deviceOverview',
  module: 'Intune',
  technology: 'intune',
  title: 'Managed device overview',
  description: 'Counts of enrolled devices by platform. No per-device data is collected.',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/deviceManagement/managedDeviceOverview`],
  permissions: ['Graph: DeviceManagementManagedDevices.Read.All'],
  prerequisites: ['Microsoft Intune'],
  personalData: 'none',
  schema: z.object({
    enrolledDeviceCount: z.number().int().nonnegative(),
    windowsCount: z.number().int().nonnegative(),
    macOSCount: z.number().int().nonnegative(),
    iosCount: z.number().int().nonnegative(),
    androidCount: z.number().int().nonnegative(),
  }),
});

export const intuneCompliancePolicies = defineDataset({
  id: 'intune.compliancePolicies',
  module: 'Intune',
  technology: 'intune',
  title: 'Device compliance policies',
  description: 'Device compliance policies with selected security settings and assignment targets.',
  source: 'MicrosoftGraph',
  operations: [`GET ${GRAPH}/deviceManagement/deviceCompliancePolicies?$expand=assignments`],
  permissions: ['Graph: DeviceManagementConfiguration.Read.All'],
  prerequisites: ['Microsoft Intune'],
  personalData: 'none',
  schema: z.array(
    z.object({
      id: z.string(),
      displayName: z.string(),
      /** OData type, e.g. #microsoft.graph.windows10CompliancePolicy */
      odataType: z.string(),
      lastModifiedDateTime: optTimestamp,
      assignments: list(
        z.object({
          /** e.g. #microsoft.graph.allDevicesAssignmentTarget, groupAssignmentTarget, exclusionGroupAssignmentTarget */
          targetType: z.string(),
          groupId: optString,
        }),
      ),
      settings: z.object({
        bitLockerEnabled: optBool,
        secureBootEnabled: optBool,
        codeIntegrityEnabled: optBool,
        storageRequireEncryption: optBool,
        passwordRequired: optBool,
        defenderEnabled: optBool,
        rtpEnabled: optBool,
        antivirusRequired: optBool,
        firewallEnabled: optBool,
        tpmRequired: optBool,
        osMinimumVersion: optString,
      }),
    }),
  ),
});

export const INTUNE_DATASETS = [intuneSettings, intuneDeviceOverview, intuneCompliancePolicies] as const;
