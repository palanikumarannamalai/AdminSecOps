/**
 * Builders for schema-valid Intune evidence used by control tests. They produce
 * collector-shaped input that the test inventory validates with the real schemas.
 */
import { nextGuid } from './entra.js';

export function intuneSettings(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    secureByDefault: true,
    deviceComplianceCheckinThresholdDays: 30,
    isScheduledActionEnabled: true,
    ...overrides,
  };
}

export function deviceOverview(
  counts: {
    windows?: number;
    macOS?: number;
    ios?: number;
    android?: number;
    linux?: number | null;
  } = {},
): Record<string, unknown> {
  const windowsCount = counts.windows ?? 0;
  const macOSCount = counts.macOS ?? 0;
  const iosCount = counts.ios ?? 0;
  const androidCount = counts.android ?? 0;
  const linuxCount = counts.linux ?? null;
  return {
    enrolledDeviceCount: windowsCount + macOSCount + iosCount + androidCount + (linuxCount ?? 0),
    windowsCount,
    macOSCount,
    iosCount,
    androidCount,
    linuxCount,
  };
}

export const ALL_DEVICES = '#microsoft.graph.allDevicesAssignmentTarget';
export const ALL_USERS = '#microsoft.graph.allLicensedUsersAssignmentTarget';
export const GROUP = '#microsoft.graph.groupAssignmentTarget';
export const EXCLUDE_GROUP = '#microsoft.graph.exclusionGroupAssignmentTarget';

export interface CompliancePolicyInput {
  id?: string;
  displayName?: string;
  /** Short OData type such as windows10CompliancePolicy; the #microsoft.graph. prefix is added. */
  type?: string;
  /** Assignment target types; defaults to all devices. */
  targets?: string[];
  settings?: Record<string, unknown>;
}

export function compliancePolicy(input: CompliancePolicyInput = {}): Record<string, unknown> {
  const type = input.type ?? 'windows10CompliancePolicy';
  return {
    id: input.id ?? nextGuid(),
    displayName: input.displayName ?? `${type} policy`,
    odataType: type.startsWith('#') ? type : `#microsoft.graph.${type}`,
    lastModifiedDateTime: '2026-08-01T10:00:00Z',
    assignments: (input.targets ?? [ALL_DEVICES]).map((targetType) => ({
      targetType,
      groupId: targetType === GROUP || targetType === EXCLUDE_GROUP ? nextGuid() : null,
    })),
    settings: {
      bitLockerEnabled: null,
      secureBootEnabled: null,
      codeIntegrityEnabled: null,
      storageRequireEncryption: null,
      passwordRequired: null,
      defenderEnabled: null,
      rtpEnabled: null,
      antivirusRequired: null,
      firewallEnabled: null,
      tpmRequired: null,
      osMinimumVersion: null,
      ...input.settings,
    },
  };
}
