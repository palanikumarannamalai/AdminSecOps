import type { DatasetData } from '@adminsecops/schemas';

/**
 * Normalization helpers for Intune compliance policies. They map Graph OData types
 * to the platforms counted by managedDeviceOverview; security judgements stay in the
 * controls.
 */

export type CompliancePolicy = DatasetData<'intune.compliancePolicies'>[number];
export type DeviceOverview = DatasetData<'intune.deviceOverview'>;

export const PLATFORMS = ['windows', 'macOS', 'iOS', 'android'] as const;
export type Platform = (typeof PLATFORMS)[number];

export const PLATFORM_LABELS: Record<Platform, string> = {
  windows: 'Windows',
  macOS: 'macOS',
  iOS: 'iOS/iPadOS',
  android: 'Android',
};

/**
 * Compliance policy OData types (without the "#microsoft.graph." prefix, lower-case)
 * for each platform. Windows Phone / Windows 10 Mobile policies are not mapped because
 * those devices are not part of windowsCount. Linux compliance is configured through
 * the settings catalog, not deviceCompliancePolicies, so it has no entry here.
 */
const ODATA_PLATFORM: Record<string, Platform> = {
  windows10compliancepolicy: 'windows',
  windows81compliancepolicy: 'windows',
  macoscompliancepolicy: 'macOS',
  ioscompliancepolicy: 'iOS',
  androidcompliancepolicy: 'android',
  androidworkprofilecompliancepolicy: 'android',
  androiddeviceownercompliancepolicy: 'android',
  aospdeviceownercompliancepolicy: 'android',
};

export function normalizedOdataType(policy: CompliancePolicy): string {
  return policy.odataType
    .trim()
    .toLowerCase()
    .replace(/^#?microsoft\.graph\./, '');
}

export function policyPlatform(policy: CompliancePolicy): Platform | null {
  return ODATA_PLATFORM[normalizedOdataType(policy)] ?? null;
}

export function isWindows10Policy(policy: CompliancePolicy): boolean {
  return normalizedOdataType(policy) === 'windows10compliancepolicy';
}

function targetKind(targetType: string): string {
  return targetType
    .trim()
    .toLowerCase()
    .replace(/^#?microsoft\.graph\./, '');
}

/** True when the policy has at least one include assignment (exclusion-only assignments do not count). */
export function isAssigned(policy: CompliancePolicy): boolean {
  return policy.assignments.some((a) => !targetKind(a.targetType).startsWith('exclusion'));
}

/** True when the policy targets all devices or all licensed users (not only specific groups). */
export function isAssignedBroadly(policy: CompliancePolicy): boolean {
  return policy.assignments.some((a) => {
    const kind = targetKind(a.targetType);
    return kind === 'alldevicesassignmenttarget' || kind === 'alllicensedusersassignmenttarget';
  });
}

export function deviceCount(overview: DeviceOverview, platform: Platform): number {
  switch (platform) {
    case 'windows':
      return overview.windowsCount;
    case 'macOS':
      return overview.macOSCount;
    case 'iOS':
      return overview.iosCount;
    case 'android':
      return overview.androidCount;
  }
}
