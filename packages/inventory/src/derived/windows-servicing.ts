import { windowsLifecycleStatus, type LifecycleStatus } from './windows-lifecycle.js';

/**
 * Windows build and servicing helpers for host evidence (windows.hosts). Pure data
 * normalization: deciding whether a state is acceptable is left to controls.
 */

/**
 * Windows build number from the collected osBuild ("22631") or osVersion
 * ("10.0.22631"); null when neither can be parsed.
 */
export function windowsBuildNumber(osBuild: string | null, osVersion: string | null): number | null {
  if (osBuild !== null && /^\s*\d{3,6}\s*$/.test(osBuild)) return Number(osBuild.trim());
  if (osVersion !== null) {
    const match = /^\s*\d+\.\d+\.(\d{3,6})/.exec(osVersion);
    if (match?.[1] !== undefined) return Number(match[1]);
  }
  return null;
}

/** True when the OS caption describes a Windows Server edition. */
export function isWindowsServerCaption(caption: string | null): boolean {
  return caption !== null && /\bwindows server\b/i.test(caption);
}

/**
 * Windows 11 General Availability Channel releases with end-of-updates dates per edition
 * group, from the Windows 11 release information page on Microsoft Learn
 * (Home/Pro/Pro Education/Pro for Workstations vs Enterprise/Education/IoT Enterprise).
 */
export interface Windows11Release {
  version: string;
  build: number;
  endHomePro: string;
  endEnterpriseEducation: string;
}

export const WINDOWS11_RELEASES: readonly Windows11Release[] = [
  { version: '21H2', build: 22000, endHomePro: '2023-10-10', endEnterpriseEducation: '2024-10-08' },
  { version: '22H2', build: 22621, endHomePro: '2024-10-08', endEnterpriseEducation: '2025-10-14' },
  { version: '23H2', build: 22631, endHomePro: '2025-11-11', endEnterpriseEducation: '2026-11-10' },
  { version: '24H2', build: 26100, endHomePro: '2026-10-13', endEnterpriseEducation: '2027-10-12' },
  { version: '25H2', build: 26200, endHomePro: '2027-10-12', endEnterpriseEducation: '2028-10-10' },
  { version: '26H1', build: 28000, endHomePro: '2028-03-14', endEnterpriseEducation: '2029-03-13' },
];

type Windows11EditionGroup = 'homePro' | 'enterpriseEducation';

/** Edition group of a Windows 11 caption; null when it cannot be determined. */
export function windows11EditionGroup(caption: string): Windows11EditionGroup | null {
  // "Pro Education" and "Pro for Workstations" follow the Home/Pro schedule.
  if (/\bpro\b/i.test(caption) || /\bhome\b/i.test(caption)) return 'homePro';
  if (/\benterprise\b/i.test(caption) || /\beducation\b/i.test(caption)) return 'enterpriseEducation';
  return null;
}

function unsupportedAt(endOfSupport: string, at: Date): boolean {
  return at.getTime() > Date.parse(`${endOfSupport}T23:59:59Z`);
}

/**
 * Support status of a Windows 11 host by build and edition. Undefined for LTSC editions,
 * unknown builds or editions (the administrator must confirm those).
 */
export function windows11ServicingStatus(caption: string | null, build: number | null, at: Date): LifecycleStatus | undefined {
  if (caption === null || build === null) return undefined;
  if (!/\bwindows 11\b/i.test(caption) || isWindowsServerCaption(caption)) return undefined;
  if (/\bltsc\b/i.test(caption)) return undefined;
  const release = WINDOWS11_RELEASES.find((r) => r.build === build);
  const group = windows11EditionGroup(caption);
  if (release === undefined || group === null) return undefined;
  const endOfSupport = group === 'homePro' ? release.endHomePro : release.endEnterpriseEducation;
  return {
    product: `Windows 11 ${group === 'homePro' ? 'Home/Pro' : 'Enterprise/Education'}, version ${release.version}`,
    endOfSupport,
    unsupported: unsupportedAt(endOfSupport, at),
  };
}

/**
 * Support status of a Windows host at a point in time: Windows 11 by build and edition,
 * other products from the WINDOWS_LIFECYCLE table. Undefined when the product is not
 * known to AdminSecOps.
 */
export function windowsOsSupportStatus(caption: string | null, build: number | null, at: Date): LifecycleStatus | undefined {
  if (caption !== null && /\bwindows 11\b/i.test(caption) && !isWindowsServerCaption(caption)) {
    return windows11ServicingStatus(caption, build, at);
  }
  return windowsLifecycleStatus(caption, at);
}
