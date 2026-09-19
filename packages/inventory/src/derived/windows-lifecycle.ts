/**
 * End of support dates for Windows operating systems, used to identify unsupported
 * systems deterministically at the assessment date. Dates are the end of extended
 * support (servers) or end of servicing for the final release (clients), from the
 * Microsoft Lifecycle Policy site. Extended Security Updates (ESU) are not modelled;
 * a system covered by ESU is still reported so the administrator can confirm coverage.
 */
export interface LifecycleEntry {
  /** Pattern matched against the AD operatingSystem / OS caption string. */
  pattern: RegExp;
  product: string;
  endOfSupport: string;
}

export const WINDOWS_LIFECYCLE: readonly LifecycleEntry[] = [
  { pattern: /windows server 2003/i, product: 'Windows Server 2003', endOfSupport: '2015-07-14' },
  { pattern: /windows server 2008 r2/i, product: 'Windows Server 2008 R2', endOfSupport: '2020-01-14' },
  { pattern: /windows server 2008(?! r2)/i, product: 'Windows Server 2008', endOfSupport: '2020-01-14' },
  { pattern: /windows server 2012 r2/i, product: 'Windows Server 2012 R2', endOfSupport: '2023-10-10' },
  { pattern: /windows server 2012(?! r2)/i, product: 'Windows Server 2012', endOfSupport: '2023-10-10' },
  { pattern: /windows server 2016/i, product: 'Windows Server 2016', endOfSupport: '2027-01-12' },
  { pattern: /windows server 2019/i, product: 'Windows Server 2019', endOfSupport: '2029-01-09' },
  { pattern: /windows server 2022/i, product: 'Windows Server 2022', endOfSupport: '2031-10-14' },
  { pattern: /windows server 2025/i, product: 'Windows Server 2025', endOfSupport: '2034-11-14' },
  { pattern: /windows xp/i, product: 'Windows XP', endOfSupport: '2014-04-08' },
  { pattern: /windows vista/i, product: 'Windows Vista', endOfSupport: '2017-04-11' },
  { pattern: /windows 7/i, product: 'Windows 7', endOfSupport: '2020-01-14' },
  { pattern: /windows 8\.1/i, product: 'Windows 8.1', endOfSupport: '2023-01-10' },
  { pattern: /windows 8(?!\.)/i, product: 'Windows 8', endOfSupport: '2016-01-12' },
  // LTSC/LTSB editions have release-specific dates and are intentionally not matched.
  { pattern: /windows 10(?!.*\b(?:ltsc|ltsb)\b)/i, product: 'Windows 10', endOfSupport: '2025-10-14' },
];

export interface LifecycleStatus {
  product: string;
  endOfSupport: string;
  unsupported: boolean;
}

/** Lifecycle status of an OS name at the given date; undefined when the OS is not in the table. */
export function windowsLifecycleStatus(operatingSystem: string | null, at: Date): LifecycleStatus | undefined {
  if (operatingSystem === null) return undefined;
  const entry = WINDOWS_LIFECYCLE.find((e) => e.pattern.test(operatingSystem));
  if (entry === undefined) return undefined;
  return {
    product: entry.product,
    endOfSupport: entry.endOfSupport,
    unsupported: at.getTime() > Date.parse(`${entry.endOfSupport}T23:59:59Z`),
  };
}
