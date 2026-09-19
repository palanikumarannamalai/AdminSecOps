const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * Parse an ISO-8601 timestamp. Returns undefined for missing or invalid input rather
 * than producing an Invalid Date, so callers must handle absence explicitly.
 */
export function parseTimestamp(value: string | null | undefined): Date | undefined {
  if (value === null || value === undefined || value === '') return undefined;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? undefined : new Date(ms);
}

/** Whole days from `from` to `to` (positive when `to` is later). */
export function daysBetween(from: Date, to: Date): number {
  return Math.floor((to.getTime() - from.getTime()) / MS_PER_DAY);
}

export function addDays(date: Date, days: number): Date {
  return new Date(date.getTime() + days * MS_PER_DAY);
}
