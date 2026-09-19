const dateTimeFormat = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  timeZoneName: 'short',
});

const dateFormat = new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: '2-digit' });

/** Localized date and time; returns the input unchanged when it is not a valid timestamp. */
export function formatDateTime(value: string | null | undefined): string {
  if (value === null || value === undefined || value === '') return 'Not recorded';
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? value : dateTimeFormat.format(new Date(ms));
}

export function formatDate(value: string | null | undefined): string {
  if (value === null || value === undefined || value === '') return 'Not recorded';
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? value : dateFormat.format(new Date(ms));
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes) || bytes < 0) return 'Unknown';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

export function formatCount(value: number, singular: string, plural = `${singular}s`): string {
  return `${value.toLocaleString()} ${value === 1 ? singular : plural}`;
}

/** Whole-number percentage, or null when the denominator is zero. */
export function percent(part: number, whole: number): number | null {
  if (whole <= 0) return null;
  return Math.round((part / whole) * 100);
}

/** First and last characters of a hash for compact display; the full value stays available to copy. */
export function shortHash(hash: string | null | undefined): string {
  if (hash === null || hash === undefined || hash === '') return 'Not available';
  return hash.length > 16 ? `${hash.slice(0, 8)}...${hash.slice(-8)}` : hash;
}

/** Text for an observed fact value (string, number, boolean or null). */
export function formatFactValue(value: string | number | boolean | null): string {
  if (value === null) return 'Not set';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'number') return value.toLocaleString();
  return value;
}

/** Human-readable name of an environment from the fields the collector recorded. */
export function environmentName(env: {
  label?: string | null;
  tenantDisplayName?: string | null;
  primaryDomain?: string | null;
  adForestName?: string | null;
}): string {
  return env.label ?? env.tenantDisplayName ?? env.primaryDomain ?? env.adForestName ?? 'Unnamed environment';
}
