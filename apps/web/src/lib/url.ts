/**
 * Returns the normalized URL when it is an absolute https URL, otherwise null.
 * Used for every external link rendered from API data so that javascript:, data:
 * and plain http links are never rendered as clickable.
 */
export function safeHttpsUrl(value: string | null | undefined): string | null {
  if (typeof value !== 'string' || value.length > 2000) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username !== '' || url.password !== '') return null;
    return url.href;
  } catch {
    return null;
  }
}
