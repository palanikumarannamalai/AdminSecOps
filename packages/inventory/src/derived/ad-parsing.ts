/**
 * Pure parsing and normalization helpers for Active Directory and AD CS evidence.
 * These functions only reshape collector values (SIDs, host names, rights strings,
 * timestamps); security judgements belong in the controls.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

/** Relative identifier (last sub-authority) of a SID, or '' when the SID is malformed. */
export function sidRid(sid: string): string {
  const parts = sid.trim().split('-');
  return parts.length > 1 ? (parts[parts.length - 1] ?? '') : '';
}

/**
 * Domain portion of a domain-relative SID (S-1-5-21-a-b-c), upper-cased, or null for
 * well-known / builtin SIDs that do not belong to a domain.
 */
export function sidDomainPart(sid: string): string | null {
  const upper = sid.trim().toUpperCase();
  if (!upper.startsWith('S-1-5-21-')) return null;
  const parts = upper.split('-');
  if (parts.length < 8) return null;
  return parts.slice(0, parts.length - 1).join('-');
}

/** Case-insensitive SID equality. */
export function sameSid(a: string | null | undefined, b: string | null | undefined): boolean {
  if (a === null || a === undefined || b === null || b === undefined) return false;
  return a.trim().toUpperCase() === b.trim().toUpperCase();
}

/** Lower-cased first DNS label of a host name ("DC01.contoso.com" -> "dc01"). */
export function hostShortName(hostName: string): string {
  return (hostName.trim().split('.')[0] ?? '').toLowerCase();
}

/**
 * Host name equality that tolerates one side being a short name and the other an FQDN.
 * Two different FQDNs never match even when their first label is equal.
 */
export function hostNamesMatch(a: string, b: string): boolean {
  const la = a.trim().toLowerCase().replace(/\.$/, '');
  const lb = b.trim().toLowerCase().replace(/\.$/, '');
  if (la === lb) return true;
  if (la.includes('.') && lb.includes('.')) return false;
  return hostShortName(la) === hostShortName(lb);
}

/**
 * Whole days elapsed between an ISO timestamp and a reference date (floored). Negative
 * when the timestamp is after the reference date. Returns null for null/invalid input.
 */
export function daysSince(timestamp: string | null, at: Date): number | null {
  if (timestamp === null) return null;
  const ms = Date.parse(timestamp);
  if (Number.isNaN(ms)) return null;
  return Math.floor((at.getTime() - ms) / DAY_MS);
}

/**
 * Normalise ActiveDirectoryRights values. Collectors may emit either separate flags
 * (["ReadProperty","WriteProperty"]) or the .NET flags string ("ReadProperty, WriteProperty").
 * Returns lower-cased, de-duplicated flag names.
 */
export function normalizeAdRights(rights: readonly string[]): string[] {
  const out = new Set<string>();
  for (const entry of rights) {
    for (const part of entry.split(',')) {
      const trimmed = part.trim().toLowerCase();
      if (trimmed.length > 0) out.add(trimmed);
    }
  }
  return [...out];
}

/** Lower-cased GUID of an ACE object type; null/empty means "all objects/properties". */
export const ALL_OBJECTS_GUID = '00000000-0000-0000-0000-000000000000';
export function normalizeObjectType(objectType: string | null): string {
  const trimmed = (objectType ?? '').trim().toLowerCase().replace(/^\{|\}$/g, '');
  return trimmed.length === 0 ? ALL_OBJECTS_GUID : trimmed;
}

/**
 * Index of published certificate template names (lower-cased) to the names of the
 * enterprise CAs that publish them.
 */
export function publishedTemplateIndex(
  authorities: readonly { name: string; certificateTemplates: readonly string[] }[],
): Map<string, string[]> {
  const index = new Map<string, string[]>();
  for (const ca of authorities) {
    for (const template of ca.certificateTemplates) {
      const key = template.trim().toLowerCase();
      if (key.length === 0) continue;
      const cas = index.get(key) ?? [];
      if (!cas.includes(ca.name)) cas.push(ca.name);
      index.set(key, cas);
    }
  }
  return index;
}
