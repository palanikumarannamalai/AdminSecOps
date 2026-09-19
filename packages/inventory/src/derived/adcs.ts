import type { TemplateAce } from '@adminsecops/schemas';

/** Extended key usage / application policy OIDs relevant to authentication. */
export const EKU = {
  clientAuthentication: '1.3.6.1.5.5.7.3.2',
  pkinitClientAuthentication: '1.3.6.1.5.2.3.4',
  smartCardLogon: '1.3.6.1.4.1.311.20.2.2',
  anyPurpose: '2.5.29.37.0',
  certificateRequestAgent: '1.3.6.1.4.1.311.20.2.1',
} as const;

/** Certificate template flag bits. */
export const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1;
export const CT_FLAG_PEND_ALL_REQUESTS = 0x2;

/** Extended rights GUIDs. */
export const ENROLL_RIGHT_GUID = '0e10c968-78fb-11d2-90d4-00c04f79dc55';
export const AUTOENROLL_RIGHT_GUID = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2';
const ALL_OBJECTS_GUID = '00000000-0000-0000-0000-000000000000';

/**
 * Well-known low-privileged principals. Domain Users (-513) and Domain Computers (-515)
 * are matched by RID for any domain SID.
 */
export const LOW_PRIVILEGED_SIDS: Readonly<Record<string, string>> = {
  'S-1-1-0': 'Everyone',
  'S-1-5-11': 'Authenticated Users',
  'S-1-5-32-545': 'Users',
  'S-1-5-7': 'Anonymous Logon',
};
const LOW_PRIVILEGED_RIDS = new Set(['513', '515', '514']);

export function isLowPrivilegedPrincipal(sid: string | null, name: string): boolean {
  if (sid !== null) {
    const upper = sid.toUpperCase();
    if (upper in LOW_PRIVILEGED_SIDS) return true;
    const rid = upper.split('-').pop() ?? '';
    if (upper.startsWith('S-1-5-21-') && LOW_PRIVILEGED_RIDS.has(rid)) return true;
    return false;
  }
  // Fall back to name matching only when the SID could not be resolved by the collector.
  const lower = name.toLowerCase();
  return ['everyone', 'authenticated users', 'domain users', 'domain computers', 'builtin\\users'].some((n) =>
    lower.endsWith(n),
  );
}

function hasRight(ace: TemplateAce, right: string): boolean {
  return ace.rights.some((r) => r.toLowerCase() === right.toLowerCase());
}

function objectTypeIs(ace: TemplateAce, guid: string): boolean {
  return (ace.objectType ?? ALL_OBJECTS_GUID).toLowerCase() === guid;
}

/** ACE grants the Enroll (or AutoEnroll) right, including via GenericAll or all extended rights. */
export function aceGrantsEnroll(ace: TemplateAce): boolean {
  if (ace.accessControlType.toLowerCase() !== 'allow') return false;
  if (hasRight(ace, 'GenericAll')) return true;
  if (!hasRight(ace, 'ExtendedRight')) return false;
  return objectTypeIs(ace, ALL_OBJECTS_GUID) || objectTypeIs(ace, ENROLL_RIGHT_GUID) || objectTypeIs(ace, AUTOENROLL_RIGHT_GUID);
}

/** ACE grants rights that allow modifying the template object or its permissions. */
export function aceGrantsWrite(ace: TemplateAce): string[] {
  if (ace.accessControlType.toLowerCase() !== 'allow') return [];
  const dangerous = ['GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner'];
  const granted = dangerous.filter((right) => hasRight(ace, right));
  if (hasRight(ace, 'WriteProperty') && objectTypeIs(ace, ALL_OBJECTS_GUID)) granted.push('WriteProperty');
  return granted;
}

/** Template EKUs allow client authentication (or any purpose / no EKU restriction). */
export function authenticationCapable(ekus: readonly string[]): { capable: boolean; reason: string } {
  if (ekus.length === 0) return { capable: true, reason: 'no EKU restriction (usable for any purpose)' };
  if (ekus.includes(EKU.anyPurpose)) return { capable: true, reason: 'Any Purpose EKU' };
  const auth = [EKU.clientAuthentication, EKU.pkinitClientAuthentication, EKU.smartCardLogon].filter((e) => ekus.includes(e));
  if (auth.length > 0) return { capable: true, reason: 'client authentication EKU' };
  return { capable: false, reason: 'no authentication EKU' };
}
