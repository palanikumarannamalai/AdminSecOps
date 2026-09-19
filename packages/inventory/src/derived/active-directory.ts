import type { DatasetData } from '@adminsecops/schemas';
import type { Fact, Inventory } from '../inventory.js';

/**
 * Privileged built-in groups by relative identifier (domain SID + RID) or builtin SID.
 * Membership in these groups grants control of the domain or forest directly or through
 * well-documented escalation paths. Source: Microsoft "Appendix B: Privileged accounts
 * and groups in Active Directory".
 */
export const PRIVILEGED_GROUP_RIDS: Readonly<Record<string, string>> = {
  '512': 'Domain Admins',
  '518': 'Schema Admins',
  '519': 'Enterprise Admins',
  '526': 'Key Admins',
  '527': 'Enterprise Key Admins',
};

export const PRIVILEGED_BUILTIN_SIDS: Readonly<Record<string, string>> = {
  'S-1-5-32-544': 'Administrators',
  'S-1-5-32-548': 'Account Operators',
  'S-1-5-32-549': 'Server Operators',
  'S-1-5-32-550': 'Print Operators',
  'S-1-5-32-551': 'Backup Operators',
};

export function isPrivilegedGroupSid(sid: string): boolean {
  const upper = sid.toUpperCase();
  if (upper in PRIVILEGED_BUILTIN_SIDS) return true;
  const rid = upper.split('-').pop() ?? '';
  return upper.startsWith('S-1-5-21-') && rid in PRIVILEGED_GROUP_RIDS;
}

export interface PrivilegedAccount {
  domain: string;
  samAccountName: string;
  sid: string;
  objectClass: string;
  groups: string[];
}

/** Accounts that are (recursively) members of a privileged built-in group. */
export function privilegedAdAccounts(inventory: Inventory): Fact<PrivilegedAccount[]> {
  const groups = inventory.get('ad.privilegedGroups');
  if (!groups.available) return groups;
  return { ...groups, data: collectPrivilegedAccounts(groups.data) };
}

export function collectPrivilegedAccounts(groups: DatasetData<'ad.privilegedGroups'>): PrivilegedAccount[] {
  const bySid = new Map<string, PrivilegedAccount>();
  for (const group of groups) {
    if (!isPrivilegedGroupSid(group.groupSid)) continue;
    for (const member of group.members) {
      const key = member.sid.toUpperCase();
      const existing = bySid.get(key);
      if (existing === undefined) {
        bySid.set(key, {
          domain: group.domain,
          samAccountName: member.samAccountName,
          sid: member.sid,
          objectClass: member.objectClass,
          groups: [group.groupName],
        });
      } else if (!existing.groups.includes(group.groupName)) {
        existing.groups.push(group.groupName);
      }
    }
  }
  return [...bySid.values()].sort((a, b) => a.samAccountName.localeCompare(b.samAccountName));
}

/** Domain/forest functional level ordering (Get-ADDomain DomainMode values). */
const FUNCTIONAL_LEVELS = [
  'Windows2000',
  'Windows2003Interim',
  'Windows2003',
  'Windows2008',
  'Windows2008R2',
  'Windows2012',
  'Windows2012R2',
  'Windows2016',
  'Windows2025',
] as const;

/** Rank of a functional level string such as "Windows2016Domain"; -1 when unknown. */
export function functionalLevelRank(mode: string): number {
  const base = mode.replace(/(Domain|Forest)$/i, '');
  return FUNCTIONAL_LEVELS.findIndex((level) => level.toLowerCase() === base.toLowerCase());
}
