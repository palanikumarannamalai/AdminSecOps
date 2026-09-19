import { collectPrivilegedAccounts, sidRid, type PrivilegedAccount } from '@adminsecops/inventory';
import type { DatasetData } from '@adminsecops/schemas';
import type { ControlContext } from '../../define.js';
import { affected } from '../../helpers.js';

export type AdUser = DatasetData<'ad.users'>['users'][number];
export type AdComputer = DatasetData<'ad.computers'>[number];

/** Display name DOMAIN\\sAMAccountName so multi-domain results are unambiguous. */
export function qualifiedName(domain: string, name: string): string {
  return `${domain}\\${name}`;
}

export function userObject(user: AdUser, detail?: string) {
  return affected('adUser', user.sid, qualifiedName(user.domain, user.samAccountName), detail);
}

export function computerObject(computer: AdComputer, detail?: string) {
  return affected('adComputer', qualifiedName(computer.domain, computer.name), computer.dnsHostName ?? computer.name, detail);
}

/** The KRBTGT account (RID 502) and RODC krbtgt_NNNNN accounts. */
export function isKrbtgtAccount(user: AdUser): boolean {
  const sam = user.samAccountName.toLowerCase();
  return sam === 'krbtgt' || sam.startsWith('krbtgt_') || sidRid(user.sid) === '502';
}

/** Built-in domain Administrator account (RID 500). */
export function isBuiltInAdministrator(sid: string): boolean {
  return sidRid(sid) === '500';
}

/** Privileged accounts from recursive privileged-group membership, keyed by upper-case SID. */
export function privilegedBySid(ctx: ControlContext): Map<string, PrivilegedAccount> {
  const accounts = collectPrivilegedAccounts(ctx.data('ad.privilegedGroups'));
  return new Map(accounts.map((a) => [a.sid.toUpperCase(), a]));
}

export function isPrivileged(map: ReadonlyMap<string, PrivilegedAccount>, sid: string): PrivilegedAccount | undefined {
  return map.get(sid.toUpperCase());
}

/** Privileged SIDs (upper-case) when the optional privileged group evidence is available, otherwise null. */
export function optionalPrivilegedSids(ctx: ControlContext): Set<string> | null {
  const groups = ctx.fact('ad.privilegedGroups');
  if (!groups.available) return null;
  return new Set(collectPrivilegedAccounts(groups.data).map((a) => a.sid.toUpperCase()));
}

export const PRIVILEGED_UNAVAILABLE_NOTE = 'Privileged group evidence was not available, so privileged accounts are not highlighted.';

/** Distinct domains of the objects, sorted, for summaries. */
export function domainsOf(items: readonly { domain: string }[]): string[] {
  return [...new Set(items.map((i) => i.domain.toLowerCase()))].sort();
}

/** Standard note for disabled accounts that carry a risky setting but are not failed. */
export function disabledNote(disabled: readonly AdUser[], setting: string): string[] {
  if (disabled.length === 0) return [];
  const names = disabled.slice(0, 10).map((u) => qualifiedName(u.domain, u.samAccountName));
  return [
    `${disabled.length} disabled account(s) also have ${setting} (${names.join(', ')}${disabled.length > 10 ? ', ...' : ''}). They are not counted as failures because disabled accounts cannot authenticate, but clear the setting before any of them is re-enabled.`,
  ];
}
