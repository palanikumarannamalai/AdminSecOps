import type { DatasetData } from '@adminsecops/schemas';

/**
 * Pure normalization helpers for Group Policy evidence (gpo.groupPolicyObjects).
 * They answer "what does this GPO configure and does it apply", never "is that
 * secure" - security judgements stay in the controls.
 *
 * Settings convention (collector contract): entries are {scope, category, name, value}.
 * - SecurityOptions: name is the registry KeyName from the GPO XML report, e.g.
 *   MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel.
 * - RegistryValue (Group Policy Preferences registry items): name is the full path
 *   including the value name, e.g. HKEY_LOCAL_MACHINE\SYSTEM\...\UseLogonCredential.
 * - RegistryPolicy (Administrative Templates): name is the policy display name,
 *   value Enabled | Disabled.
 */
export type GroupPolicyObject = DatasetData<'gpo.groupPolicyObjects'>[number];
export type GroupPolicySetting = GroupPolicyObject['settings'][number];

const HIVE_PREFIXES: readonly [RegExp, string][] = [
  [/^hkey_local_machine\\/, 'hklm\\'],
  [/^machine\\/, 'hklm\\'],
  [/^hklm:?\\/, 'hklm\\'],
  [/^hkey_current_user\\/, 'hkcu\\'],
  [/^user\\/, 'hkcu\\'],
  [/^hkcu:?\\/, 'hkcu\\'],
];

/**
 * Canonical, case-insensitive form of a registry path. Tolerates the MACHINE\ prefix used
 * in GPO security option reports, HKEY_LOCAL_MACHINE\ / HKLM\ / HKLM:\ prefixes,
 * forward slashes and repeated or trailing separators.
 */
export function normalizeRegistryPath(path: string): string {
  let value = path.trim().replace(/\//g, '\\').replace(/\\{2,}/g, '\\').replace(/\\$/, '').toLowerCase();
  for (const [pattern, replacement] of HIVE_PREFIXES) {
    if (pattern.test(value)) {
      value = value.replace(pattern, replacement);
      break;
    }
  }
  return value;
}

export function registryPathEquals(a: string, b: string): boolean {
  return normalizeRegistryPath(a) === normalizeRegistryPath(b);
}

/** Links that are enabled (a disabled link does not apply the GPO). */
export function enabledGpoLinks(gpo: GroupPolicyObject): GroupPolicyObject['links'] {
  return gpo.links.filter((link) => link.enabled);
}

/** True when the GPO has at least one enabled link to a site, domain or OU. */
export function isGpoLinked(gpo: GroupPolicyObject): boolean {
  return enabledGpoLinks(gpo).length > 0;
}

function status(gpo: GroupPolicyObject): string {
  return gpo.gpoStatus.trim().toLowerCase();
}

/** Computer Configuration of the GPO is processed (not disabled via GPO status). */
export function gpoComputerSettingsEnabled(gpo: GroupPolicyObject): boolean {
  const s = status(gpo);
  return s !== 'computersettingsdisabled' && s !== 'allsettingsdisabled';
}

/** User Configuration of the GPO is processed (not disabled via GPO status). */
export function gpoUserSettingsEnabled(gpo: GroupPolicyObject): boolean {
  const s = status(gpo);
  return s !== 'usersettingsdisabled' && s !== 'allsettingsdisabled';
}

/**
 * True when the GPO's Computer Configuration can apply to some computer: it has an
 * enabled link and its computer settings are not disabled. Security filtering and WMI
 * filters are not evaluated (they can only narrow the scope further).
 */
export function gpoAppliesToComputers(gpo: GroupPolicyObject): boolean {
  return isGpoLinked(gpo) && gpoComputerSettingsEnabled(gpo);
}

function isComputerScope(setting: GroupPolicySetting): boolean {
  return setting.scope.trim().toLowerCase() === 'computer';
}

/** Computer-scope settings whose name is the given registry path (any category). */
export function gpoRegistrySettings(gpo: GroupPolicyObject, registryPath: string): GroupPolicySetting[] {
  const target = normalizeRegistryPath(registryPath);
  return gpo.settings.filter((s) => isComputerScope(s) && normalizeRegistryPath(s.name) === target);
}

/** Computer-scope settings in a category whose name matches (case-insensitive exact or predicate). */
export function gpoNamedSettings(
  gpo: GroupPolicyObject,
  category: string,
  name: string | ((name: string) => boolean),
): GroupPolicySetting[] {
  const cat = category.toLowerCase();
  const match = typeof name === 'string' ? (n: string) => n.trim().toLowerCase() === name.toLowerCase() : name;
  return gpo.settings.filter((s) => isComputerScope(s) && s.category.trim().toLowerCase() === cat && match(s.name));
}

/** Numeric interpretation of a setting value (number or numeric string); null otherwise. */
export function settingNumber(value: GroupPolicySetting['value']): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && /^\s*-?\d+\s*$/.test(value)) return Number(value.trim());
  return null;
}

/** Enabled/Disabled interpretation of an Administrative Template value; null otherwise. */
export function settingEnabledState(value: GroupPolicySetting['value']): 'Enabled' | 'Disabled' | null {
  if (typeof value === 'boolean') return value ? 'Enabled' : 'Disabled';
  if (typeof value !== 'string') return null;
  const v = value.trim().toLowerCase();
  if (v === 'enabled') return 'Enabled';
  if (v === 'disabled') return 'Disabled';
  return null;
}
