/**
 * Builders for schema-valid Group Policy evidence (collector-shaped input) used by control tests.
 */
import { nextGuid } from './entra.js';

export interface GpoInput {
  id?: string;
  displayName?: string;
  gpoStatus?: string;
  links?: { somPath: string; enabled: boolean; enforced?: boolean }[];
  settings?: Record<string, unknown>[];
  modifiedTime?: string | null;
}

export function gpo(input: GpoInput = {}): Record<string, unknown> {
  return {
    id: input.id ?? nextGuid(),
    displayName: input.displayName ?? 'Test GPO',
    domain: 'corp.contoso.example',
    gpoStatus: input.gpoStatus ?? 'AllSettingsEnabled',
    createdTime: '2024-01-01T00:00:00Z',
    modifiedTime: input.modifiedTime === undefined ? '2025-06-01T00:00:00Z' : input.modifiedTime,
    wmiFilter: null,
    links: (input.links ?? [{ somPath: 'corp.contoso.example', enabled: true }]).map((l) => ({ enforced: false, ...l })),
    settings: input.settings ?? [],
  };
}

export function setting(category: string, name: string, value: unknown, scope = 'Computer'): Record<string, unknown> {
  return { scope, category, name, value };
}

export const LMCOMPAT_KEY = 'MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel';
export const WDIGEST_KEY = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential';

export function sysvolScan(artifacts: Record<string, unknown>[] = [], filesScanned = 12): Record<string, unknown> {
  return { filesScanned, artifacts };
}

export function gppArtifact(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    domain: 'corp.contoso.example',
    gpoId: null,
    relativePath: '{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine\\Preferences\\Groups\\Groups.xml',
    fileName: 'Groups.xml',
    ...overrides,
  };
}
