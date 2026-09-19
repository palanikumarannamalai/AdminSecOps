import type { ControlStatus, Technology } from '@adminsecops/core';
import { CONTROL_STATUSES, TECHNOLOGY_LABELS } from '@adminsecops/core/vocabulary';
import type { AssessmentSummary, StatusCounts } from '@adminsecops/schemas';

/** Dashboard modules group the engine's technologies into the areas administrators think in. */
export const DASHBOARD_MODULES = [
  { id: 'm365', label: 'Microsoft 365', technologies: ['m365'] },
  { id: 'entra', label: 'Entra ID', technologies: ['entra', 'hybrid'] },
  { id: 'azure', label: 'Azure', technologies: ['azure'] },
  { id: 'intune', label: 'Intune', technologies: ['intune'] },
  { id: 'ad', label: 'Active Directory', technologies: ['ad', 'adcs'] },
  { id: 'windows', label: 'Windows', technologies: ['windows', 'gpo'] },
] as const satisfies readonly { id: string; label: string; technologies: readonly Technology[] }[];

export type DashboardModuleId = (typeof DASHBOARD_MODULES)[number]['id'];

export const MODULE_IDS: readonly DashboardModuleId[] = DASHBOARD_MODULES.map((m) => m.id);

const MODULE_BY_TECHNOLOGY: Record<Technology, DashboardModuleId> = {
  m365: 'm365',
  entra: 'entra',
  hybrid: 'entra',
  azure: 'azure',
  intune: 'intune',
  ad: 'ad',
  adcs: 'ad',
  windows: 'windows',
  gpo: 'windows',
};

export function moduleForTechnology(technology: Technology): DashboardModuleId {
  return MODULE_BY_TECHNOLOGY[technology];
}

export function moduleLabel(id: DashboardModuleId): string {
  return DASHBOARD_MODULES.find((m) => m.id === id)?.label ?? id;
}

export function isDashboardModuleId(value: string): value is DashboardModuleId {
  return (MODULE_IDS as readonly string[]).includes(value);
}

/** Display label of an engine technology, e.g. "AD CS / PKI". */
export function technologyLabel(technology: Technology): string {
  return TECHNOLOGY_LABELS[technology];
}

export function emptyStatusCounts(): StatusCounts {
  return { PASS: 0, FAIL: 0, REVIEW: 0, NOT_APPLICABLE: 0, NOT_ASSESSED: 0, ERROR: 0 };
}

export interface ModuleCard {
  id: DashboardModuleId;
  label: string;
  technologies: readonly Technology[];
  counts: StatusCounts;
  /** Total control results for this module. */
  total: number;
  /** Controls with a PASS, FAIL or REVIEW result. */
  assessed: number;
  /** True when no control in this module could be assessed (no evidence collected). */
  notCollected: boolean;
}

/** Summarize `summary.byTechnology` into one card per dashboard module. */
export function buildModuleCards(summary: AssessmentSummary): ModuleCard[] {
  return DASHBOARD_MODULES.map((module) => {
    const counts = emptyStatusCounts();
    for (const technology of module.technologies) {
      const byTech = summary.byTechnology[technology];
      if (byTech === undefined) continue;
      for (const status of CONTROL_STATUSES) counts[status] += byTech[status] ?? 0;
    }
    const total = CONTROL_STATUSES.reduce((sum, s: ControlStatus) => sum + counts[s], 0);
    const assessed = counts.PASS + counts.FAIL + counts.REVIEW;
    return {
      id: module.id,
      label: module.label,
      technologies: module.technologies,
      counts,
      total,
      assessed,
      notCollected: assessed === 0,
    };
  });
}
