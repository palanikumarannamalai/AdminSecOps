import type { DatasetData } from '@adminsecops/schemas';
import type { Fact, Inventory } from '../inventory.js';

/** Service plan names used for applicability decisions. */
export const SERVICE_PLANS = {
  entraIdP1: 'AAD_PREMIUM',
  entraIdP2: 'AAD_PREMIUM_P2',
  intune: 'INTUNE_A',
  defenderForOffice365P1: 'ATP_ENTERPRISE',
  defenderForOffice365P2: 'THREAT_INTELLIGENCE',
} as const;

export interface LicenceView {
  hasServicePlan(servicePlanName: string): boolean;
  hasAnyServicePlan(servicePlanNames: readonly string[]): boolean;
}

/**
 * A service plan counts as licensed when its SKU is Enabled or in Warning (grace)
 * state, at least one unit is enabled, and the plan is not Disabled.
 */
export function licenceView(skus: DatasetData<'entra.subscribedSkus'>): LicenceView {
  const active = new Set<string>();
  for (const sku of skus) {
    if (!['Enabled', 'Warning'].includes(sku.capabilityStatus)) continue;
    if (sku.prepaidUnits.enabled <= 0) continue;
    for (const plan of sku.servicePlans) {
      if (plan.provisioningStatus !== 'Disabled') active.add(plan.servicePlanName.toUpperCase());
    }
  }
  return {
    hasServicePlan: (name) => active.has(name.toUpperCase()),
    hasAnyServicePlan: (names) => names.some((n) => active.has(n.toUpperCase())),
  };
}

export function tenantLicences(inventory: Inventory): Fact<LicenceView> {
  const skus = inventory.get('entra.subscribedSkus');
  if (!skus.available) return skus;
  return { ...skus, data: licenceView(skus.data) };
}
