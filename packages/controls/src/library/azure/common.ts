import type { ControlContext } from '../../define.js';
import type { Subject } from '../shared/verdicts.js';

export interface SubscriptionRef {
  id: string;
  name: string;
}

const INACTIVE_STATES = new Set(['disabled', 'deleted']);

/**
 * Subscriptions to evaluate for a per-subscription control: every subscription that
 * appears in the control's dataset plus every active subscription listed in
 * azure.subscriptions (optional evidence). A subscription known only from
 * azure.subscriptions is evaluated as "not reported" by the control, never as compliant.
 * Result is sorted by subscription ID for deterministic output.
 */
export function subscriptionUniverse(ctx: ControlContext, idsFromDataset: Iterable<string>): SubscriptionRef[] {
  const names = new Map<string, SubscriptionRef>();
  const subscriptions = ctx.fact('azure.subscriptions');
  if (subscriptions.available) {
    for (const s of subscriptions.data) {
      if (INACTIVE_STATES.has(s.state.trim().toLowerCase())) continue;
      names.set(s.subscriptionId.toLowerCase(), { id: s.subscriptionId, name: s.displayName });
    }
  }
  for (const id of idsFromDataset) {
    const key = id.toLowerCase();
    if (!names.has(key)) names.set(key, { id, name: subscriptionDisplayName(ctx, id) });
  }
  return [...names.values()].sort((a, b) => a.id.localeCompare(b.id));
}

/** Display name of a subscription from azure.subscriptions when available, else the ID. */
export function subscriptionDisplayName(ctx: ControlContext, id: string): string {
  const subscriptions = ctx.fact('azure.subscriptions');
  if (!subscriptions.available) return id;
  return subscriptions.data.find((s) => s.subscriptionId.toLowerCase() === id.toLowerCase())?.displayName ?? id;
}

export function subscriptionSubject(ref: SubscriptionRef): Subject {
  return { type: 'subscription', id: `/subscriptions/${ref.id}`, name: ref.name };
}

export function sameId(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

/** Subject for an ARM resource (storage account, key vault, NSG). */
export function resourceSubject(type: string, resource: { id: string; name: string }): Subject {
  return { type, id: resource.id, name: resource.name };
}
