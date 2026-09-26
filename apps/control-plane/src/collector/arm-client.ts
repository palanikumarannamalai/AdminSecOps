import { GraphClient, parseServiceUrl, type CollectionBudget, type GraphLimits, type ServicePolicy } from './graph-client.js';

/**
 * Azure Resource Manager (ARM) URL policy for the hosted collector.
 *
 * Security properties (in addition to those of the shared bounded client):
 * - Only https://management.azure.com and only the fixed read operations below, each with
 *   its documented api-version. Any other path, provider, api-version or query parameter is
 *   rejected before a request is built, so the ARM token is never sent elsewhere.
 * - A nextLink must keep exactly the path of the first page (same subscription, same
 *   operation) and the same api-version, so a response cannot steer the collector to another
 *   subscription or operation.
 * - GET only; there is no API for any other method. No role assignment, setting or resource
 *   is ever changed.
 */

export const ARM_ORIGIN = 'https://management.azure.com';

const GUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';

/** Read operations and their api-versions (see docs/ONLINE-CONNECTORS.md for sources). */
export const ARM_OPERATIONS = {
  subscriptions: { path: '/subscriptions', apiVersion: '2022-12-01' },
  roleAssignments: { path: '/providers/Microsoft.Authorization/roleAssignments', apiVersion: '2022-04-01' },
  roleDefinitions: { path: '/providers/Microsoft.Authorization/roleDefinitions', apiVersion: '2022-04-01' },
  pricings: { path: '/providers/Microsoft.Security/pricings', apiVersion: '2024-01-01' },
  securityContacts: { path: '/providers/Microsoft.Security/securityContacts', apiVersion: '2023-12-01-preview' },
  storageAccounts: { path: '/providers/Microsoft.Storage/storageAccounts', apiVersion: '2023-05-01' },
  keyVaults: { path: '/providers/Microsoft.KeyVault/vaults', apiVersion: '2023-07-01' },
  networkSecurityGroups: { path: '/providers/Microsoft.Network/networkSecurityGroups', apiVersion: '2023-09-01' },
  diagnosticSettings: { path: '/providers/Microsoft.Insights/diagnosticSettings', apiVersion: '2021-05-01-preview' },
} as const;
export type ArmOperation = keyof typeof ARM_OPERATIONS;

const SUBSCRIPTION_SCOPED = Object.entries(ARM_OPERATIONS).filter(([name]) => name !== 'subscriptions');
const SCOPED_PATH = new RegExp(`^/subscriptions/(${GUID})(/providers/[A-Za-z.]+/[A-Za-z]+)$`);
/** Query parameters ARM uses for paging; anything else is rejected. */
const ALLOWED_QUERY = new Set(['api-version', '$skiptoken', '%24skiptoken']);

/** Api-version that the path is allowed with, or undefined for a path outside the allowlist. */
function apiVersionFor(pathname: string): string | undefined {
  if (pathname === ARM_OPERATIONS.subscriptions.path) return ARM_OPERATIONS.subscriptions.apiVersion;
  const match = SCOPED_PATH.exec(pathname);
  if (match === null) return undefined;
  const suffix = match[2]?.toLowerCase();
  return SUBSCRIPTION_SCOPED.find(([, op]) => op.path.toLowerCase() === suffix)?.[1].apiVersion;
}

/** Validate an ARM URL against the allowlist. Returns the normalised URL, or undefined. */
export function validateArmUrl(raw: unknown): string | undefined {
  const url = parseServiceUrl(raw, ARM_ORIGIN);
  if (url === undefined || url.hostname !== 'management.azure.com') return undefined;
  const expected = apiVersionFor(url.pathname);
  if (expected === undefined) return undefined;
  const keys = [...url.searchParams.keys()];
  if (keys.some((k) => !ALLOWED_QUERY.has(k.toLowerCase())) || new Set(keys.map((k) => k.toLowerCase())).size !== keys.length) return undefined;
  if (url.searchParams.get('api-version') !== expected) return undefined;
  return url.href;
}

/** A nextLink must stay on the path of the first page (case-insensitively) with the same api-version. */
export function validateArmNextLink(raw: unknown, first: string): string | undefined {
  const next = validateArmUrl(raw);
  if (next === undefined) return undefined;
  const a = new URL(next);
  const b = new URL(first);
  return a.pathname.toLowerCase() === b.pathname.toLowerCase() ? next : undefined;
}

export const ARM_POLICY: ServicePolicy = {
  service: 'Azure Resource Manager',
  allowlist: 'Azure Resource Manager read-operation allowlist',
  validate: validateArmUrl,
  validateNext: validateArmNextLink,
  nextLinkProperty: 'nextLink',
  headers: { Accept: 'application/json' },
};

/** URL of an allow-listed operation; subscription-scoped operations need a subscription GUID. */
export function armUrl(operation: ArmOperation, subscriptionId?: string): string | undefined {
  const op = ARM_OPERATIONS[operation];
  if (operation === 'subscriptions') return `${ARM_ORIGIN}${op.path}?api-version=${op.apiVersion}`;
  if (subscriptionId === undefined || !new RegExp(`^${GUID}$`).test(subscriptionId)) return undefined;
  return `${ARM_ORIGIN}/subscriptions/${subscriptionId.toLowerCase()}${op.path}?api-version=${op.apiVersion}`;
}

export function createArmClient(options: {
  accessToken: string;
  fetch: typeof globalThis.fetch;
  signal?: AbortSignal | undefined;
  limits: GraphLimits;
  now: () => number;
  budget: CollectionBudget;
}): GraphClient {
  return new GraphClient({ ...options, policy: ARM_POLICY });
}
