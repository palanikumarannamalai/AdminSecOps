/**
 * Builders for schema-valid Azure evidence (collector-shaped input) used by control tests.
 */
import { nextGuid } from './entra.js';

export const SUB_A = '11111111-1111-4111-8111-111111111111';
export const SUB_B = '22222222-2222-4222-8222-222222222222';

export function subscription(id: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { subscriptionId: id, displayName: `Subscription ${id.slice(0, 4)}`, state: 'Enabled', tenantId: null, ...overrides };
}

export interface RoleAssignmentInput {
  subscriptionId?: string;
  scope?: string;
  role?: string;
  roleDefinitionId?: string | null;
  principalId?: string;
  principalType?: string;
  principalDisplayName?: string | null;
  principalSignInName?: string | null;
}

export function azRoleAssignment(input: RoleAssignmentInput = {}): Record<string, unknown> {
  const subscriptionId = input.subscriptionId ?? SUB_A;
  const principalId = input.principalId ?? nextGuid();
  return {
    subscriptionId,
    roleAssignmentId: `/subscriptions/${subscriptionId}/providers/Microsoft.Authorization/roleAssignments/${nextGuid()}`,
    scope: input.scope ?? `/subscriptions/${subscriptionId}`,
    roleDefinitionName: input.role ?? 'Owner',
    roleDefinitionId: input.roleDefinitionId ?? null,
    principalId,
    principalType: input.principalType ?? 'User',
    principalDisplayName: input.principalDisplayName === undefined ? `Principal ${principalId.slice(-4)}` : input.principalDisplayName,
    principalSignInName: input.principalSignInName === undefined ? `user${principalId.slice(-4)}@contoso.example` : input.principalSignInName,
  };
}

export function defenderPlans(subscriptionId: string, tiers: Record<string, 'Free' | 'Standard'>): Record<string, unknown>[] {
  return Object.entries(tiers).map(([name, pricingTier]) => ({ subscriptionId, name, pricingTier, subPlan: null }));
}

export const ALL_KEY_PLANS_STANDARD = {
  VirtualMachines: 'Standard',
  StorageAccounts: 'Standard',
  KeyVaults: 'Standard',
  Arm: 'Standard',
  CloudPosture: 'Standard',
} as const;

export function securityContact(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: 'default',
    emailCount: 1,
    isEnabled: true,
    notifyRoles: ['Owner'],
    notifyRolesState: 'On',
    alertMinimalSeverity: 'Medium',
    ...overrides,
  };
}

export function storageAccount(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const name = (overrides.name as string | undefined) ?? `st${nextGuid().slice(-6)}`;
  const subscriptionId = (overrides.subscriptionId as string | undefined) ?? SUB_A;
  return {
    subscriptionId,
    id: `/subscriptions/${subscriptionId}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/${name}`,
    name,
    resourceGroup: 'rg',
    location: 'westeurope',
    kind: 'StorageV2',
    allowBlobPublicAccess: false,
    supportsHttpsTrafficOnly: true,
    minimumTlsVersion: 'TLS1_2',
    allowSharedKeyAccess: null,
    publicNetworkAccess: 'Enabled',
    networkDefaultAction: 'Allow',
    ...overrides,
  };
}

export function keyVault(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const name = (overrides.name as string | undefined) ?? `kv${nextGuid().slice(-6)}`;
  const subscriptionId = (overrides.subscriptionId as string | undefined) ?? SUB_A;
  return {
    subscriptionId,
    id: `/subscriptions/${subscriptionId}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/${name}`,
    name,
    resourceGroup: 'rg',
    location: 'westeurope',
    enableSoftDelete: true,
    softDeleteRetentionInDays: 90,
    enablePurgeProtection: true,
    enableRbacAuthorization: true,
    publicNetworkAccess: 'Enabled',
    networkDefaultAction: 'Deny',
    ...overrides,
  };
}

export interface NsgRuleInput {
  name?: string;
  direction?: string;
  access?: string;
  priority?: number;
  protocol?: string;
  source?: string | null;
  sources?: string[];
  port?: string | null;
  ports?: string[];
}

export function nsgRule(input: NsgRuleInput = {}): Record<string, unknown> {
  return {
    name: input.name ?? 'rule',
    direction: input.direction ?? 'Inbound',
    access: input.access ?? 'Allow',
    priority: input.priority ?? 100,
    protocol: input.protocol ?? 'Tcp',
    sourceAddressPrefix: input.source === undefined ? '*' : input.source,
    sourceAddressPrefixes: input.sources ?? [],
    destinationPortRange: input.port === undefined ? '3389' : input.port,
    destinationPortRanges: input.ports ?? [],
  };
}

export function nsg(name: string, rules: Record<string, unknown>[], subscriptionId: string = SUB_A): Record<string, unknown> {
  return {
    subscriptionId,
    id: `/subscriptions/${subscriptionId}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/${name}`,
    name,
    resourceGroup: 'rg',
    securityRules: rules,
  };
}

export function diagnosticSetting(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    name: 'activity-log-export',
    workspaceConfigured: true,
    storageAccountConfigured: false,
    eventHubConfigured: false,
    enabledCategories: ['Administrative', 'Security', 'Policy', 'Alert', 'ServiceHealth'],
    ...overrides,
  };
}
