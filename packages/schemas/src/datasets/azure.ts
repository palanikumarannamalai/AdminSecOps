import { z } from 'zod';
import { list, optBool, optNumber, optString } from '../common.js';
import { defineDataset } from './define.js';

const ARM = 'https://management.azure.com';
const READER = 'Azure RBAC: Reader on each assessed subscription (or management group)';

export const azureSubscriptions = defineDataset({
  id: 'azure.subscriptions',
  module: 'Azure',
  technology: 'azure',
  title: 'Subscriptions',
  description: 'Azure subscriptions visible to the collecting account.',
  source: 'AzureResourceManager',
  operations: [`GET ${ARM}/subscriptions?api-version=2022-12-01`],
  permissions: [READER],
  personalData: 'none',
  schema: z.array(
    z.object({
      subscriptionId: z.string(),
      displayName: z.string(),
      state: z.string(),
      tenantId: optString,
    }),
  ),
});

export const azureRoleAssignments = defineDataset({
  id: 'azure.roleAssignments',
  module: 'Azure',
  technology: 'azure',
  title: 'Azure RBAC role assignments',
  description: 'Role assignments at subscription scope and below, with role and principal names resolved.',
  source: 'AzureResourceManager',
  operations: [
    'GET https://management.azure.com/subscriptions/{id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01',
    'GET https://management.azure.com/subscriptions/{id}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01',
    'GET https://graph.microsoft.com/v1.0/directoryObjects/{principalId} (principal name resolution, up to 500 principals)',
  ],
  permissions: [READER, 'Graph: Directory.Read.All (principal name resolution)'],
  personalData: 'identifiers',
  schema: z.array(
    z.object({
      subscriptionId: z.string(),
      roleAssignmentId: z.string(),
      scope: z.string(),
      roleDefinitionName: z.string(),
      roleDefinitionId: optString,
      principalId: z.string(),
      /** User | Group | ServicePrincipal | ForeignGroup | Unknown */
      principalType: z.string(),
      principalDisplayName: optString,
      principalSignInName: optString,
    }),
  ),
});

export const azureDefenderPlans = defineDataset({
  id: 'azure.defenderPlans',
  module: 'Azure',
  technology: 'azure',
  title: 'Microsoft Defender for Cloud plans',
  description: 'Defender for Cloud plan pricing tier per subscription.',
  source: 'AzureResourceManager',
  operations: [`GET ${ARM}/subscriptions/{id}/providers/Microsoft.Security/pricings?api-version=2024-01-01`],
  permissions: [READER],
  personalData: 'none',
  schema: z.array(
    z.object({
      subscriptionId: z.string(),
      name: z.string(),
      /** Free | Standard */
      pricingTier: z.string(),
      subPlan: optString,
    }),
  ),
});

export const azureSecurityContacts = defineDataset({
  id: 'azure.securityContacts',
  module: 'Azure',
  technology: 'azure',
  title: 'Defender for Cloud security contacts',
  description:
    'Security contact notification configuration per subscription. Email addresses are not collected, only whether they are configured.',
  source: 'AzureResourceManager',
  operations: [
    `GET ${ARM}/subscriptions/{id}/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview`,
  ],
  permissions: [READER],
  personalData: 'none',
  schema: z.array(
    z.object({
      subscriptionId: z.string(),
      contacts: list(
        z.object({
          name: z.string(),
          emailCount: z.number().int().nonnegative(),
          isEnabled: optBool,
          notifyRoles: list(z.string()),
          notifyRolesState: optString,
          alertMinimalSeverity: optString,
        }),
      ),
    }),
  ),
});

export const azureStorageAccounts = defineDataset({
  id: 'azure.storageAccounts',
  module: 'Azure',
  technology: 'azure',
  title: 'Storage accounts',
  description: 'Security-relevant storage account properties. Keys and connection strings are never collected.',
  source: 'AzureResourceManager',
  operations: [`GET ${ARM}/subscriptions/{id}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01`],
  permissions: [READER],
  personalData: 'none',
  schema: z.array(
    z.object({
      subscriptionId: z.string(),
      id: z.string(),
      name: z.string(),
      resourceGroup: z.string(),
      location: optString,
      kind: optString,
      allowBlobPublicAccess: optBool,
      supportsHttpsTrafficOnly: optBool,
      minimumTlsVersion: optString,
      allowSharedKeyAccess: optBool,
      publicNetworkAccess: optString,
      networkDefaultAction: optString,
    }),
  ),
});

export const azureKeyVaults = defineDataset({
  id: 'azure.keyVaults',
  module: 'Azure',
  technology: 'azure',
  title: 'Key vaults',
  description: 'Key Vault management-plane properties. Secrets, keys and certificates are never read.',
  source: 'AzureResourceManager',
  operations: [`GET ${ARM}/subscriptions/{id}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01`],
  permissions: [READER],
  personalData: 'none',
  schema: z.array(
    z.object({
      subscriptionId: z.string(),
      id: z.string(),
      name: z.string(),
      resourceGroup: z.string(),
      location: optString,
      enableSoftDelete: optBool,
      softDeleteRetentionInDays: optNumber,
      enablePurgeProtection: optBool,
      enableRbacAuthorization: optBool,
      publicNetworkAccess: optString,
      networkDefaultAction: optString,
    }),
  ),
});

export const NsgRuleSchema = z.object({
  name: z.string(),
  /** Inbound | Outbound */
  direction: z.string(),
  /** Allow | Deny */
  access: z.string(),
  priority: z.number().int(),
  protocol: z.string(),
  sourceAddressPrefix: optString,
  sourceAddressPrefixes: list(z.string()),
  destinationPortRange: optString,
  destinationPortRanges: list(z.string()),
});
export type NsgRule = z.output<typeof NsgRuleSchema>;

export const azureNetworkSecurityGroups = defineDataset({
  id: 'azure.networkSecurityGroups',
  module: 'Azure',
  technology: 'azure',
  title: 'Network security groups',
  description: 'Custom security rules of network security groups (default rules excluded).',
  source: 'AzureResourceManager',
  operations: [`GET ${ARM}/subscriptions/{id}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-09-01`],
  permissions: [READER],
  personalData: 'none',
  schema: z.array(
    z.object({
      subscriptionId: z.string(),
      id: z.string(),
      name: z.string(),
      resourceGroup: z.string(),
      securityRules: list(NsgRuleSchema),
    }),
  ),
});

export const azureActivityLogDiagnostics = defineDataset({
  id: 'azure.activityLogDiagnostics',
  module: 'Azure',
  technology: 'azure',
  title: 'Activity log diagnostic settings',
  description: 'Subscription-level diagnostic settings that export the Azure activity log.',
  source: 'AzureResourceManager',
  operations: [
    `GET ${ARM}/subscriptions/{id}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview`,
  ],
  permissions: [READER],
  personalData: 'none',
  schema: z.array(
    z.object({
      subscriptionId: z.string(),
      settings: list(
        z.object({
          name: z.string(),
          workspaceConfigured: z.boolean(),
          storageAccountConfigured: z.boolean(),
          eventHubConfigured: z.boolean(),
          enabledCategories: list(z.string()),
        }),
      ),
    }),
  ),
});

export const AZURE_DATASETS = [
  azureSubscriptions,
  azureRoleAssignments,
  azureDefenderPlans,
  azureSecurityContacts,
  azureStorageAccounts,
  azureKeyVaults,
  azureNetworkSecurityGroups,
  azureActivityLogDiagnostics,
] as const;
