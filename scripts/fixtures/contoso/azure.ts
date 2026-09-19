/**
 * Contoso - Azure datasets.
 *
 * Intended state: two subscriptions; production has five Owners including a guest;
 * Defender for Cloud plans mostly Free; one storage account allows anonymous blob
 * access, one has the property unset (null) and one still accepts TLS 1.0; one key
 * vault without purge protection; an NSG that allows RDP (3389) from the Internet;
 * the activity log is exported for production only.
 */
import {
  type azureActivityLogDiagnostics,
  type azureDefenderPlans,
  type azureKeyVaults,
  type azureNetworkSecurityGroups,
  type azureRoleAssignments,
  type azureSecurityContacts,
  type azureStorageAccounts,
  type azureSubscriptions,
} from '@adminsecops/schemas';
import type { z } from 'zod';
import { guid } from '../common.js';
import { APP, GUEST_AZURE_OWNER } from './entra.js';
import { GROUPS, TENANT_ID, USERS, type CloudUser } from './identity.js';

type In<D extends { schema: z.ZodType }> = z.input<D['schema']>;
type RoleAssignment = In<typeof azureRoleAssignments>[number];

export interface ContosoAzureData {
  subscriptions: In<typeof azureSubscriptions>;
  roleAssignments: RoleAssignment[];
  defenderPlans: In<typeof azureDefenderPlans>;
  securityContacts: In<typeof azureSecurityContacts>;
  storageAccounts: In<typeof azureStorageAccounts>;
  keyVaults: In<typeof azureKeyVaults>;
  networkSecurityGroups: In<typeof azureNetworkSecurityGroups>;
  activityLogDiagnostics: In<typeof azureActivityLogDiagnostics>;
}

export const SUB_PROD = guid('contoso:subscription:production');
export const SUB_DEV = guid('contoso:subscription:devtest');

/** Built-in Azure RBAC role definition IDs (identical in every tenant). */
const AZ_ROLE = {
  Owner: '8e3af657-a8ff-443c-a75c-2fe8c4bcb635',
  Contributor: 'b24988ac-6180-42a0-ab88-20f7382dd24c',
  Reader: 'acdd72a7-3385-48ef-bd42-f606fba81ae7',
  'User Access Administrator': '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9',
} as const;

type AzRoleName = keyof typeof AZ_ROLE;

const DEFENDER_PLAN_NAMES = [
  'VirtualMachines',
  'SqlServers',
  'AppServices',
  'StorageAccounts',
  'KeyVaults',
  'Arm',
  'Containers',
  'CloudPosture',
] as const;

function rbac(
  subscriptionId: string,
  role: AzRoleName,
  principal: { id: string; type: string; displayName: string; signInName: string | null },
  scopeSuffix = '',
): RoleAssignment {
  const scope = `/subscriptions/${subscriptionId}${scopeSuffix}`;
  const assignmentGuid = guid(`contoso:azrbac:${scope}:${role}:${principal.id}`);
  return {
    subscriptionId,
    roleAssignmentId: `${scope}/providers/Microsoft.Authorization/roleAssignments/${assignmentGuid}`,
    scope,
    roleDefinitionName: role,
    roleDefinitionId: `/subscriptions/${subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/${AZ_ROLE[role]}`,
    principalId: principal.id,
    principalType: principal.type,
    principalDisplayName: principal.displayName,
    principalSignInName: principal.signInName,
  };
}

const asUser = (u: CloudUser) => ({ id: u.id, type: 'User', displayName: u.displayName, signInName: u.userPrincipalName });

function storageId(sub: string, rg: string, name: string): string {
  return `/subscriptions/${sub}/resourceGroups/${rg}/providers/Microsoft.Storage/storageAccounts/${name}`;
}

export function contosoAzure(): ContosoAzureData {
  const guestOwner = {
    id: GUEST_AZURE_OWNER.id,
    type: 'User',
    displayName: 'Morgan Cloud (Partner Co)',
    signInName: GUEST_AZURE_OWNER.userPrincipalName,
  };
  const provisioningSp = { id: APP.provisioning.sp, type: 'ServicePrincipal', displayName: 'Contoso Provisioning Automation', signInName: null };
  const automationMi = { id: guid('contoso:sp:mi-automation'), type: 'ServicePrincipal', displayName: 'aa-contoso-prod-automation', signInName: null };
  const readers = { id: GROUPS.azureReaders.id, type: 'Group', displayName: GROUPS.azureReaders.displayName, signInName: null };
  const devTeam = { id: guid('contoso:group:dev-team'), type: 'Group', displayName: 'SG-Developers', signInName: null };

  return {
    subscriptions: [
      { subscriptionId: SUB_PROD, displayName: 'Contoso Production', state: 'Enabled', tenantId: TENANT_ID },
      { subscriptionId: SUB_DEV, displayName: 'Contoso Dev/Test', state: 'Enabled', tenantId: TENANT_ID },
    ],
    roleAssignments: [
      rbac(SUB_PROD, 'Owner', asUser(USERS.alexAdmin)),
      rbac(SUB_PROD, 'Owner', asUser(USERS.taylorOps)),
      rbac(SUB_PROD, 'Owner', asUser(USERS.jordanIt)),
      rbac(SUB_PROD, 'Owner', asUser(USERS.caseyExec)),
      rbac(SUB_PROD, 'Owner', guestOwner),
      rbac(SUB_PROD, 'Contributor', provisioningSp, '/resourceGroups/rg-identity-automation'),
      rbac(SUB_PROD, 'Contributor', automationMi),
      rbac(SUB_PROD, 'Reader', readers),
      rbac(SUB_DEV, 'Owner', asUser(USERS.alexAdmin)),
      rbac(SUB_DEV, 'Owner', asUser(USERS.jamieApps)),
      rbac(SUB_DEV, 'Contributor', devTeam),
      rbac(SUB_DEV, 'User Access Administrator', asUser(USERS.taylorOps)),
    ],
    defenderPlans: [SUB_PROD, SUB_DEV].flatMap((subscriptionId) =>
      DEFENDER_PLAN_NAMES.map((name) =>
        // Only Defender for Servers Plan 1 on production is enabled; everything else is Free.
        subscriptionId === SUB_PROD && name === 'VirtualMachines'
          ? { subscriptionId, name, pricingTier: 'Standard', subPlan: 'P1' }
          : { subscriptionId, name, pricingTier: 'Free', subPlan: null },
      ),
    ),
    securityContacts: [
      {
        subscriptionId: SUB_PROD,
        contacts: [
          {
            name: 'default',
            emailCount: 1,
            isEnabled: true,
            notifyRoles: ['Owner'],
            notifyRolesState: 'On',
            alertMinimalSeverity: 'High',
          },
        ],
      },
      { subscriptionId: SUB_DEV, contacts: [] },
    ],
    storageAccounts: [
      {
        subscriptionId: SUB_PROD,
        id: storageId(SUB_PROD, 'rg-web-prod', 'stcontosowebprod'),
        name: 'stcontosowebprod',
        resourceGroup: 'rg-web-prod',
        location: 'westeurope',
        kind: 'StorageV2',
        allowBlobPublicAccess: true,
        supportsHttpsTrafficOnly: true,
        minimumTlsVersion: 'TLS1_2',
        allowSharedKeyAccess: true,
        publicNetworkAccess: 'Enabled',
        networkDefaultAction: 'Allow',
      },
      {
        subscriptionId: SUB_PROD,
        id: storageId(SUB_PROD, 'rg-logging-prod', 'stcontosologsprod'),
        name: 'stcontosologsprod',
        resourceGroup: 'rg-logging-prod',
        location: 'westeurope',
        kind: 'StorageV2',
        allowBlobPublicAccess: false,
        supportsHttpsTrafficOnly: true,
        minimumTlsVersion: 'TLS1_2',
        allowSharedKeyAccess: false,
        publicNetworkAccess: 'Disabled',
        networkDefaultAction: 'Deny',
      },
      {
        subscriptionId: SUB_DEV,
        id: storageId(SUB_DEV, 'rg-data-dev', 'stcontosodevdata'),
        name: 'stcontosodevdata',
        resourceGroup: 'rg-data-dev',
        location: 'northeurope',
        kind: 'Storage',
        allowBlobPublicAccess: null,
        supportsHttpsTrafficOnly: true,
        minimumTlsVersion: 'TLS1_0',
        allowSharedKeyAccess: true,
        publicNetworkAccess: 'Enabled',
        networkDefaultAction: 'Allow',
      },
    ],
    keyVaults: [
      {
        subscriptionId: SUB_PROD,
        id: `/subscriptions/${SUB_PROD}/resourceGroups/rg-security-prod/providers/Microsoft.KeyVault/vaults/kv-contoso-prod`,
        name: 'kv-contoso-prod',
        resourceGroup: 'rg-security-prod',
        location: 'westeurope',
        enableSoftDelete: true,
        softDeleteRetentionInDays: 90,
        enablePurgeProtection: true,
        enableRbacAuthorization: true,
        publicNetworkAccess: 'Disabled',
        networkDefaultAction: 'Deny',
      },
      {
        subscriptionId: SUB_DEV,
        id: `/subscriptions/${SUB_DEV}/resourceGroups/rg-apps-dev/providers/Microsoft.KeyVault/vaults/kv-contoso-dev`,
        name: 'kv-contoso-dev',
        resourceGroup: 'rg-apps-dev',
        location: 'northeurope',
        enableSoftDelete: true,
        softDeleteRetentionInDays: 90,
        enablePurgeProtection: null,
        enableRbacAuthorization: false,
        publicNetworkAccess: 'Enabled',
        networkDefaultAction: 'Allow',
      },
    ],
    networkSecurityGroups: [
      {
        subscriptionId: SUB_PROD,
        id: `/subscriptions/${SUB_PROD}/resourceGroups/rg-web-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web-prod`,
        name: 'nsg-web-prod',
        resourceGroup: 'rg-web-prod',
        securityRules: [
          {
            name: 'Allow-HTTPS-Inbound',
            direction: 'Inbound',
            access: 'Allow',
            priority: 100,
            protocol: 'Tcp',
            sourceAddressPrefix: 'Internet',
            sourceAddressPrefixes: [],
            destinationPortRange: '443',
            destinationPortRanges: [],
          },
        ],
      },
      {
        subscriptionId: SUB_PROD,
        id: `/subscriptions/${SUB_PROD}/resourceGroups/rg-mgmt-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-mgmt-prod`,
        name: 'nsg-mgmt-prod',
        resourceGroup: 'rg-mgmt-prod',
        securityRules: [
          {
            name: 'Allow-RDP-Temp',
            direction: 'Inbound',
            access: 'Allow',
            priority: 300,
            protocol: 'Tcp',
            sourceAddressPrefix: 'Internet',
            sourceAddressPrefixes: [],
            destinationPortRange: '3389',
            destinationPortRanges: [],
          },
          {
            name: 'Allow-SSH-Admin-Office',
            direction: 'Inbound',
            access: 'Allow',
            priority: 310,
            protocol: 'Tcp',
            sourceAddressPrefix: null,
            sourceAddressPrefixes: ['203.0.113.0/27', '198.51.100.14/32'],
            destinationPortRange: '22',
            destinationPortRanges: [],
          },
        ],
      },
      {
        subscriptionId: SUB_DEV,
        id: `/subscriptions/${SUB_DEV}/resourceGroups/rg-apps-dev/providers/Microsoft.Network/networkSecurityGroups/nsg-apps-dev`,
        name: 'nsg-apps-dev',
        resourceGroup: 'rg-apps-dev',
        securityRules: [
          {
            name: 'Allow-AppGateway',
            direction: 'Inbound',
            access: 'Allow',
            priority: 200,
            protocol: 'Tcp',
            sourceAddressPrefix: 'GatewayManager',
            sourceAddressPrefixes: [],
            destinationPortRange: null,
            destinationPortRanges: ['65200-65535'],
          },
          {
            name: 'Deny-All-Inbound',
            direction: 'Inbound',
            access: 'Deny',
            priority: 4000,
            protocol: '*',
            sourceAddressPrefix: '*',
            sourceAddressPrefixes: [],
            destinationPortRange: '*',
            destinationPortRanges: [],
          },
        ],
      },
    ],
    activityLogDiagnostics: [
      {
        subscriptionId: SUB_PROD,
        settings: [
          {
            name: 'export-activity-to-law',
            workspaceConfigured: true,
            storageAccountConfigured: false,
            eventHubConfigured: false,
            enabledCategories: ['Administrative', 'Security', 'ServiceHealth', 'Alert', 'Recommendation', 'Policy', 'Autoscale', 'ResourceHealth'],
          },
        ],
      },
      { subscriptionId: SUB_DEV, settings: [] },
    ],
  };
}
