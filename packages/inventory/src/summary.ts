import type { Technology } from '@adminsecops/core';
import { listDatasetDefinitions, type DatasetAvailability, type DatasetId, type InventoryItem } from '@adminsecops/schemas';
import type { Inventory } from './inventory.js';

interface ItemSpec {
  technology: Technology;
  key: string;
  label: string;
  datasetId: DatasetId;
  count: (inventory: Inventory) => number | null;
}

function arrayCount(id: DatasetId) {
  return (inventory: Inventory): number | null => {
    const fact = inventory.get(id);
    return fact.available && Array.isArray(fact.data) ? fact.data.length : null;
  };
}

const ITEMS: readonly ItemSpec[] = [
  { technology: 'entra', key: 'caPolicies', label: 'Conditional Access policies', datasetId: 'entra.conditionalAccessPolicies', count: arrayCount('entra.conditionalAccessPolicies') },
  { technology: 'entra', key: 'roleAssignments', label: 'Active directory role assignments', datasetId: 'entra.roleAssignments', count: arrayCount('entra.roleAssignments') },
  { technology: 'entra', key: 'registeredUsers', label: 'Users in MFA registration report', datasetId: 'entra.userRegistrationDetails', count: arrayCount('entra.userRegistrationDetails') },
  { technology: 'entra', key: 'guests', label: 'Guest users', datasetId: 'entra.guestUsers', count: arrayCount('entra.guestUsers') },
  { technology: 'entra', key: 'applications', label: 'App registrations', datasetId: 'entra.applications', count: arrayCount('entra.applications') },
  { technology: 'entra', key: 'servicePrincipals', label: 'Service principals', datasetId: 'entra.servicePrincipals', count: arrayCount('entra.servicePrincipals') },
  { technology: 'm365', key: 'acceptedDomains', label: 'Accepted domains', datasetId: 'exchange.acceptedDomains', count: arrayCount('exchange.acceptedDomains') },
  { technology: 'm365', key: 'forwardingMailboxes', label: 'Mailboxes with forwarding', datasetId: 'exchange.mailboxForwarding', count: arrayCount('exchange.mailboxForwarding') },
  {
    technology: 'intune',
    key: 'enrolledDevices',
    label: 'Enrolled devices',
    datasetId: 'intune.deviceOverview',
    count: (inv) => {
      const fact = inv.get('intune.deviceOverview');
      return fact.available ? fact.data.enrolledDeviceCount : null;
    },
  },
  { technology: 'intune', key: 'compliancePolicies', label: 'Compliance policies', datasetId: 'intune.compliancePolicies', count: arrayCount('intune.compliancePolicies') },
  { technology: 'azure', key: 'subscriptions', label: 'Subscriptions', datasetId: 'azure.subscriptions', count: arrayCount('azure.subscriptions') },
  { technology: 'azure', key: 'rbacAssignments', label: 'RBAC role assignments', datasetId: 'azure.roleAssignments', count: arrayCount('azure.roleAssignments') },
  { technology: 'azure', key: 'storageAccounts', label: 'Storage accounts', datasetId: 'azure.storageAccounts', count: arrayCount('azure.storageAccounts') },
  { technology: 'azure', key: 'keyVaults', label: 'Key vaults', datasetId: 'azure.keyVaults', count: arrayCount('azure.keyVaults') },
  { technology: 'azure', key: 'nsgs', label: 'Network security groups', datasetId: 'azure.networkSecurityGroups', count: arrayCount('azure.networkSecurityGroups') },
  { technology: 'ad', key: 'domains', label: 'Domains', datasetId: 'ad.domains', count: arrayCount('ad.domains') },
  { technology: 'ad', key: 'domainControllers', label: 'Domain controllers', datasetId: 'ad.domainControllers', count: arrayCount('ad.domainControllers') },
  {
    technology: 'ad',
    key: 'enabledUsers',
    label: 'Enabled user accounts',
    datasetId: 'ad.users',
    count: (inv) => {
      const fact = inv.get('ad.users');
      return fact.available ? fact.data.domains.reduce((sum, d) => sum + d.enabledUsers, 0) : null;
    },
  },
  { technology: 'ad', key: 'computers', label: 'Computer accounts', datasetId: 'ad.computers', count: arrayCount('ad.computers') },
  { technology: 'ad', key: 'trusts', label: 'Trusts', datasetId: 'ad.trusts', count: arrayCount('ad.trusts') },
  { technology: 'adcs', key: 'cas', label: 'Enterprise CAs', datasetId: 'adcs.certificateAuthorities', count: arrayCount('adcs.certificateAuthorities') },
  { technology: 'adcs', key: 'templates', label: 'Certificate templates', datasetId: 'adcs.certificateTemplates', count: arrayCount('adcs.certificateTemplates') },
  { technology: 'gpo', key: 'gpos', label: 'Group Policy objects', datasetId: 'gpo.groupPolicyObjects', count: arrayCount('gpo.groupPolicyObjects') },
  { technology: 'windows', key: 'hosts', label: 'Assessed Windows hosts', datasetId: 'windows.hosts', count: arrayCount('windows.hosts') },
];

/** Environment inventory counts for the dashboard. Null counts mean "not collected". */
export function summarizeInventory(inventory: Inventory): InventoryItem[] {
  return ITEMS.map((item) => ({
    technology: item.technology,
    key: item.key,
    label: item.label,
    datasetId: item.datasetId,
    count: item.count(inventory),
  }));
}

/** Availability of every known dataset, for the evidence and not-assessed views. */
export function datasetAvailability(inventory: Inventory): DatasetAvailability[] {
  const loaded = new Map(inventory.loadedDatasets().map((d) => [d.datasetId, d]));
  return listDatasetDefinitions().map((definition) => {
    const dataset = loaded.get(definition.id);
    if (dataset === undefined) {
      return {
        datasetId: definition.id,
        title: definition.title,
        technology: definition.technology,
        module: definition.module,
        state: 'unavailable' as const,
        collectionStatus: null,
        reason: `Not present in the evidence package (collector module ${definition.module} not run or dataset not collected).`,
      };
    }
    return {
      datasetId: definition.id,
      title: definition.title,
      technology: definition.technology,
      module: definition.module,
      state: dataset.state,
      collectionStatus: dataset.collectionStatus,
      reason: dataset.reason,
    };
  });
}
