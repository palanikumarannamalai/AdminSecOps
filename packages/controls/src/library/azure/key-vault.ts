import type { DatasetData } from '@adminsecops/schemas';
import { defineControl } from '../../define.js';
import { aggregateVerdicts, fail_, pass_ } from '../shared/verdicts.js';
import { resourceSubject } from './common.js';
import { AZ_REF } from './references.js';

type KeyVault = DatasetData<'azure.keyVaults'>[number];

const subject = (v: KeyVault) => resourceSubject('keyVault', v);
const location = (v: KeyVault) => `subscription ${v.subscriptionId}, resource group ${v.resourceGroup}`;
const EMPTY = { status: 'NOT_APPLICABLE' as const, reason: 'No key vaults were found in the assessed subscriptions.' };

export const azKeyVaultPurgeProtection = defineControl({
  id: 'AZ-KV-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Key vaults have purge protection enabled',
  technology: 'azure',
  category: 'Data protection',
  subcategory: 'Key Vault',
  description: 'Checks that every Azure Key Vault has purge protection enabled, so deleted vaults and their keys, secrets and certificates cannot be permanently erased before the retention period ends.',
  rationale:
    'Soft delete lets you recover a deleted vault or object, but without purge protection anyone with sufficient permissions - including an attacker using a compromised administrator account - can purge it immediately. Losing encryption keys can make data encrypted with them (disks, storage, databases) permanently unrecoverable; this is a known ransomware and sabotage technique.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'All Azure key vaults.' },
  requiredEvidence: ['azure.keyVaults'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each key vault: PASS when enablePurgeProtection is true, otherwise FAIL. An unset value (null) is treated as disabled: the Key Vault API only accepts true for this property and omits it when purge protection was never enabled. The detail also notes vaults whose soft delete is reported as disabled.',
    parameters: {},
  },
  expectedState: 'Purge protection (and soft delete) is enabled on every key vault, especially vaults holding customer-managed encryption keys.',
  remediation: {
    summary: 'Enable purge protection on each affected key vault. This change is irreversible by design.',
    steps: [
      'Confirm the vault does not need to be deleted and re-created with the same name in the near future (with purge protection, a deleted vault name stays reserved for the retention period).',
      'In the Azure portal open the key vault > Settings > Properties.',
      'Under Purge protection select "Enable purge protection (enforce a mandatory retention period for deleted vaults and vault objects)" and select Save.',
      'Assign the built-in Azure Policy that requires purge protection on key vaults.',
    ],
    scriptExample: '# Enable purge protection after review (Az PowerShell). Irreversible.\n# Update-AzKeyVault -ResourceGroupName "<rg>" -VaultName "<vault>" -EnablePurgeProtection',
    effort: 'low',
  },
  implementationConsiderations: [
    'Purge protection cannot be turned off once enabled; deleted vaults and objects remain (and count toward names/quotas) until the retention period expires.',
    'Test and development automation that deletes and re-creates vaults with fixed names will fail; use unique names in non-production pipelines.',
    'Services that use customer-managed keys (for example Azure Storage, SQL, Disk Encryption Sets) require purge protection on the key vault.',
  ],
  impact: 'Deleted vaults and objects can only be recovered or expire after the retention period; they can no longer be purged immediately.',
  rollback: ['Purge protection cannot be disabled. If the setting blocks a legitimate process, change the process (for example use different vault names) rather than the vault.'],
  validation: ['Re-run the AdminSecOps Azure collector and confirm AZ-KV-001 is PASS.', 'Key vault > Properties shows purge protection enabled.'],
  references: [AZ_REF.keyVaultRecovery, AZ_REF.keyVaultSoftDelete, AZ_REF.mcsb, AZ_REF.attackDataDestruction],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'CP-9' },
    { framework: 'NIST-800-53r5', id: 'SC-12' },
    { framework: 'MCSB', id: 'DP-8' },
    { framework: 'MITRE-ATTACK', id: 'T1485' },
  ],
  tags: ['key-vault', 'data-protection', 'ransomware-resilience'],
  evaluate: (ctx) =>
    aggregateVerdicts({
      items: ctx.data('azure.keyVaults'),
      subject,
      noun: ['key vault', 'key vaults'],
      requirement: 'purge protection is enabled',
      empty: EMPTY,
      classify: (v) => {
        const softDelete = v.enableSoftDelete === false ? ' Soft delete is also reported as disabled.' : '';
        if (v.enablePurgeProtection === true) return pass_(`Purge protection enabled${v.softDeleteRetentionInDays !== null ? `; retention ${v.softDeleteRetentionInDays} days` : ''}.`);
        return fail_(`Purge protection is not enabled (${location(v)}).${softDelete}`);
      },
    }),
});

export const azKeyVaultRbac = defineControl({
  id: 'AZ-KV-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Key vaults use the Azure RBAC permission model',
  technology: 'azure',
  category: 'Data protection',
  subcategory: 'Key Vault',
  description: 'Checks that every key vault authorizes data-plane access (keys, secrets, certificates) with Azure role-based access control instead of legacy vault access policies.',
  rationale:
    'With access policies, anyone who holds Contributor or Key Vault Contributor on the vault can grant themselves access to every secret by editing the policy, and access cannot be managed with Privileged Identity Management, scoped to individual secrets or governed centrally. Azure RBAC separates management from data access and is Microsoft\'s recommended model.',
  severity: 'low',
  confidence: 'high',
  applicability: { description: 'All Azure key vaults.' },
  requiredEvidence: ['azure.keyVaults'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each key vault: PASS when enableRbacAuthorization is true. FAIL when it is false or not set (null): Microsoft documents that vaults with the property false or null use access policies.',
    parameters: {},
  },
  expectedState: 'Every key vault uses the Azure RBAC permission model, with data-plane roles (for example Key Vault Secrets User) granted at the smallest scope needed.',
  remediation: {
    summary: 'Migrate each affected vault from access policies to Azure RBAC.',
    steps: [
      'Export the current access policies (key vault > Access policies) and map each permission set to a built-in Key Vault data-plane role (for example Key Vault Secrets User, Key Vault Crypto Service Encryption User).',
      'Assign those roles to the same users, groups and managed identities in key vault > Access control (IAM). You need Owner or User Access Administrator (or Role Based Access Control Administrator) to do this.',
      'In key vault > Settings > Access configuration select "Azure role-based access control" and Apply.',
      'Test applications that read from the vault, then remove the obsolete access policies.',
    ],
    scriptExample: '# Switch the permission model after role assignments are in place (Az PowerShell)\n# Update-AzKeyVault -ResourceGroupName "<rg>" -VaultName "<vault>" -EnableRbacAuthorization $true',
    effort: 'medium',
  },
  implementationConsiderations: [
    'Switching the permission model immediately ignores existing access policies; create equivalent role assignments first or applications will lose access.',
    'Role assignments can take several minutes to take effect.',
    'New vaults created with Key Vault API version 2026-02-01 or later default to Azure RBAC; existing vaults keep their model until changed.',
  ],
  impact: 'Data-plane access is governed by Azure role assignments; access policies stop being evaluated.',
  rollback: ['In key vault > Access configuration switch back to "Vault access policy" (existing access policies are still stored and take effect again).'],
  validation: ['Re-run the AdminSecOps Azure collector and confirm AZ-KV-002 is PASS.', 'Confirm applications can still read the secrets they need.'],
  references: [AZ_REF.keyVaultRbacVsAccessPolicies, AZ_REF.keyVaultAccessControlDefault, AZ_REF.mcsb],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-6' },
    { framework: 'NIST-800-53r5', id: 'AC-3' },
    { framework: 'MCSB', id: 'PA-7' },
    { framework: 'MCSB', id: 'DP-8' },
  ],
  tags: ['key-vault', 'azure-rbac', 'least-privilege'],
  evaluate: (ctx) =>
    aggregateVerdicts({
      items: ctx.data('azure.keyVaults'),
      subject,
      noun: ['key vault', 'key vaults'],
      requirement: 'the Azure RBAC permission model is used',
      empty: EMPTY,
      classify: (v) => {
        if (v.enableRbacAuthorization === true) return pass_('Azure RBAC permission model.');
        return fail_(
          `Uses vault access policies (enableRbacAuthorization ${v.enableRbacAuthorization === null ? 'not set' : 'false'}; ${location(v)}).`,
        );
      },
    }),
});
