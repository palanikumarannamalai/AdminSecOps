import type { DatasetData } from '@adminsecops/schemas';
import { defineControl } from '../../define.js';
import { eqi } from '../../helpers.js';
import { aggregateVerdicts, fail_, na_, pass_, unknown_ } from '../shared/verdicts.js';
import { resourceSubject } from './common.js';
import { AZ_REF } from './references.js';

type StorageAccount = DatasetData<'azure.storageAccounts'>[number];

const subject = (a: StorageAccount) => resourceSubject('storageAccount', a);
const location = (a: StorageAccount) => `subscription ${a.subscriptionId}, resource group ${a.resourceGroup}`;
const EMPTY = { status: 'NOT_APPLICABLE' as const, reason: 'No storage accounts were found in the assessed subscriptions.' };

export const azStorageNoAnonymousBlob = defineControl({
  id: 'AZ-STG-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Storage accounts disallow anonymous blob access',
  technology: 'azure',
  category: 'Data protection',
  subcategory: 'Storage accounts',
  description:
    'Checks that every storage account with a Blob service explicitly disallows anonymous (public) read access to blobs and containers (AllowBlobPublicAccess = false).',
  rationale:
    'When a storage account permits anonymous access, anyone who can modify a container can make its contents readable by the whole internet without authentication. Misconfigured public containers are a recurring cause of data leaks. Disallowing anonymous access at the account level overrides every container setting and removes this risk.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'Azure storage accounts that provide Blob storage (FileStorage accounts are not applicable).' },
  requiredEvidence: ['azure.storageAccounts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each storage account: NOT_APPLICABLE when kind is FileStorage (no Blob service). PASS when allowBlobPublicAccess is false. FAIL when it is true, or when it is not set (null): Microsoft treats an unset property as not disallowing anonymous access, and its own remediation script and Azure Policy definition flag unset accounts. The control does not read container-level settings, so a FAIL means anonymous access is possible, not that a container is currently public.',
    parameters: {},
  },
  expectedState: 'AllowBlobPublicAccess is explicitly set to false on every storage account; data that must be public is served from a dedicated, documented account or through a CDN with authentication to the origin.',
  remediation: {
    summary: 'Set "Allow Blob anonymous access" to Disabled on each affected storage account after confirming no application relies on anonymous reads.',
    steps: [
      'For each affected account, check whether any client reads blobs anonymously: in the Azure portal open the storage account > Monitoring > Metrics, metric Transactions, filter Authentication = Anonymous.',
      'If anonymous reads are required (for example public website assets), move that content to a dedicated storage account and document the exception.',
      'Open the storage account > Settings > Configuration, set "Allow Blob anonymous access" to Disabled and select Save.',
      'Assign the built-in Azure Policy that denies storage accounts allowing anonymous access, so new accounts stay compliant.',
    ],
    scriptExample:
      '# Review first: list accounts that do not explicitly disallow anonymous access (Az PowerShell)\nGet-AzStorageAccount | Where-Object { $_.AllowBlobPublicAccess -ne $false } |\n  Select-Object StorageAccountName, ResourceGroupName, AllowBlobPublicAccess\n# Remediate one account after review\n# Set-AzStorageAccount -ResourceGroupName "<rg>" -Name "<account>" -AllowBlobPublicAccess $false',
    effort: 'low',
  },
  implementationConsiderations: [
    'Disallowing anonymous access immediately breaks clients that read public containers without credentials; check metrics and logs first.',
    'Static websites hosted from the $web container are not affected by this setting.',
    'Clients that use a SAS token, account key or Microsoft Entra ID are not affected.',
  ],
  impact: 'Anonymous read requests to blobs and containers in the account fail; authenticated access is unchanged.',
  rollback: ['Set "Allow Blob anonymous access" back to Enabled on the storage account Configuration page (containers keep their previous access level).'],
  validation: [
    'Re-run the AdminSecOps Azure collector and confirm AZ-STG-001 is PASS.',
    'In Azure Resource Graph, query storage accounts and confirm allowBlobPublicAccess is false for all of them.',
  ],
  references: [AZ_REF.storageAnonymousAccess, AZ_REF.mcsb, AZ_REF.attackCloudStorage],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-3' },
    { framework: 'NIST-800-53r5', id: 'AC-14' },
    { framework: 'MCSB', id: 'NS-2' },
    { framework: 'MITRE-ATTACK', id: 'T1530' },
  ],
  tags: ['storage', 'internet-exposure', 'data-protection'],
  evaluate: (ctx) =>
    aggregateVerdicts({
      items: ctx.data('azure.storageAccounts'),
      subject,
      noun: ['storage account', 'storage accounts'],
      requirement: 'anonymous blob access is explicitly disallowed',
      empty: EMPTY,
      classify: (a) => {
        if (eqi(a.kind, 'FileStorage')) return na_('FileStorage account without a Blob service.');
        const network = eqi(a.publicNetworkAccess, 'Disabled') ? ' Public network access is disabled, which limits exposure.' : '';
        if (a.allowBlobPublicAccess === false) return pass_('Anonymous blob access is disallowed.');
        if (a.allowBlobPublicAccess === true) return fail_(`Anonymous blob access is allowed (${location(a)}).${network}`);
        return fail_(`AllowBlobPublicAccess is not set, which does not disallow anonymous access (${location(a)}).${network}`);
      },
    }),
});

export const azStorageSecureTransfer = defineControl({
  id: 'AZ-STG-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Storage accounts require secure transfer (HTTPS)',
  technology: 'azure',
  category: 'Data protection',
  subcategory: 'Storage accounts',
  description: 'Checks that every storage account has "Secure transfer required" enabled (supportsHttpsTrafficOnly = true), so requests over plain HTTP and unencrypted SMB are rejected.',
  rationale:
    'Requests over HTTP travel unencrypted, exposing data and shared access signatures to anyone who can observe the network path. Requiring secure transfer ensures data and credentials in transit are protected by TLS.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'All Azure storage accounts.' },
  requiredEvidence: ['azure.storageAccounts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each storage account: PASS when supportsHttpsTrafficOnly is true, FAIL when it is false. When the property is missing from the evidence the account cannot be evaluated and is reported for review (never PASS).',
    parameters: {},
  },
  expectedState: 'Secure transfer required is Enabled on every storage account.',
  remediation: {
    summary: 'Enable "Secure transfer required" on each affected storage account.',
    steps: [
      'Identify clients that still use http:// endpoints (storage logs record the protocol) and update them to https://.',
      'In the Azure portal open the storage account > Settings > Configuration, set "Secure transfer required" to Enabled and select Save.',
      'Assign the built-in Azure Policy that audits or denies storage accounts without secure transfer.',
    ],
    scriptExample: '# Remediate one account after review (Az PowerShell)\n# Set-AzStorageAccount -ResourceGroupName "<rg>" -Name "<account>" -EnableHttpsTrafficOnly $true',
    effort: 'low',
  },
  implementationConsiderations: [
    'Azure Files over SMB without encryption (for example SMB 2.1 clients) stops working when secure transfer is required.',
    'Custom domain names over HTTPS for blob endpoints need Azure Front Door or a CDN; plain custom domains only support HTTP.',
  ],
  impact: 'HTTP requests and unencrypted SMB connections to the account are rejected.',
  rollback: ['Set "Secure transfer required" to Disabled on the storage account Configuration page.'],
  validation: ['Re-run the AdminSecOps Azure collector and confirm AZ-STG-002 is PASS.', 'Confirm an http:// request to the blob endpoint is rejected.'],
  references: [AZ_REF.storageSecureTransfer, AZ_REF.mcsb],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SC-8' },
    { framework: 'NIST-800-53r5', id: 'SC-8(1)' },
    { framework: 'MCSB', id: 'DP-3' },
  ],
  tags: ['storage', 'encryption-in-transit', 'data-protection'],
  evaluate: (ctx) =>
    aggregateVerdicts({
      items: ctx.data('azure.storageAccounts'),
      subject,
      noun: ['storage account', 'storage accounts'],
      requirement: 'secure transfer (HTTPS) is required',
      empty: EMPTY,
      classify: (a) => {
        if (a.supportsHttpsTrafficOnly === true) return pass_('Secure transfer is required.');
        if (a.supportsHttpsTrafficOnly === false) return fail_(`Secure transfer is not required; HTTP is accepted (${location(a)}).`);
        return unknown_('supportsHttpsTrafficOnly was not reported.');
      },
    }),
});

const MODERN_TLS = new Set(['tls1_2', 'tls1_3']);
const LEGACY_TLS = new Set(['tls1_0', 'tls1_1']);

export const azStorageMinimumTls = defineControl({
  id: 'AZ-STG-003',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Storage accounts require TLS 1.2 or later',
  technology: 'azure',
  category: 'Data protection',
  subcategory: 'Storage accounts',
  description: 'Checks that every storage account sets its minimum TLS version to TLS 1.2 or later.',
  rationale:
    'TLS 1.0 and 1.1 have known weaknesses. Setting the minimum TLS version on the account ensures that, whatever the platform default, the account itself rejects legacy protocol versions and satisfies Azure Policy and audit requirements.',
  severity: 'low',
  confidence: 'high',
  applicability: { description: 'All Azure storage accounts.' },
  requiredEvidence: ['azure.storageAccounts'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each storage account: PASS when minimumTlsVersion is TLS1_2 or TLS1_3. FAIL when it is TLS1_0 or TLS1_1, or when it is not set (null or empty): Microsoft documents that an account without the property accepts TLS 1.0 or later. An unrecognized value cannot be evaluated and is reported for review.',
    parameters: {},
  },
  expectedState: 'Minimum TLS version is TLS 1.2 on every storage account.',
  remediation: {
    summary: 'Set the minimum TLS version to TLS 1.2 on each affected storage account.',
    steps: [
      'Check storage logs (StorageBlobLogs TlsVersion) for clients still using TLS 1.0/1.1 and update them.',
      'In the Azure portal open the storage account > Settings > Configuration, set "Minimum TLS version" to Version 1.2 and select Save.',
      'Assign the built-in Azure Policy that requires a minimum TLS version for storage accounts.',
    ],
    scriptExample: '# Remediate one account after review (Az PowerShell)\n# Set-AzStorageAccount -ResourceGroupName "<rg>" -Name "<account>" -MinimumTlsVersion TLS1_2',
    effort: 'low',
  },
  implementationConsiderations: [
    'Microsoft Learn states that Azure Storage now supports only TLS 1.2 and 1.3 for requests, so the practical risk of an unset value is lower than in the past; the account setting remains the documented control and is what Azure Policy evaluates. Severity is therefore low.',
    'Very old clients (for example .NET Framework applications without TLS 1.2 enabled) must be updated before enforcement.',
  ],
  impact: 'Requests using TLS versions older than the configured minimum are rejected.',
  rollback: ['Change "Minimum TLS version" back to the previous value on the storage account Configuration page.'],
  validation: ['Re-run the AdminSecOps Azure collector and confirm AZ-STG-003 is PASS.'],
  references: [AZ_REF.storageMinimumTls, AZ_REF.mcsb],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SC-8(1)' },
    { framework: 'NIST-800-53r5', id: 'SC-13' },
    { framework: 'MCSB', id: 'DP-3' },
  ],
  tags: ['storage', 'tls', 'encryption-in-transit'],
  evaluate: (ctx) =>
    aggregateVerdicts({
      items: ctx.data('azure.storageAccounts'),
      subject,
      noun: ['storage account', 'storage accounts'],
      requirement: 'the minimum TLS version is 1.2 or later',
      empty: EMPTY,
      classify: (a) => {
        const value = (a.minimumTlsVersion ?? '').trim().toLowerCase();
        if (MODERN_TLS.has(value)) return pass_(`Minimum TLS version ${a.minimumTlsVersion ?? ''}.`);
        if (LEGACY_TLS.has(value)) return fail_(`Minimum TLS version is ${a.minimumTlsVersion ?? ''} (${location(a)}).`);
        if (value === '') return fail_(`Minimum TLS version is not set, which permits TLS 1.0 and later (${location(a)}).`);
        return unknown_(`Unrecognized minimum TLS version "${a.minimumTlsVersion ?? ''}".`);
      },
    }),
});
