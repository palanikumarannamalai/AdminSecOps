import type { Reference } from '@adminsecops/schemas';

/**
 * Azure-specific references. Every URL was checked on Microsoft Learn / the publisher's
 * site when added. Titles are paraphrased; no third-party text is copied.
 */
const ms = (title: string, url: string): Reference => ({ title, url, publisher: 'Microsoft' });
const mitre = (title: string, url: string): Reference => ({ title, url, publisher: 'MITRE' });
const LEARN = 'https://learn.microsoft.com/en-us';

export const AZ_REF = {
  storageTlsRetirement: ms('Azure Blob Storage TLS 1.0 and 1.1 retirement', `${LEARN}/azure/storage/common/transport-layer-security-configure-migrate-to-tls2`),
  rbacBestPractices: ms('Best practices for Azure RBAC', `${LEARN}/azure/role-based-access-control/best-practices`),
  rbacBuiltInRoles: ms('Azure built-in roles', `${LEARN}/azure/role-based-access-control/built-in-roles`),
  defenderIdentityRecommendations: ms(
    'Identity and access recommendations in Microsoft Defender for Cloud',
    `${LEARN}/azure/defender-for-cloud/recommendations-reference-identity-access`,
  ),
  defenderIntroduction: ms('What is Microsoft Defender for Cloud?', `${LEARN}/azure/defender-for-cloud/defender-for-cloud-introduction`),
  defenderEnablePlans: ms(
    'Connect your Azure subscriptions and enable Defender plans',
    `${LEARN}/azure/defender-for-cloud/connect-azure-subscription`,
  ),
  defenderEmailNotifications: ms(
    'Configure email notifications for Defender for Cloud alerts and attack paths',
    `${LEARN}/azure/defender-for-cloud/configure-email-notifications`,
  ),
  storageAnonymousAccess: ms(
    'Remediate anonymous read access to blob data (Azure Resource Manager deployments)',
    `${LEARN}/azure/storage/blobs/anonymous-read-access-prevent`,
  ),
  storageSecureTransfer: ms(
    'Require secure transfer to ensure secure connections to Azure Storage',
    `${LEARN}/azure/storage/common/storage-require-secure-transfer`,
  ),
  storageMinimumTls: ms(
    'Enforce a minimum required version of TLS for requests to a storage account',
    `${LEARN}/azure/storage/common/transport-layer-security-configure-minimum-version`,
  ),
  keyVaultSoftDelete: ms('Azure Key Vault soft-delete overview', `${LEARN}/azure/key-vault/general/soft-delete-overview`),
  keyVaultRecovery: ms(
    'Azure Key Vault recovery management with soft delete and purge protection',
    `${LEARN}/azure/key-vault/general/key-vault-recovery`,
  ),
  keyVaultRbacVsAccessPolicies: ms(
    'Azure role-based access control (Azure RBAC) vs. access policies for Key Vault',
    `${LEARN}/azure/key-vault/general/rbac-access-policy`,
  ),
  keyVaultAccessControlDefault: ms(
    'Plan for Azure RBAC as the default access control model in Key Vault',
    `${LEARN}/azure/key-vault/general/access-control-default`,
  ),
  nsgOverview: ms('Azure network security groups overview', `${LEARN}/azure/virtual-network/network-security-groups-overview`),
  justInTimeAccess: ms(
    'Just-in-time machine access in Microsoft Defender for Cloud',
    `${LEARN}/azure/defender-for-cloud/just-in-time-access-overview`,
  ),
  bastionOverview: ms('What is Azure Bastion?', `${LEARN}/azure/bastion/bastion-overview`),
  activityLog: ms('Azure Monitor activity log', `${LEARN}/azure/azure-monitor/platform/activity-log`),
  diagnosticSettings: ms('Diagnostic settings in Azure Monitor', `${LEARN}/azure/azure-monitor/platform/diagnostic-settings`),
  mcsb: ms('Overview of the Microsoft cloud security benchmark', `${LEARN}/security/benchmark/azure/introduction`),

  attackCloudStorage: mitre('MITRE ATT&CK T1530: Data from Cloud Storage', 'https://attack.mitre.org/techniques/T1530/'),
  attackExternalRemoteServices: mitre('MITRE ATT&CK T1133: External Remote Services', 'https://attack.mitre.org/techniques/T1133/'),
  attackRdp: mitre('MITRE ATT&CK T1021.001: Remote Desktop Protocol', 'https://attack.mitre.org/techniques/T1021/001/'),
  attackSsh: mitre('MITRE ATT&CK T1021.004: SSH', 'https://attack.mitre.org/techniques/T1021/004/'),
  attackBruteForce: mitre('MITRE ATT&CK T1110: Brute Force', 'https://attack.mitre.org/techniques/T1110/'),
  attackDisableCloudLogs: mitre(
    'MITRE ATT&CK T1562.008: Impair Defenses: Disable or Modify Cloud Logs',
    'https://attack.mitre.org/techniques/T1562/008/',
  ),
  attackDataDestruction: mitre('MITRE ATT&CK T1485: Data Destruction', 'https://attack.mitre.org/techniques/T1485/'),
} as const satisfies Record<string, Reference>;
