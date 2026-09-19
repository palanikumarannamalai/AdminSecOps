/**
 * Contoso sample environment: a ~500-user hybrid organisation that is "partly
 * secured". `contosoData` returns the typed payloads; `contosoEnvironment` turns
 * them into an evidence package description, including the collection states
 * (Unauthorized, Partial, NotCollected, NotApplicable) the UI should demonstrate.
 */
import {
  adComputers,
  adDomainControllerSettings,
  adDomainControllers,
  adDomains,
  adForest,
  adKrbtgt,
  adPasswordPolicies,
  adPrivilegedGroups,
  adTrusts,
  adUsers,
  adcsCertificateAuthorities,
  adcsCertificateTemplates,
  azureActivityLogDiagnostics,
  azureDefenderPlans,
  azureKeyVaults,
  azureNetworkSecurityGroups,
  azureRoleAssignments,
  azureSecurityContacts,
  azureStorageAccounts,
  azureSubscriptions,
  entraApiPermissionGrants,
  entraApplications,
  entraAuthenticationMethodsPolicy,
  entraAuthorizationPolicy,
  entraConditionalAccessPolicies,
  entraGroupSettings,
  entraGuestUsers,
  entraOnPremisesSynchronization,
  entraOrganization,
  entraRoleAssignmentScheduleInstances,
  entraRoleAssignments,
  entraRoleDefinitions,
  entraRoleEligibilitySchedules,
  entraSecurityDefaults,
  entraServicePrincipals,
  entraSubscribedSkus,
  entraUserRegistrationDetails,
  exchangeAcceptedDomains,
  exchangeAdminAuditLogConfig,
  exchangeAtpPolicy,
  exchangeDkimSigningConfigs,
  exchangeMailboxForwarding,
  exchangeMailDnsRecords,
  exchangeOrganizationConfig,
  exchangeOutboundSpamPolicies,
  exchangeRemoteDomains,
  exchangeSmtpAuthMailboxes,
  exchangeTransportConfig,
  gpoGroupPolicyObjects,
  gpoSysvolPasswordArtifacts,
  intuneCompliancePolicies,
  intuneDeviceOverview,
  intuneSettings,
  m365SharePointSettings,
  windowsHosts,
} from '@adminsecops/schemas';
import {
  type Clock,
  type DatasetFixture,
  type EnvironmentFixture,
  type ModuleRun,
  collected,
  message,
  uncollected,
} from '../common.js';
import { type ContosoAzureData, contosoAzure } from './azure.js';
import { type ContosoEntraData, contosoEntra } from './entra.js';
import { AD_DOMAIN, PRIMARY_DOMAIN, TENANT_ID } from './identity.js';
import { type ContosoM365Data, contosoM365 } from './m365.js';
import { type ContosoOnPremData, contosoOnPrem } from './onprem.js';

export interface ContosoData {
  entra: ContosoEntraData;
  m365: ContosoM365Data;
  azure: ContosoAzureData;
  onPrem: ContosoOnPremData;
}

export function contosoData(clock: Clock): ContosoData {
  return { entra: contosoEntra(clock), m365: contosoM365(), azure: contosoAzure(), onPrem: contosoOnPrem(clock) };
}

export interface ContosoVariant {
  directory: string;
  assessmentId: string;
  clock: Clock;
  label: string;
  /** false: the collecting account lacked the directory role, dataset reported Unauthorized. */
  onPremisesSynchronizationCollected: boolean;
  /** true: Graph paging failed part-way through the service principal listing. */
  servicePrincipalsPartial: boolean;
}

const GRAPH = 'https://graph.microsoft.com/v1.0';

export function contosoEnvironment(data: ContosoData, variant: ContosoVariant): EnvironmentFixture {
  const { entra, m365, azure, onPrem } = data;

  const servicePrincipals = variant.servicePrincipalsPartial
    ? collected(entraServicePrincipals, entra.servicePrincipals, {
        partial: true,
        errors: [
          message(
            'GRAPH_PAGING_FAILED',
            'Page 3 of the service principal listing failed with HTTP 503 (Service Unavailable) after 3 retries. Service principals after page 2 were not collected.',
            `GET ${GRAPH}/servicePrincipals`,
          ),
        ],
      })
    : collected(entraServicePrincipals, entra.servicePrincipals);

  const onPremSync = variant.onPremisesSynchronizationCollected
    ? collected(entraOnPremisesSynchronization, entra.onPremisesSynchronization)
    : uncollected(entraOnPremisesSynchronization, 'Unauthorized', {
        errors: [
          message(
            'UNAUTHORIZED',
            'Microsoft Graph returned 403 Forbidden. Reading directory synchronization settings requires the signed-in account to hold the Global Administrator or Hybrid Identity Administrator role; the collecting account holds Global Reader.',
            `GET ${GRAPH}/directory/onPremisesSynchronization`,
          ),
        ],
      });

  const datasets: DatasetFixture[] = [
    collected(entraOrganization, entra.organization),
    collected(entraSubscribedSkus, entra.subscribedSkus),
    collected(entraSecurityDefaults, entra.securityDefaults),
    collected(entraAuthorizationPolicy, entra.authorizationPolicy),
    collected(entraConditionalAccessPolicies, entra.conditionalAccessPolicies),
    collected(entraRoleDefinitions, entra.roleDefinitions),
    collected(entraRoleAssignments, entra.roleAssignments),
    collected(entraRoleAssignmentScheduleInstances, entra.roleAssignmentScheduleInstances),
    collected(entraRoleEligibilitySchedules, entra.roleEligibilitySchedules),
    collected(entraUserRegistrationDetails, entra.userRegistrationDetails),
    collected(entraAuthenticationMethodsPolicy, entra.authenticationMethodsPolicy),
    collected(entraApplications, entra.applications),
    servicePrincipals,
    collected(entraApiPermissionGrants, entra.apiPermissionGrants),
    collected(entraGroupSettings, entra.groupSettings),
    collected(entraGuestUsers, entra.guestUsers),
    onPremSync,

    collected(exchangeOrganizationConfig, m365.organizationConfig),
    collected(exchangeTransportConfig, m365.transportConfig),
    collected(exchangeAdminAuditLogConfig, m365.adminAuditLogConfig),
    collected(exchangeAcceptedDomains, m365.acceptedDomains),
    collected(exchangeDkimSigningConfigs, m365.dkimSigningConfigs),
    collected(exchangeOutboundSpamPolicies, m365.outboundSpamPolicies),
    collected(exchangeRemoteDomains, m365.remoteDomains),
    collected(exchangeMailboxForwarding, m365.mailboxForwarding),
    collected(exchangeSmtpAuthMailboxes, m365.smtpAuthMailboxes),
    uncollected(exchangeAtpPolicy, 'NotApplicable', {
      warnings: [
        message(
          'PREREQUISITE_NOT_LICENSED',
          'Microsoft Defender for Office 365 (Plan 1 or Plan 2) is not licensed in this tenant, so Get-AtpPolicyForO365 is not available.',
          'Get-AtpPolicyForO365',
        ),
      ],
    }),
    collected(exchangeMailDnsRecords, m365.mailDnsRecords),
    collected(m365SharePointSettings, m365.sharePointSettings),

    collected(intuneSettings, m365.intuneSettings),
    collected(intuneDeviceOverview, m365.intuneDeviceOverview),
    collected(intuneCompliancePolicies, m365.intuneCompliancePolicies),

    collected(azureSubscriptions, azure.subscriptions),
    collected(azureRoleAssignments, azure.roleAssignments),
    collected(azureDefenderPlans, azure.defenderPlans),
    collected(azureSecurityContacts, azure.securityContacts),
    collected(azureStorageAccounts, azure.storageAccounts),
    collected(azureKeyVaults, azure.keyVaults),
    collected(azureNetworkSecurityGroups, azure.networkSecurityGroups),
    collected(azureActivityLogDiagnostics, azure.activityLogDiagnostics),

    collected(adForest, onPrem.forest),
    collected(adDomains, onPrem.domains),
    collected(adPasswordPolicies, onPrem.passwordPolicies),
    collected(adPrivilegedGroups, onPrem.privilegedGroups),
    collected(adUsers, onPrem.users),
    collected(adKrbtgt, onPrem.krbtgt),
    collected(adComputers, onPrem.computers),
    collected(adTrusts, onPrem.trusts),
    collected(adDomainControllers, onPrem.domainControllers),
    uncollected(adDomainControllerSettings, 'NotCollected', {
      warnings: [
        message(
          'OPTION_NOT_SELECTED',
          'Domain controller registry settings were not collected because -IncludeDomainControllerSettings was not specified.',
        ),
      ],
    }),

    collected(adcsCertificateAuthorities, onPrem.certificateAuthorities),
    collected(adcsCertificateTemplates, onPrem.certificateTemplates),

    collected(gpoGroupPolicyObjects, onPrem.groupPolicyObjects),
    collected(gpoSysvolPasswordArtifacts, onPrem.sysvolPasswordArtifacts),
    collected(windowsHosts, onPrem.windowsHosts),
  ];

  const entraIncomplete = datasets.filter(
    (d) => d.definition.module === 'Entra' && d.status !== 'Success',
  ).length;

  const graphPrereqs = [
    { name: 'Microsoft.Graph.Authentication module', satisfied: true, detail: '2.25.0' },
    { name: 'Delegated sign-in (Global Reader)', satisfied: true, detail: null },
  ];
  const modules: ModuleRun[] = [
    {
      module: 'Entra',
      status: entraIncomplete > 0 ? 'CompletedWithErrors' : 'Completed',
      startedOffset: -34,
      completedOffset: -29,
      prerequisites: graphPrereqs,
      warnings:
        entraIncomplete > 0
          ? [message('MODULE_INCOMPLETE', `${entraIncomplete} of 17 Entra datasets were not fully collected; see the dataset errors.`)]
          : [],
    },
    { module: 'M365', status: 'Completed', startedOffset: -29, completedOffset: -28, prerequisites: graphPrereqs },
    {
      module: 'Exchange',
      status: 'Completed',
      startedOffset: -28,
      completedOffset: -24,
      prerequisites: [
        { name: 'ExchangeOnlineManagement module', satisfied: true, detail: '3.7.1' },
        { name: 'View-Only Organization Management', satisfied: true, detail: null },
      ],
    },
    { module: 'Intune', status: 'Completed', startedOffset: -24, completedOffset: -23, prerequisites: graphPrereqs },
    {
      module: 'Azure',
      status: 'Completed',
      startedOffset: -23,
      completedOffset: -17,
      prerequisites: [
        { name: 'Az.Accounts module', satisfied: true, detail: '4.0.2' },
        { name: 'Reader on assessed subscriptions', satisfied: true, detail: '2 subscriptions' },
      ],
    },
    {
      module: 'AD',
      status: 'Completed',
      startedOffset: -16,
      completedOffset: -9,
      prerequisites: [
        { name: 'ActiveDirectory module (RSAT)', satisfied: true, detail: null },
        { name: 'Domain reachable', satisfied: true, detail: AD_DOMAIN },
      ],
    },
    { module: 'ADCS', status: 'Completed', startedOffset: -9, completedOffset: -7, prerequisites: [{ name: 'ActiveDirectory module (RSAT)', satisfied: true, detail: null }] },
    {
      module: 'GPO',
      status: 'Completed',
      startedOffset: -7,
      completedOffset: -3,
      prerequisites: [
        { name: 'GroupPolicy module (GPMC)', satisfied: true, detail: null },
        { name: 'SYSVOL readable', satisfied: true, detail: null },
      ],
    },
    {
      module: 'Windows',
      status: 'Completed',
      startedOffset: -3,
      completedOffset: -1,
      prerequisites: [{ name: 'Running elevated on the assessed host', satisfied: true, detail: null }],
    },
  ];

  return {
    directory: variant.directory,
    assessmentId: variant.assessmentId,
    clock: variant.clock,
    environment: {
      label: variant.label,
      tenantId: TENANT_ID,
      tenantDisplayName: 'Contoso',
      primaryDomain: PRIMARY_DOMAIN,
      adForestName: AD_DOMAIN,
      adDomainName: AD_DOMAIN,
    },
    options: {
      modules: modules.map((m) => m.module),
      includeDomainControllerSettings: false,
      windowsHostScope: 'LocalHost',
      tenantDomain: PRIMARY_DOMAIN,
    },
    modules,
    datasets,
  };
}
