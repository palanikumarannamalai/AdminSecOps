import { z } from 'zod';
import { list, optBool, optString } from '../common.js';
import { defineDataset } from './define.js';

const EXO_ROLE = 'Exchange Online: View-Only Organization Management (or Global Reader)';

export const exchangeOrganizationConfig = defineDataset({
  id: 'exchange.organizationConfig',
  module: 'Exchange',
  technology: 'm365',
  title: 'Exchange Online organization configuration',
  description: 'Organization-wide Exchange Online settings including mailbox auditing and modern authentication.',
  source: 'ExchangeOnline',
  operations: ['Get-OrganizationConfig'],
  permissions: [EXO_ROLE],
  personalData: 'none',
  schema: z.object({
    auditDisabled: z.boolean(),
    oAuth2ClientProfileEnabled: z.boolean(),
    customerLockBoxEnabled: optBool,
    mailTipsExternalRecipientsTipsEnabled: optBool,
  }),
});

export const exchangeTransportConfig = defineDataset({
  id: 'exchange.transportConfig',
  module: 'Exchange',
  technology: 'm365',
  title: 'Exchange Online transport configuration',
  description: 'Organization-wide transport settings including SMTP AUTH.',
  source: 'ExchangeOnline',
  operations: ['Get-TransportConfig'],
  permissions: [EXO_ROLE],
  personalData: 'none',
  schema: z.object({
    smtpClientAuthenticationDisabled: z.boolean(),
  }),
});

export const exchangeAdminAuditLogConfig = defineDataset({
  id: 'exchange.adminAuditLogConfig',
  module: 'Exchange',
  technology: 'm365',
  title: 'Audit log configuration',
  description: 'Whether unified audit log ingestion is enabled for the organization.',
  source: 'ExchangeOnline',
  operations: ['Get-AdminAuditLogConfig'],
  permissions: [EXO_ROLE],
  personalData: 'none',
  schema: z.object({
    unifiedAuditLogIngestionEnabled: z.boolean(),
  }),
});

export const exchangeAcceptedDomains = defineDataset({
  id: 'exchange.acceptedDomains',
  module: 'Exchange',
  technology: 'm365',
  title: 'Accepted domains',
  description: 'Mail domains accepted by Exchange Online.',
  source: 'ExchangeOnline',
  operations: ['Get-AcceptedDomain'],
  permissions: [EXO_ROLE],
  personalData: 'none',
  schema: z.array(
    z.object({
      domainName: z.string(),
      /** Authoritative | InternalRelay | ExternalRelay */
      domainType: z.string(),
      default: z.boolean(),
      isCoexistenceDomain: optBool,
    }),
  ),
});

export const exchangeDkimSigningConfigs = defineDataset({
  id: 'exchange.dkimSigningConfigs',
  module: 'Exchange',
  technology: 'm365',
  title: 'DKIM signing configuration',
  description: 'DKIM signing configuration per domain.',
  source: 'ExchangeOnline',
  operations: ['Get-DkimSigningConfig'],
  permissions: [EXO_ROLE],
  personalData: 'none',
  schema: z.array(
    z.object({
      domain: z.string(),
      enabled: z.boolean(),
      status: optString,
    }),
  ),
});

export const exchangeOutboundSpamPolicies = defineDataset({
  id: 'exchange.outboundSpamPolicies',
  module: 'Exchange',
  technology: 'm365',
  title: 'Outbound spam filter policies',
  description: 'Outbound spam policies including the automatic external forwarding mode.',
  source: 'ExchangeOnline',
  operations: ['Get-HostedOutboundSpamFilterPolicy'],
  permissions: [EXO_ROLE],
  personalData: 'none',
  schema: z.array(
    z.object({
      name: z.string(),
      isDefault: z.boolean(),
      /** Automatic | On | Off */
      autoForwardingMode: z.string(),
    }),
  ),
});

export const exchangeRemoteDomains = defineDataset({
  id: 'exchange.remoteDomains',
  module: 'Exchange',
  technology: 'm365',
  title: 'Remote domains',
  description: 'Remote domain settings including whether automatic forwarding is allowed.',
  source: 'ExchangeOnline',
  operations: ['Get-RemoteDomain'],
  permissions: [EXO_ROLE],
  personalData: 'none',
  schema: z.array(
    z.object({
      name: z.string(),
      domainName: z.string(),
      autoForwardEnabled: z.boolean(),
    }),
  ),
});

export const exchangeMailboxForwarding = defineDataset({
  id: 'exchange.mailboxForwarding',
  module: 'Exchange',
  technology: 'm365',
  title: 'Mailbox-level forwarding',
  description:
    'Only mailboxes that have ForwardingSmtpAddress or ForwardingAddress set. Inbox rules and message content are not collected.',
  source: 'ExchangeOnline',
  operations: ['Get-EXOMailbox -Filter "ForwardingSmtpAddress -ne $null -or ForwardingAddress -ne $null"'],
  permissions: [EXO_ROLE],
  personalData: 'identifiers',
  schema: z.array(
    z.object({
      userPrincipalName: z.string(),
      recipientTypeDetails: optString,
      forwardingSmtpAddress: optString,
      forwardingAddress: optString,
      deliverToMailboxAndForward: optBool,
    }),
  ),
});

export const exchangeSmtpAuthMailboxes = defineDataset({
  id: 'exchange.smtpAuthMailboxes',
  module: 'Exchange',
  technology: 'm365',
  title: 'Per-mailbox SMTP AUTH overrides',
  description:
    'Only mailboxes where SmtpClientAuthenticationDisabled is explicitly set (overriding the organization setting).',
  source: 'ExchangeOnline',
  operations: ['Get-EXOCASMailbox -Properties SmtpClientAuthenticationDisabled'],
  permissions: [EXO_ROLE],
  personalData: 'identifiers',
  schema: z.array(
    z.object({
      userPrincipalName: z.string(),
      smtpClientAuthenticationDisabled: z.boolean(),
    }),
  ),
});

export const exchangeAtpPolicy = defineDataset({
  id: 'exchange.atpPolicy',
  module: 'Exchange',
  technology: 'm365',
  title: 'Defender for Office 365 global settings',
  description: 'Safe Attachments for SharePoint, OneDrive and Microsoft Teams, and Safe Documents.',
  source: 'ExchangeOnline',
  operations: ['Get-AtpPolicyForO365'],
  permissions: [EXO_ROLE],
  prerequisites: ['Microsoft Defender for Office 365 Plan 1 or Plan 2'],
  personalData: 'none',
  schema: z.object({
    enableATPForSPOTeamsODB: z.boolean(),
    enableSafeDocs: optBool,
    allowSafeDocsOpen: optBool,
  }),
});

const DnsLookupSchema = z.object({
  /** Found | NotFound | Error */
  lookupStatus: z.enum(['Found', 'NotFound', 'Error']),
  records: list(z.string().max(4096)),
});

export const exchangeMailDnsRecords = defineDataset({
  id: 'exchange.mailDnsRecords',
  module: 'Exchange',
  technology: 'm365',
  title: 'Mail authentication DNS records',
  description: 'Public SPF (TXT) and DMARC (_dmarc TXT) records for each authoritative accepted domain.',
  source: 'DNS',
  operations: ['Resolve-DnsName -Type TXT <domain>', 'Resolve-DnsName -Type TXT _dmarc.<domain>'],
  permissions: ['None (public DNS)'],
  personalData: 'none',
  schema: z.array(
    z.object({
      domain: z.string(),
      spf: DnsLookupSchema,
      dmarc: DnsLookupSchema,
    }),
  ),
});

export const m365SharePointSettings = defineDataset({
  id: 'm365.sharePointSettings',
  module: 'M365',
  technology: 'm365',
  title: 'SharePoint and OneDrive tenant settings',
  description: 'Tenant-level SharePoint Online and OneDrive sharing and access settings.',
  source: 'MicrosoftGraph',
  operations: ['GET https://graph.microsoft.com/v1.0/admin/sharepoint/settings'],
  permissions: ['Graph: SharePointTenantSettings.Read.All'],
  personalData: 'none',
  schema: z.object({
    /** disabled | externalUserSharingOnly | externalUserAndGuestSharing | existingExternalUserSharingOnly */
    sharingCapability: z.string(),
    /** none | allowList | blockList */
    sharingDomainRestrictionMode: optString,
    isResharingByExternalUsersEnabled: optBool,
    isLegacyAuthProtocolsEnabled: optBool,
    isUnmanagedSyncAppForTenantRestricted: optBool,
  }),
});

export const M365_DATASETS = [
  exchangeOrganizationConfig,
  exchangeTransportConfig,
  exchangeAdminAuditLogConfig,
  exchangeAcceptedDomains,
  exchangeDkimSigningConfigs,
  exchangeOutboundSpamPolicies,
  exchangeRemoteDomains,
  exchangeMailboxForwarding,
  exchangeSmtpAuthMailboxes,
  exchangeAtpPolicy,
  exchangeMailDnsRecords,
  m365SharePointSettings,
] as const;
