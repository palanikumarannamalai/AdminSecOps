import { z } from 'zod';
import { list, optBool, optNumber, optString } from '../common.js';
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
    'Only mailboxes that have ForwardingSmtpAddress or ForwardingAddress set. Inbox rules use a separate dataset; message content is not collected.',
  source: 'ExchangeOnline',
  operations: ['Get-EXOMailbox -Filter "ForwardingSmtpAddress -ne $null -or ForwardingAddress -ne $null" -Properties ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward'],
  permissions: [EXO_ROLE],
  personalData: 'identifiers',
  schema: z.array(
    z.object({
      userPrincipalName: z.string(),
      recipientTypeDetails: optString,
      forwardingSmtpAddress: optString,
      forwardingAddress: optString,
      resolvedForwardingSmtpAddress: z.string().nullable().optional(),
      resolvedForwardingRecipientType: z.string().nullable().optional(),
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
      /** Get-EXOCASMailbox does not return a UPN; the collector records the primary SMTP address here. */
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
  permissions: [
    'Graph: SharePointTenantSettings.Read.All',
    'Directory role for delegated access: Global Reader or SharePoint Administrator',
  ],
  personalData: 'none',
  schema: z.object({
    /** disabled | externalUserSharingOnly | externalUserAndGuestSharing | existingExternalUserSharingOnly */
    sharingCapability: z.string(),
    /** none | allowList | blockList */
    sharingDomainRestrictionMode: optString,
    isResharingByExternalUsersEnabled: optBool,
    isLegacyAuthProtocolsEnabled: optBool,
    isUnmanagedSyncAppForTenantRestricted: optBool,
    /** Domain names only; null when not returned. */
    sharingAllowedDomainList: z.array(z.string().max(300)).max(5000).nullish().transform((v) => v ?? null),
    sharingBlockedDomainList: z.array(z.string().max(300)).max(5000).nullish().transform((v) => v ?? null),
    isRequireAcceptingUserToMatchInvitedUserEnabled: optBool,
    /** Idle session sign-out for browser sessions on unmanaged devices; null when not returned. */
    idleSessionSignOut: z
      .object({
        isEnabled: optBool,
        warnAfterInSeconds: optNumber,
        signOutAfterInSeconds: optNumber,
      })
      .nullish()
      .transform((v) => v ?? null),
  }),
});

const TEAMS_ROLE_NOTE =
  'Directory role: Microsoft does not document the directory role for delegated access; a signed-in role that cannot read it is reported Unauthorized';

export const m365TeamsAppSettings = defineDataset({
  id: 'm365.teamsAppSettings',
  module: 'M365',
  technology: 'm365',
  title: 'Microsoft Teams app settings',
  description:
    'Tenant-wide settings for Teams apps: whether users can request unavailable apps and whether apps that need resource-specific consent can be installed in the personal scope. Teams meeting, messaging, federation and app permission policies are not available to delegated Microsoft Graph and are not included.',
  source: 'MicrosoftGraph',
  operations: ['GET https://graph.microsoft.com/v1.0/teamwork/teamsAppSettings'],
  permissions: ['Graph: TeamworkAppSettings.Read.All (delegated only)', TEAMS_ROLE_NOTE],
  prerequisites: ['Microsoft Teams'],
  personalData: 'none',
  schema: z.object({
    allowUserRequestsForAppAccess: optBool,
    isUserPersonalScopeResourceSpecificConsentEnabled: optBool,
  }),
});

const TeamMemberSettingsSchema = z.object({
  allowCreateUpdateChannels: optBool,
  allowDeleteChannels: optBool,
  allowAddRemoveApps: optBool,
  allowCreateUpdateRemoveTabs: optBool,
  allowCreateUpdateRemoveConnectors: optBool,
});

const TeamGuestSettingsSchema = z.object({
  allowCreateUpdateChannels: optBool,
  allowDeleteChannels: optBool,
});

export const m365TeamsTeamSettings = defineDataset({
  id: 'm365.teamsTeamSettings',
  module: 'M365',
  technology: 'm365',
  title: 'Microsoft Teams per-team settings',
  description:
    'Member and guest settings of individual teams (settings chosen by team owners, not tenant-wide policy). Collection is bounded: when not every team can be read the dataset is Partial. Channels, messages, members and files are not collected.',
  source: 'MicrosoftGraph',
  operations: [
    'GET https://graph.microsoft.com/v1.0/teams?$select=id,displayName,visibility',
    'GET https://graph.microsoft.com/v1.0/teams/{id}?$select=id,displayName,visibility,isArchived,memberSettings,guestSettings',
  ],
  permissions: ['Graph: Team.ReadBasic.All', TEAMS_ROLE_NOTE],
  prerequisites: ['Microsoft Teams'],
  personalData: 'identifiers',
  schema: z.array(
    z.object({
      id: z.string().min(1).max(200),
      displayName: optString,
      /** private | public | hiddenMembership */
      visibility: optString,
      isArchived: optBool,
      memberSettings: TeamMemberSettingsSchema.nullish().transform((v) => v ?? null),
      guestSettings: TeamGuestSettingsSchema.nullish().transform((v) => v ?? null),
    }),
  ),
});

export const exchangeInboxRules = defineDataset({
  id: 'exchange.inboxRules', module: 'Exchange', technology: 'm365',
  title: 'Inbox forwarding rule review',
  description: 'Bounded mailbox scan including hidden Inbox rules. Only forwarding-rule identifiers and enabled state are stored; no message content or conditions.',
  source: 'ExchangeOnline', operations: ['Get-EXOMailbox', 'Get-InboxRule -IncludeHidden'],
  permissions: ['Exchange role permitting Get-InboxRule on the assessed mailboxes; Global Reader and View-Only Organization Management are insufficient'],
  personalData: 'identifiers',
  schema: z.object({
    complete: z.boolean(), scannedMailboxes: z.number().int().nonnegative(), unscannedMailboxes: z.number().int().nonnegative(),
    rules: z.array(z.object({ mailbox: z.string(), id: optString, name: optString, enabled: optBool })),
  }),
});

export const exchangeTransportRules = defineDataset({
  id: 'exchange.transportRules', module: 'Exchange', technology: 'm365',
  title: 'Mail-flow recipient actions',
  description: 'Mail-flow rule state and recipient redirection/copy actions. Conditions, exceptions, recipient lists and message content are not stored.',
  source: 'ExchangeOnline', operations: ['Get-TransportRule -ExcludeConditionActionDetails:$false'],
  permissions: [EXO_ROLE], personalData: 'identifiers',
  schema: z.object({ complete: z.boolean(), rules: z.array(z.object({
    id: optString, name: optString, state: optString, mode: optString, priority: optNumber,
    hasRedirect: optBool, hasCopy: optBool, hasBlindCopy: optBool, hasAddedRecipients: optBool,
  })) }),
});

export const M365_DATASETS = [
  exchangeInboxRules,
  exchangeTransportRules,
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
  m365TeamsAppSettings,
  m365TeamsTeamSettings,
] as const;
