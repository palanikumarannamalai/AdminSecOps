/**
 * Contoso - Exchange Online, SharePoint and Intune datasets.
 *
 * Intended state: unified audit log and mailbox auditing on; SMTP AUTH disabled for
 * the organisation but explicitly enabled on two mailboxes; a custom outbound spam
 * policy with automatic forwarding On; one mailbox forwarding to an external personal
 * address; DKIM enabled for contoso.example but not mail.contoso.example; SPF ~all on
 * contoso.example and missing on mail.contoso.example; DMARC p=none; SharePoint
 * "Anyone" links allowed; no Defender for Office 365 licence; Intune without
 * secure-by-default and with a Windows-only compliance policy.
 */
import {
  type exchangeAcceptedDomains,
  type exchangeAdminAuditLogConfig,
  type exchangeDkimSigningConfigs,
  type exchangeMailboxForwarding,
  type exchangeMailDnsRecords,
  type exchangeOrganizationConfig,
  type exchangeOutboundSpamPolicies,
  type exchangeRemoteDomains,
  type exchangeSmtpAuthMailboxes,
  type exchangeTransportConfig,
  type intuneCompliancePolicies,
  type intuneDeviceOverview,
  type intuneSettings,
  type m365SharePointSettings,
  type m365TeamsAppSettings,
  type m365TeamsTeamSettings,
} from '@adminsecops/schemas';
import type { z } from 'zod';
import { guid } from '../common.js';
import { GROUPS, INITIAL_DOMAIN, MAIL_DOMAIN, PRIMARY_DOMAIN, USERS } from './identity.js';

type In<D extends { schema: z.ZodType }> = z.input<D['schema']>;

export interface ContosoM365Data {
  organizationConfig: In<typeof exchangeOrganizationConfig>;
  transportConfig: In<typeof exchangeTransportConfig>;
  adminAuditLogConfig: In<typeof exchangeAdminAuditLogConfig>;
  acceptedDomains: In<typeof exchangeAcceptedDomains>;
  dkimSigningConfigs: In<typeof exchangeDkimSigningConfigs>;
  outboundSpamPolicies: In<typeof exchangeOutboundSpamPolicies>;
  remoteDomains: In<typeof exchangeRemoteDomains>;
  mailboxForwarding: In<typeof exchangeMailboxForwarding>;
  smtpAuthMailboxes: In<typeof exchangeSmtpAuthMailboxes>;
  mailDnsRecords: In<typeof exchangeMailDnsRecords>;
  sharePointSettings: In<typeof m365SharePointSettings>;
  teamsAppSettings: In<typeof m365TeamsAppSettings>;
  teamsTeamSettings: In<typeof m365TeamsTeamSettings>;
  intuneSettings: In<typeof intuneSettings>;
  intuneDeviceOverview: In<typeof intuneDeviceOverview>;
  intuneCompliancePolicies: In<typeof intuneCompliancePolicies>;
}

export const EXTERNAL_FORWARD_ADDRESS = 'robin.sales.home@personal-mail.example';

export function contosoM365(): ContosoM365Data {
  return {
    organizationConfig: {
      auditDisabled: false,
      oAuth2ClientProfileEnabled: true,
      customerLockBoxEnabled: false,
      mailTipsExternalRecipientsTipsEnabled: false,
    },
    transportConfig: { smtpClientAuthenticationDisabled: true },
    adminAuditLogConfig: { unifiedAuditLogIngestionEnabled: true },
    acceptedDomains: [
      { domainName: PRIMARY_DOMAIN, domainType: 'Authoritative', default: true, isCoexistenceDomain: false },
      { domainName: MAIL_DOMAIN, domainType: 'Authoritative', default: false, isCoexistenceDomain: false },
      { domainName: INITIAL_DOMAIN, domainType: 'Authoritative', default: false, isCoexistenceDomain: false },
      { domainName: 'contoso.mail.onmicrosoft.com', domainType: 'Authoritative', default: false, isCoexistenceDomain: true },
    ],
    dkimSigningConfigs: [
      { domain: PRIMARY_DOMAIN, enabled: true, status: 'Valid' },
      { domain: MAIL_DOMAIN, enabled: false, status: 'CnameMissing' },
      { domain: INITIAL_DOMAIN, enabled: true, status: 'Valid' },
    ],
    outboundSpamPolicies: [
      { name: 'Default', isDefault: true, autoForwardingMode: 'Automatic' },
      { name: 'Executive Assistants - Allow Forwarding', isDefault: false, autoForwardingMode: 'On' },
    ],
    remoteDomains: [
      { name: 'Default', domainName: '*', autoForwardEnabled: true },
      { name: 'Partner Co', domainName: 'partner-co.example', autoForwardEnabled: true },
    ],
    mailboxForwarding: [
      {
        userPrincipalName: USERS.robinSales.userPrincipalName,
        recipientTypeDetails: 'UserMailbox',
        forwardingSmtpAddress: `smtp:${EXTERNAL_FORWARD_ADDRESS}`,
        forwardingAddress: null,
        deliverToMailboxAndForward: true,
      },
      {
        userPrincipalName: `reception@${PRIMARY_DOMAIN}`,
        recipientTypeDetails: 'SharedMailbox',
        forwardingSmtpAddress: null,
        forwardingAddress: 'Front Desk Team',
        deliverToMailboxAndForward: true,
      },
    ],
    smtpAuthMailboxes: [
      { userPrincipalName: `scanner-hq@${PRIMARY_DOMAIN}`, smtpClientAuthenticationDisabled: false },
      { userPrincipalName: `crm-notifications@${PRIMARY_DOMAIN}`, smtpClientAuthenticationDisabled: false },
      { userPrincipalName: `legacy-fax@${PRIMARY_DOMAIN}`, smtpClientAuthenticationDisabled: true },
    ],
    mailDnsRecords: [
      {
        domain: PRIMARY_DOMAIN,
        spf: {
          lookupStatus: 'Found',
          records: ['v=spf1 include:spf.protection.outlook.com ip4:203.0.113.25 ~all', 'contoso-site-verification=4c1f0e9a7b'],
        },
        dmarc: { lookupStatus: 'Found', records: [`v=DMARC1; p=none; rua=mailto:dmarc-reports@${PRIMARY_DOMAIN}; fo=1`] },
      },
      {
        domain: MAIL_DOMAIN,
        spf: { lookupStatus: 'NotFound', records: [] },
        dmarc: { lookupStatus: 'NotFound', records: [] },
      },
      {
        domain: INITIAL_DOMAIN,
        spf: { lookupStatus: 'Found', records: ['v=spf1 include:spf.protection.outlook.com -all'] },
        dmarc: { lookupStatus: 'NotFound', records: [] },
      },
    ],
    sharePointSettings: {
      sharingCapability: 'externalUserAndGuestSharing',
      sharingDomainRestrictionMode: 'none',
      isResharingByExternalUsersEnabled: true,
      isLegacyAuthProtocolsEnabled: false,
      isUnmanagedSyncAppForTenantRestricted: false,
      sharingAllowedDomainList: [],
      sharingBlockedDomainList: [],
      isRequireAcceptingUserToMatchInvitedUserEnabled: true,
      idleSessionSignOut: { isEnabled: false, warnAfterInSeconds: 0, signOutAfterInSeconds: 0 },
    },
    teamsAppSettings: { allowUserRequestsForAppAccess: true, isUserPersonalScopeResourceSpecificConsentEnabled: true },
    teamsTeamSettings: [
      {
        id: guid('contoso:teams:finance'),
        displayName: 'Finance',
        visibility: 'private',
        isArchived: false,
        memberSettings: {
          allowCreateUpdateChannels: true,
          allowDeleteChannels: true,
          allowAddRemoveApps: true,
          allowCreateUpdateRemoveTabs: true,
          allowCreateUpdateRemoveConnectors: true,
        },
        guestSettings: { allowCreateUpdateChannels: false, allowDeleteChannels: false },
      },
      {
        id: guid('contoso:teams:partner-falcon'),
        displayName: 'Partner Project Falcon',
        visibility: 'private',
        isArchived: false,
        memberSettings: {
          allowCreateUpdateChannels: true,
          allowDeleteChannels: false,
          allowAddRemoveApps: false,
          allowCreateUpdateRemoveTabs: true,
          allowCreateUpdateRemoveConnectors: false,
        },
        guestSettings: { allowCreateUpdateChannels: true, allowDeleteChannels: true },
      },
    ],
    intuneSettings: { secureByDefault: false, deviceComplianceCheckinThresholdDays: 30, isScheduledActionEnabled: true },
    intuneDeviceOverview: { enrolledDeviceCount: 432, windowsCount: 368, macOSCount: 0, iosCount: 64, androidCount: 0 },
    intuneCompliancePolicies: [
      {
        id: guid('contoso:intune:compliance:windows'),
        displayName: 'Windows 10/11 - Baseline compliance',
        odataType: '#microsoft.graph.windows10CompliancePolicy',
        lastModifiedDateTime: '2026-02-17T11:24:39Z',
        assignments: [{ targetType: '#microsoft.graph.groupAssignmentTarget', groupId: GROUPS.allWindowsDevices.id }],
        settings: {
          bitLockerEnabled: true,
          secureBootEnabled: true,
          codeIntegrityEnabled: true,
          storageRequireEncryption: true,
          passwordRequired: false,
          defenderEnabled: true,
          rtpEnabled: true,
          antivirusRequired: true,
          firewallEnabled: true,
          tpmRequired: true,
          osMinimumVersion: '10.0.22631',
        },
      },
    ],
  };
}
