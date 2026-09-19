import type { Reference } from '@adminsecops/schemas';

/**
 * References specific to the Microsoft 365 controls (Exchange Online, mail DNS,
 * SharePoint Online and Defender for Office 365). Shared references (standards,
 * common MITRE techniques) live in ../../references.ts. Every URL below was
 * checked against Microsoft Learn / the publisher's site when it was added; only
 * titles and URLs are stored, never copied text.
 */
const ms = (title: string, url: string): Reference => ({ title, url, publisher: 'Microsoft' });
const mitre = (title: string, url: string): Reference => ({ title, url, publisher: 'MITRE' });

const LEARN = 'https://learn.microsoft.com/en-us';

export const M365_REF = {
  // --- Auditing ------------------------------------------------------------------
  auditLogEnableDisable: ms(
    'Turn auditing on or off (Microsoft Purview)',
    `${LEARN}/purview/audit-log-enable-disable`,
  ),
  mailboxAuditing: ms(
    'Manage mailbox auditing (Microsoft Purview)',
    `${LEARN}/purview/audit-mailboxes`,
  ),

  // --- Exchange Online authentication ---------------------------------------------
  smtpAuth: ms(
    'Enable or disable SMTP AUTH in Exchange Online',
    `${LEARN}/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission`,
  ),
  smtpAuthClientsReport: ms(
    'SMTP AUTH clients report in the new Exchange admin center',
    `${LEARN}/exchange/monitoring/mail-flow-reports/mfr-smtp-auth-clients-report`,
  ),
  basicAuthDeprecation: ms(
    'Deprecation of Basic authentication in Exchange Online',
    `${LEARN}/exchange/clients-and-mobile-in-exchange-online/deprecation-of-basic-authentication-exchange-online`,
  ),
  setTransportConfig: ms(
    'Set-TransportConfig (Exchange PowerShell)',
    `${LEARN}/powershell/module/exchangepowershell/set-transportconfig`,
  ),
  modernAuthExchange: ms(
    'Enable or disable modern authentication for Outlook in Exchange Online',
    `${LEARN}/exchange/clients-and-mobile-in-exchange-online/enable-or-disable-modern-authentication-in-exchange-online`,
  ),

  // --- Forwarding --------------------------------------------------------------------
  externalForwarding: ms(
    'Control external email forwarding (Microsoft Defender for Office 365)',
    `${LEARN}/defender-office-365/outbound-spam-policies-external-email-forwarding`,
  ),
  outboundSpamConfigure: ms(
    'Configure outbound spam policies (Microsoft Defender for Office 365)',
    `${LEARN}/defender-office-365/outbound-spam-policies-configure`,
  ),
  setOutboundSpamPolicy: ms(
    'Set-HostedOutboundSpamFilterPolicy (Exchange PowerShell)',
    `${LEARN}/powershell/module/exchangepowershell/set-hostedoutboundspamfilterpolicy`,
  ),
  remoteDomains: ms(
    'Remote domains in Exchange Online',
    `${LEARN}/exchange/mail-flow-best-practices/remote-domains/remote-domains`,
  ),
  manageRemoteDomains: ms(
    'Manage remote domains in Exchange Online',
    `${LEARN}/exchange/mail-flow-best-practices/remote-domains/manage-remote-domains`,
  ),
  mailboxForwarding: ms(
    'Configure email forwarding for a mailbox in Exchange Online',
    `${LEARN}/exchange/recipients-in-exchange-online/manage-user-mailboxes/configure-email-forwarding`,
  ),
  autoForwardedReport: ms(
    'Auto forwarded messages report in the new Exchange admin center',
    `${LEARN}/exchange/monitoring/mail-flow-reports/mfr-auto-forwarded-messages-report`,
  ),
  compromisedAccount: ms(
    'Respond to a compromised email account in Microsoft 365',
    `${LEARN}/defender-office-365/responding-to-a-compromised-email-account`,
  ),

  // --- Email authentication -------------------------------------------------------------
  dkim: ms(
    'How to use DKIM for email in your custom domain',
    `${LEARN}/defender-office-365/email-authentication-dkim-configure`,
  ),
  spf: ms(
    'Set up SPF to identify valid email sources for your Microsoft 365 domain',
    `${LEARN}/defender-office-365/email-authentication-spf-configure`,
  ),
  dmarc: ms(
    'Set up DMARC to validate email in Microsoft 365',
    `${LEARN}/defender-office-365/email-authentication-dmarc-configure`,
  ),

  // --- SharePoint and OneDrive -------------------------------------------------------------
  sharingOverview: ms(
    'Overview of external sharing in SharePoint and OneDrive in Microsoft 365',
    `${LEARN}/sharepoint/external-sharing-overview`,
  ),
  manageSharing: ms(
    'Manage sharing settings for SharePoint and OneDrive in Microsoft 365',
    `${LEARN}/sharepoint/turn-external-sharing-on-or-off`,
  ),
  graphSharePointSettings: ms(
    'sharepointSettings resource type (Microsoft Graph)',
    `${LEARN}/graph/api/resources/sharepointsettings?view=graph-rest-1.0`,
  ),
  spoUnmanagedDevices: ms(
    'Control access from unmanaged devices (SharePoint and OneDrive)',
    `${LEARN}/sharepoint/control-access-from-unmanaged-devices`,
  ),
  setSpoTenant: ms(
    'Set-SPOTenant (SharePoint Online PowerShell)',
    `${LEARN}/powershell/module/microsoft.online.sharepoint.powershell/set-spotenant`,
  ),

  // --- Defender for Office 365 -------------------------------------------------------------
  safeAttachmentsSpoAbout: ms(
    'Safe Attachments for SharePoint, OneDrive, and Microsoft Teams',
    `${LEARN}/defender-office-365/safe-attachments-for-spo-odfb-teams-about`,
  ),
  safeAttachmentsSpoConfigure: ms(
    'Turn on Safe Attachments for SharePoint, OneDrive, and Microsoft Teams',
    `${LEARN}/defender-office-365/safe-attachments-for-spo-odfb-teams-configure`,
  ),

  // --- MITRE ATT&CK ----------------------------------------------------------------------------
  attackEmailForwardingRule: mitre(
    'MITRE ATT&CK T1114.003: Email Forwarding Rule',
    'https://attack.mitre.org/techniques/T1114/003/',
  ),
  attackDisableCloudLogs: mitre(
    'MITRE ATT&CK T1562.008: Disable or Modify Cloud Logs',
    'https://attack.mitre.org/techniques/T1562/008/',
  ),
  attackPhishing: mitre(
    'MITRE ATT&CK T1566: Phishing',
    'https://attack.mitre.org/techniques/T1566/',
  ),
  attackSpearphishingAttachment: mitre(
    'MITRE ATT&CK T1566.001: Spearphishing Attachment',
    'https://attack.mitre.org/techniques/T1566/001/',
  ),
  attackCloudStorageData: mitre(
    'MITRE ATT&CK T1530: Data from Cloud Storage',
    'https://attack.mitre.org/techniques/T1530/',
  ),
} as const satisfies Record<string, Reference>;
