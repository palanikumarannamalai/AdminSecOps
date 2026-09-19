import { defineControl } from '../../define.js';
import { affected, fact, fail, pass, plural, review } from '../../helpers.js';
import { REF } from '../../references.js';
import { M365_REF } from './references.js';

export const m365SmtpAuthDisabled = defineControl({
  id: 'M365-EXO-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'SMTP AUTH is disabled for the organization',
  technology: 'm365',
  category: 'Authentication',
  subcategory: 'Legacy protocols',
  description:
    'Checks that authenticated client SMTP submission (SMTP AUTH) is turned off organization-wide in Exchange Online (SmtpClientAuthenticationDisabled is true in the transport configuration).',
  rationale:
    'SMTP AUTH is a legacy protocol that modern Outlook clients do not use. When it accepts Basic authentication it cannot enforce MFA, so attackers use it to validate sprayed or stolen passwords and to send phishing or spam from compromised mailboxes. Microsoft recommends disabling it for the organization and enabling it only on the specific mailboxes that still need it.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'All Microsoft 365 tenants with Exchange Online.' },
  requiredEvidence: ['exchange.transportConfig'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'PASS when SmtpClientAuthenticationDisabled is true in Get-TransportConfig. FAIL when it is false (SMTP AUTH is allowed for every mailbox that does not override the setting). Per-mailbox exceptions are evaluated separately by M365-EXO-002.',
    parameters: {},
  },
  expectedState:
    'SmtpClientAuthenticationDisabled is True at the organization level; any required exceptions are configured per mailbox.',
  remediation: {
    summary:
      'Identify which mailboxes still send with SMTP AUTH, enable it only for those mailboxes, then disable SMTP AUTH for the organization.',
    steps: [
      'In the Exchange admin center go to Reports > Mail flow > SMTP AUTH clients report and note the sender addresses that use SMTP AUTH (review at least 30 days).',
      'Move those devices and applications to alternatives where possible (Microsoft Graph, OAuth for SMTP AUTH, High Volume Email, an SMTP relay connector).',
      'For the mailboxes that must keep SMTP AUTH, enable it per mailbox: Microsoft 365 admin center > Users > Active users > select the user > Mail > Manage email apps > Authenticated SMTP.',
      'Disable SMTP AUTH organization-wide with Set-TransportConfig -SmtpClientAuthenticationDisabled $true (see the script example), or in the Exchange admin center under Settings > Mail flow > "Turn off SMTP AUTH protocol for your organization".',
    ],
    scriptExample:
      'Connect-ExchangeOnline\n# Keep SMTP AUTH only for mailboxes that still require it (example)\nSet-CASMailbox -Identity scanner@contoso.com -SmtpClientAuthenticationDisabled $false\n# Disable SMTP AUTH for the rest of the organization\nSet-TransportConfig -SmtpClientAuthenticationDisabled $true\nGet-TransportConfig | Format-List SmtpClientAuthenticationDisabled',
    effort: 'medium',
  },
  implementationConsiderations: [
    'Multifunction printers, scanners and line-of-business applications that send mail through smtp.office365.com stop working unless their mailbox has a per-mailbox exception or they move to another sending method.',
    'Microsoft is retiring Basic authentication for SMTP AUTH; check the current Microsoft announcement for dates. Clients that already use OAuth for SMTP AUTH still need SMTP AUTH enabled for their mailbox.',
    'When Microsoft Entra security defaults are enabled, SMTP AUTH is already disabled in Exchange Online regardless of this setting.',
  ],
  impact:
    'Mailboxes without a per-mailbox exception can no longer send mail through authenticated SMTP submission.',
  rollback: [
    'Run Set-TransportConfig -SmtpClientAuthenticationDisabled $false in Exchange Online PowerShell.',
  ],
  validation: [
    'Re-run the AdminSecOps Exchange collector and confirm M365-EXO-001 is PASS.',
    'Run Get-TransportConfig | Format-List SmtpClientAuthenticationDisabled and confirm the value is True.',
    'Monitor the SMTP AUTH clients report and confirm only the expected mailboxes still send with SMTP AUTH.',
  ],
  references: [
    M365_REF.smtpAuth,
    M365_REF.smtpAuthClientsReport,
    M365_REF.basicAuthDeprecation,
    REF.attackPasswordSpraying,
    REF.scubaGearBaselines,
  ],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'CM-7' },
    { framework: 'NIST-800-53r5', id: 'IA-2' },
    { framework: 'CISA-SCuBA', id: 'MS.EXO.5.1v1' },
    { framework: 'MITRE-ATTACK', id: 'T1110.003' },
  ],
  tags: ['legacy-authentication', 'smtp-auth', 'exchange-online'],
  evaluate: (ctx) => {
    const disabled = ctx.data('exchange.transportConfig').smtpClientAuthenticationDisabled;
    const facts = [fact('SmtpClientAuthenticationDisabled', disabled)];
    if (disabled) {
      return pass({
        reason: 'SMTP AUTH is disabled for the organization.',
        summary: 'Authenticated SMTP submission is off by default for all mailboxes.',
        facts,
        notes: ['Individual mailboxes can still override this setting; see M365-EXO-002.'],
      });
    }
    return fail({
      reason:
        'SMTP AUTH is enabled for the organization (SmtpClientAuthenticationDisabled is False).',
      summary: 'Every mailbox without an explicit override can authenticate with SMTP AUTH.',
      facts,
    });
  },
});

export const m365SmtpAuthMailboxes = defineControl({
  id: 'M365-EXO-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Mailboxes with SMTP AUTH explicitly enabled are reviewed',
  technology: 'm365',
  category: 'Authentication',
  subcategory: 'Legacy protocols',
  description:
    'Lists mailboxes where SMTP AUTH has been explicitly enabled per mailbox (SmtpClientAuthenticationDisabled is false on the mailbox), which overrides the organization setting.',
  rationale:
    'A per-mailbox SMTP AUTH exception keeps a legacy authentication path open for that account even when the organization setting disables SMTP AUTH. Exceptions are legitimate for devices and applications that cannot yet use another sending method, but each one should be justified, limited to a dedicated account and protected, because a compromised exception account can be used to send phishing from your domain.',
  severity: 'low',
  confidence: 'high',
  applicability: { description: 'All Microsoft 365 tenants with Exchange Online.' },
  requiredEvidence: ['exchange.smtpAuthMailboxes'],
  optionalEvidence: ['exchange.transportConfig'],
  evaluation: {
    logic:
      'Reads the mailboxes that explicitly set SmtpClientAuthenticationDisabled. PASS when no mailbox has it set to false. REVIEW when one or more mailboxes explicitly enable SMTP AUTH, listing each mailbox: whether an exception is justified is a business decision AdminSecOps cannot make. Mailboxes that explicitly disable SMTP AUTH are not findings. The organization setting (optional evidence) is only used for context notes.',
    parameters: {},
  },
  expectedState:
    'No mailbox has SMTP AUTH enabled, or every exception is documented, owned and limited to a dedicated service mailbox.',
  remediation: {
    summary:
      'Confirm that each listed mailbox still needs SMTP AUTH; remove the exception where it is not needed.',
    steps: [
      'For each listed mailbox, identify the device or application that uses it and its owner. The SMTP AUTH clients report (Exchange admin center > Reports > Mail flow) shows recent use.',
      'Where SMTP AUTH is no longer used, return the mailbox to the organization setting with Set-CASMailbox -SmtpClientAuthenticationDisabled $null, or disable it explicitly with $true.',
      'For exceptions that remain, use a dedicated mailbox with a long unique password or OAuth, restrict who can manage it, and document the justification.',
    ],
    scriptExample:
      'Connect-ExchangeOnline\n# Return a mailbox to the organization-wide SMTP AUTH setting\nSet-CASMailbox -Identity olduser@contoso.com -SmtpClientAuthenticationDisabled $null\n# List remaining explicit exceptions\nGet-EXOCASMailbox -ResultSize Unlimited -Properties SmtpClientAuthenticationDisabled | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false }',
    effort: 'low',
  },
  implementationConsiderations: [
    'Removing an exception breaks the device or application that sends through that mailbox; confirm with the owner first.',
    'A per-mailbox value of false overrides the organization setting even when SMTP AUTH is disabled organization-wide.',
    'Conditional Access policies that block legacy authentication also block Basic authentication over SMTP AUTH for the account.',
  ],
  impact: 'Only mailboxes whose exception is removed lose the ability to send through SMTP AUTH.',
  rollback: [
    'Re-enable SMTP AUTH for a mailbox with Set-CASMailbox -Identity <mailbox> -SmtpClientAuthenticationDisabled $false.',
  ],
  validation: [
    'Re-run the AdminSecOps Exchange collector and confirm M365-EXO-002 lists only approved exceptions (or is PASS).',
    'Run Get-EXOCASMailbox -Properties SmtpClientAuthenticationDisabled filtered for $false and compare with your approved list.',
  ],
  references: [M365_REF.smtpAuth, M365_REF.smtpAuthClientsReport, REF.attackPasswordSpraying],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'CM-7' },
    { framework: 'NIST-800-53r5', id: 'AC-17' },
    { framework: 'MITRE-ATTACK', id: 'T1110.003' },
  ],
  tags: ['legacy-authentication', 'smtp-auth', 'exchange-online'],
  evaluate: (ctx) => {
    const overrides = ctx.data('exchange.smtpAuthMailboxes');
    const enabled = [...overrides.filter((m) => !m.smtpClientAuthenticationDisabled)].sort((a, b) =>
      a.userPrincipalName.localeCompare(b.userPrincipalName),
    );
    const transport = ctx.fact('exchange.transportConfig');
    const orgDisabled = transport.available
      ? transport.data.smtpClientAuthenticationDisabled
      : null;
    const facts = [
      fact('Mailboxes with an explicit SMTP AUTH setting', overrides.length),
      fact('Mailboxes with SMTP AUTH explicitly enabled', enabled.length),
      fact('Organization SMTP AUTH disabled', orgDisabled),
    ];
    if (enabled.length === 0) {
      return pass({
        reason: 'No mailbox explicitly enables SMTP AUTH.',
        summary: 'There are no per-mailbox SMTP AUTH exceptions.',
        facts,
      });
    }
    const notes: string[] = [];
    if (orgDisabled === false) {
      notes.push(
        'SMTP AUTH is also enabled for the whole organization (see M365-EXO-001), so these exceptions currently add no additional exposure; they become the only SMTP AUTH paths once the organization setting is disabled.',
      );
    }
    return review({
      reason: `${plural(enabled.length, 'mailbox', 'mailboxes')} explicitly enable SMTP AUTH. Each exception needs a business owner and justification, which AdminSecOps cannot determine from configuration.`,
      summary: `${plural(enabled.length, 'mailbox', 'mailboxes')} override the organization setting to allow SMTP AUTH.`,
      facts,
      affectedObjects: enabled.map((m) =>
        affected(
          'mailbox',
          m.userPrincipalName,
          m.userPrincipalName,
          'SmtpClientAuthenticationDisabled=False (SMTP AUTH explicitly enabled on the mailbox)',
        ),
      ),
      notes,
    });
  },
});

export const m365ModernAuthExchange = defineControl({
  id: 'M365-EXO-006',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Modern authentication is enabled for Exchange Online',
  technology: 'm365',
  category: 'Authentication',
  subcategory: 'Modern authentication',
  description:
    'Checks that modern authentication (OAuth 2.0) is enabled for Outlook clients connecting to Exchange Online (OAuth2ClientProfileEnabled is true in the organization configuration).',
  rationale:
    'Modern authentication is what allows Outlook sign-ins to use MFA, Conditional Access and token-based sessions. If it is disabled, Outlook desktop clients fall back to prompts that cannot satisfy MFA or Conditional Access requirements, which either breaks access or pushes users and administrators toward weaker exceptions.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'All Microsoft 365 tenants with Exchange Online.' },
  requiredEvidence: ['exchange.organizationConfig'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'PASS when OAuth2ClientProfileEnabled is true in Get-OrganizationConfig. FAIL when it is false.',
    parameters: {},
  },
  expectedState: 'OAuth2ClientProfileEnabled is True.',
  remediation: {
    summary: 'Enable modern authentication for Exchange Online.',
    steps: [
      'In the Microsoft 365 admin center go to Settings > Org settings > Services > Modern authentication and select "Turn on modern authentication for Outlook 2013 for Windows and later", or use the script example.',
      'Restart Outlook on affected computers so that it signs in with modern authentication.',
    ],
    scriptExample:
      'Connect-ExchangeOnline\nSet-OrganizationConfig -OAuth2ClientProfileEnabled $true\nGet-OrganizationConfig | Format-List OAuth2ClientProfileEnabled',
    effort: 'low',
  },
  implementationConsiderations: [
    'Modern authentication is on by default for current tenants; a False value is an explicit change that should be investigated.',
    'Very old Outlook versions (Outlook 2010 and earlier) cannot use modern authentication and are no longer supported for Exchange Online.',
  ],
  impact:
    'Outlook clients sign in with the Microsoft Entra sign-in experience and become subject to MFA and Conditional Access.',
  rollback: ['Run Set-OrganizationConfig -OAuth2ClientProfileEnabled $false (not recommended).'],
  validation: [
    'Re-run the AdminSecOps Exchange collector and confirm M365-EXO-006 is PASS.',
    'Run Get-OrganizationConfig | Format-List OAuth2ClientProfileEnabled and confirm the value is True.',
  ],
  references: [
    M365_REF.modernAuthExchange,
    M365_REF.basicAuthDeprecation,
    REF.attackPasswordSpraying,
  ],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-2' },
    { framework: 'MITRE-ATTACK', id: 'T1110.003' },
  ],
  tags: ['modern-authentication', 'exchange-online', 'identity'],
  evaluate: (ctx) => {
    const enabled = ctx.data('exchange.organizationConfig').oAuth2ClientProfileEnabled;
    const facts = [fact('OAuth2ClientProfileEnabled', enabled)];
    if (enabled) {
      return pass({
        reason: 'Modern authentication is enabled for Exchange Online.',
        summary: 'Outlook clients can use modern authentication.',
        facts,
      });
    }
    return fail({
      reason:
        'Modern authentication is disabled for Exchange Online (OAuth2ClientProfileEnabled is False).',
      summary:
        'Outlook clients cannot use modern authentication, MFA or Conditional Access when connecting to Exchange Online.',
      facts,
    });
  },
});
