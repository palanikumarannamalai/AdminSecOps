import { defineControl } from '../../define.js';
import { fact, fail, pass } from '../../helpers.js';
import { REF } from '../../references.js';
import { M365_REF } from './references.js';

export const m365UnifiedAuditLog = defineControl({
  id: 'M365-AUD-001',
  version: '1.0.1',
  lifecycle: 'stable',
  title: 'Unified audit log ingestion is enabled',
  technology: 'm365',
  category: 'Logging and monitoring',
  subcategory: 'Audit logging',
  description:
    'Checks that the Microsoft 365 unified audit log is recording user and administrator activity (UnifiedAuditLogIngestionEnabled in the organization audit log configuration).',
  rationale:
    'The unified audit log is the primary record of who did what across Exchange Online, SharePoint, OneDrive, Teams and Microsoft Entra. Without it, a compromised account, a malicious inbox rule or mass file download cannot be investigated after the fact, and alerting that depends on audit events does not work. Attackers who gain administrative access may also turn auditing off to hide their activity.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'All Microsoft 365 tenants with Exchange Online.' },
  requiredEvidence: ['exchange.adminAuditLogConfig'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'PASS when UnifiedAuditLogIngestionEnabled is true in the Exchange Online audit log configuration (Get-AdminAuditLogConfig). FAIL when it is false.',
    parameters: {},
  },
  expectedState:
    'Audit log ingestion is turned on ("Start recording user and admin activity" has been completed in Microsoft Purview).',
  remediation: {
    summary:
      'Turn on audit log recording in the Microsoft Purview portal or with Exchange Online PowerShell.',
    steps: [
      'Sign in to the Microsoft Purview portal (https://purview.microsoft.com) with an account that has the Audit Logs role (for example Compliance Administrator or Organization Management).',
      'Go to Solutions > Audit. If auditing is off, a banner offers "Start recording user and admin activity"; select it.',
      'Alternatively, connect to Exchange Online PowerShell (Connect-ExchangeOnline) and run the command in the script example.',
      'Allow up to 60 minutes for the change to take effect, then confirm that new events appear in an audit search.',
    ],
    scriptExample:
      '# Run in Exchange Online PowerShell (not Security & Compliance PowerShell)\nConnect-ExchangeOnline\nSet-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true\nGet-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled',
    effort: 'low',
  },
  implementationConsiderations: [
    'Verify auditing explicitly. Microsoft documents exceptions to default enablement for SMB licences and unmanaged enterprise trial tenants; a disabled value alone does not establish that an attacker turned it off.',
    'Audit record retention depends on licensing (Audit Standard versus Audit Premium). Enabling ingestion does not extend retention; consider exporting audit data to a SIEM for longer retention.',
    'Get-AdminAuditLogConfig reports the correct value only in Exchange Online PowerShell. In Security & Compliance PowerShell the property always shows False, so validate with the correct module.',
  ],
  impact:
    'No user impact. Activity is recorded in the audit log and becomes searchable in Microsoft Purview.',
  rollback: [
    'Turning auditing off is not recommended. If required, run Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false in Exchange Online PowerShell.',
  ],
  validation: [
    'Re-run the AdminSecOps Exchange collector and confirm M365-AUD-001 is PASS.',
    'In Exchange Online PowerShell, run Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled and confirm the value is True.',
    'Run an audit search in Microsoft Purview for the last day and confirm recent events are returned.',
  ],
  references: [
    M365_REF.auditLogEnableDisable,
    M365_REF.attackDisableCloudLogs,
    REF.scubaGearBaselines,
  ],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AU-2' },
    { framework: 'NIST-800-53r5', id: 'AU-12' },
    { framework: 'MCSB', id: 'LT-3' },
    { framework: 'CISA-SCuBA', id: 'MS.DEFENDER.6.1v1', note: 'Historical Defender mapping; current Security Suite crosswalk not verified. This setting check does not establish full baseline compliance.' },
    { framework: 'MITRE-ATTACK', id: 'T1562.008' },
  ],
  tags: ['audit', 'logging', 'exchange-online'],
  evaluate: (ctx) => {
    const enabled = ctx.data('exchange.adminAuditLogConfig').unifiedAuditLogIngestionEnabled;
    const facts = [fact('Unified audit log ingestion enabled', enabled)];
    if (enabled) {
      return pass({
        reason: 'Unified audit log ingestion is enabled.',
        summary:
          'User and administrator activity is being recorded in the Microsoft 365 unified audit log.',
        facts,
      });
    }
    return fail({
      reason:
        'Unified audit log ingestion is disabled, so user and administrator activity is not being recorded.',
      summary: 'The Microsoft 365 unified audit log is not recording activity.',
      facts,
      notes: [
        'This value is read from Exchange Online PowerShell (Get-AdminAuditLogConfig). If you verify it manually, use Exchange Online PowerShell: Security & Compliance PowerShell always reports False.',
      ],
    });
  },
});

export const m365MailboxAuditing = defineControl({
  id: 'M365-AUD-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Mailbox auditing is on by default for the organization',
  technology: 'm365',
  category: 'Logging and monitoring',
  subcategory: 'Audit logging',
  description:
    'Checks that the organization-wide "mailbox auditing on by default" setting has not been turned off (AuditDisabled is false in the Exchange Online organization configuration).',
  rationale:
    'Mailbox audit records show who accessed a mailbox, which items were read, sent or deleted, and which inbox rules were created. They are essential when investigating business email compromise. When AuditDisabled is true, mailbox auditing is turned off for every mailbox regardless of per-mailbox settings.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'All Microsoft 365 tenants with Exchange Online.' },
  requiredEvidence: ['exchange.organizationConfig'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'PASS when AuditDisabled is false in Get-OrganizationConfig (mailbox auditing on by default). FAIL when AuditDisabled is true.',
    parameters: {},
  },
  expectedState:
    'AuditDisabled is False, so mailbox auditing on by default applies to all mailboxes.',
  remediation: {
    summary: 'Turn mailbox auditing on by default again with Exchange Online PowerShell.',
    steps: [
      'Connect to Exchange Online PowerShell with an Exchange Administrator account.',
      'Run Set-OrganizationConfig -AuditDisabled $false (see the script example).',
      'Review whether any mailboxes have an audit bypass association (Get-MailboxAuditBypassAssociation) and remove bypasses that are not required.',
    ],
    scriptExample:
      'Connect-ExchangeOnline\nSet-OrganizationConfig -AuditDisabled $false\nGet-OrganizationConfig | Format-List AuditDisabled\n# Review mailbox audit bypass associations\nGet-MailboxAuditBypassAssociation -ResultSize Unlimited | Where-Object { $_.AuditBypassEnabled }',
    effort: 'low',
  },
  implementationConsiderations: [
    'Mailbox auditing on by default is the Microsoft default; AuditDisabled set to True is an explicit change that should be explained.',
    'Which mailbox actions are logged by default depends on licensing (Audit Standard versus Audit Premium).',
    'Per-mailbox audit bypass associations are not collected by AdminSecOps; review them separately.',
  ],
  impact:
    'No user impact. Mailbox access and actions are recorded and become searchable in the audit log.',
  rollback: ['Run Set-OrganizationConfig -AuditDisabled $true (not recommended).'],
  validation: [
    'Re-run the AdminSecOps Exchange collector and confirm M365-AUD-002 is PASS.',
    'Run Get-OrganizationConfig | Format-List AuditDisabled in Exchange Online PowerShell and confirm the value is False.',
  ],
  references: [M365_REF.mailboxAuditing, M365_REF.attackDisableCloudLogs, REF.scubaGearBaselines],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AU-2' },
    { framework: 'NIST-800-53r5', id: 'AU-12' },
    { framework: 'MCSB', id: 'LT-3' },
    { framework: 'CISA-SCuBA', id: 'MS.EXO.13.1v1' },
    { framework: 'MITRE-ATTACK', id: 'T1562.008' },
  ],
  tags: ['audit', 'logging', 'exchange-online'],
  evaluate: (ctx) => {
    const disabled = ctx.data('exchange.organizationConfig').auditDisabled;
    const facts = [fact('AuditDisabled', disabled)];
    if (!disabled) {
      return pass({
        reason: 'Mailbox auditing on by default is enabled (AuditDisabled is False).',
        summary: 'Mailbox auditing applies to all mailboxes by default.',
        facts,
      });
    }
    return fail({
      reason: 'Mailbox auditing is turned off for the whole organization (AuditDisabled is True).',
      summary: 'Mailbox actions are not being audited in any mailbox.',
      facts,
    });
  },
});
