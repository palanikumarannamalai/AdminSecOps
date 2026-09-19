import { defineControl } from '../../define.js';
import { fact, fail, pass } from '../../helpers.js';
import { REF } from '../../references.js';
import { M365_REF } from './references.js';

export const m365SafeAttachmentsSpo = defineControl({
  id: 'M365-MDO-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Safe Attachments for SharePoint, OneDrive and Teams is enabled',
  technology: 'm365',
  category: 'Threat protection',
  subcategory: 'Malware protection',
  description:
    'Checks that Microsoft Defender for Office 365 Safe Attachments protection is turned on for files in SharePoint, OneDrive and Microsoft Teams (EnableATPForSPOTeamsODB in the global Defender for Office 365 settings).',
  rationale:
    'Files shared in SharePoint, OneDrive and Teams are not scanned by email Safe Attachments policies. Turning on this protection lets Defender for Office 365 detect malicious files in these locations and lock them so users cannot open them, which stops malware spreading through shared libraries and chats.',
  severity: 'medium',
  confidence: 'high',
  applicability: {
    description:
      'Tenants licensed for Microsoft Defender for Office 365 Plan 1 or Plan 2. Without it the collector reports the dataset as not applicable and the control is NOT_APPLICABLE.',
  },
  requiredEvidence: ['exchange.atpPolicy'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'PASS when EnableATPForSPOTeamsODB is true in Get-AtpPolicyForO365. FAIL when it is false. The engine reports NOT_APPLICABLE when the collector marked the dataset NotApplicable (no Defender for Office 365 licence). Safe Documents settings are reported as notes only.',
    parameters: {},
  },
  expectedState:
    'Turn on Defender for Office 365 for SharePoint, OneDrive, and Microsoft Teams is enabled.',
  remediation: {
    summary:
      'Turn on Safe Attachments for SharePoint, OneDrive and Microsoft Teams in the Defender for Office 365 global settings.',
    steps: [
      'In the Microsoft Defender portal go to Email & collaboration > Policies & rules > Threat policies > Safe Attachments and select Global settings.',
      'In the "Protect files in SharePoint, OneDrive, and Microsoft Teams" section, turn on "Turn on Defender for Office 365 for SharePoint, OneDrive, and Microsoft Teams". Select Save.',
      'Optionally prevent users from downloading detected files with Set-SPOTenant -DisallowInfectedFileDownload $true.',
      'Allow up to 30 minutes for the setting to take effect.',
    ],
    scriptExample:
      'Connect-ExchangeOnline\nSet-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true\nGet-AtpPolicyForO365 | Format-List EnableATPForSPOTeamsODB\n# SharePoint Online Management Shell (optional): block download of detected files\nConnect-SPOService -Url https://contoso-admin.sharepoint.com\nSet-SPOTenant -DisallowInfectedFileDownload $true',
    effort: 'low',
  },
  implementationConsiderations: [
    'The setting is on by default in organizations with Defender for Office 365, so a disabled value is an explicit change that should be explained.',
    'Scanning is asynchronous and does not cover every file by design; it uses sharing activity and threat signals to choose files. Detected files cannot be opened, copied, moved or shared, but can be deleted.',
    'By default users can still download a detected file; set DisallowInfectedFileDownload in SharePoint to prevent that.',
    'Consider an alert policy for detected files so the security contact is notified.',
  ],
  impact:
    'Malicious files detected in SharePoint, OneDrive and Teams are locked; users see a warning instead of opening them.',
  rollback: [
    'Run Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $false, or turn the setting off in Safe Attachments global settings.',
  ],
  validation: [
    'Re-run the AdminSecOps Exchange collector and confirm M365-MDO-001 is PASS.',
    'Run Get-AtpPolicyForO365 | Format-List EnableATPForSPOTeamsODB and confirm the value is True.',
  ],
  references: [
    M365_REF.safeAttachmentsSpoAbout,
    M365_REF.safeAttachmentsSpoConfigure,
    M365_REF.attackSpearphishingAttachment,
    REF.scubaGearBaselines,
  ],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SI-3' },
    { framework: 'CISA-SCuBA', id: 'MS.DEFENDER.3.1v1' },
    { framework: 'MITRE-ATTACK', id: 'T1566.001' },
  ],
  tags: ['malware-protection', 'defender-for-office-365', 'sharepoint', 'teams'],
  evaluate: (ctx) => {
    const policy = ctx.data('exchange.atpPolicy');
    const facts = [
      fact('EnableATPForSPOTeamsODB', policy.enableATPForSPOTeamsODB),
      fact('EnableSafeDocs', policy.enableSafeDocs),
      fact('AllowSafeDocsOpen', policy.allowSafeDocsOpen),
    ];
    const notes: string[] = [];
    if (policy.enableSafeDocs === true && policy.allowSafeDocsOpen === true) {
      notes.push(
        'Safe Documents is on but users may click through Protected View even when a file is detected as malicious (AllowSafeDocsOpen). Consider turning that off.',
      );
    }
    if (policy.enableATPForSPOTeamsODB) {
      return pass({
        reason: 'Safe Attachments for SharePoint, OneDrive and Microsoft Teams is enabled.',
        summary: 'Files in SharePoint, OneDrive and Teams are scanned by Defender for Office 365.',
        facts,
        notes,
      });
    }
    return fail({
      reason:
        'Safe Attachments for SharePoint, OneDrive and Microsoft Teams is turned off although Defender for Office 365 is available.',
      summary:
        'Files in SharePoint, OneDrive and Teams are not scanned by Defender for Office 365.',
      facts,
      notes,
    });
  },
});
