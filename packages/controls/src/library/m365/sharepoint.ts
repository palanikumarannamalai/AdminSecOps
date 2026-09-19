import { defineControl } from '../../define.js';
import { affected, fact, fail, notAssessed, pass, review } from '../../helpers.js';
import { REF } from '../../references.js';
import { M365_REF } from './references.js';

/** Graph sharingCapabilities values, from least to most permissive. */
const SHARING_LABELS: Record<string, string> = {
  disabled: 'Only people in your organization',
  existingexternalusersharingonly: 'Existing guests',
  externalusersharingonly: 'New and existing guests',
  externaluserandguestsharing: 'Anyone',
};

export const m365SharePointAnyoneLinks = defineControl({
  id: 'M365-SPO-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'SharePoint and OneDrive external sharing does not allow Anyone links',
  technology: 'm365',
  category: 'Data protection',
  subcategory: 'External sharing',
  description:
    'Checks the organization-level external sharing setting for SharePoint (sharingCapability). The "Anyone" level allows links that give access to files and folders without signing in; the other levels require guests to authenticate.',
  rationale:
    'Anyone links work for whoever has the link, without sign-in, so they can be forwarded, posted or leaked and there is no record of who opened them. Guest sharing ("New and existing guests" or "Existing guests") requires recipients to sign in or verify with a one-time code and is auditable and revocable per person. Because the OneDrive setting cannot be more permissive than the SharePoint setting, blocking Anyone at the SharePoint organization level blocks it everywhere.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'All Microsoft 365 tenants with SharePoint Online.' },
  requiredEvidence: ['m365.sharePointSettings'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'Reads sharingCapability (case-insensitive). FAIL when it is externalUserAndGuestSharing ("Anyone"). PASS when it is externalUserSharingOnly ("New and existing guests"), existingExternalUserSharingOnly ("Existing guests") or disabled ("Only people in your organization"); guest sharing requires authentication and is therefore accepted by this control (stricter baselines such as CISA SCuBA require "Existing guests" or less, which is noted). REVIEW for an unrecognized value. Resharing by guests and domain restrictions are reported as notes.',
    parameters: {},
  },
  expectedState:
    'External sharing for SharePoint is set to "New and existing guests" or more restrictive, so Anyone links cannot be created.',
  remediation: {
    summary:
      'Lower the organization-level SharePoint external sharing setting from Anyone to New and existing guests (or more restrictive).',
    steps: [
      'Before changing, identify business processes that rely on Anyone links (for example the sharing reports for key sites) and plan an alternative such as guest sharing.',
      'In the SharePoint admin center go to Policies > Sharing.',
      'Under External sharing, move the SharePoint slider to "New and existing guests" (or "Existing guests" / "Only people in your organization"). The OneDrive slider moves to the same level or lower.',
      'Select Save.',
    ],
    scriptExample:
      '# SharePoint Online Management Shell\nConnect-SPOService -Url https://contoso-admin.sharepoint.com\nSet-SPOTenant -SharingCapability ExternalUserSharingOnly\nGet-SPOTenant | Format-List SharingCapability',
    effort: 'medium',
  },
  implementationConsiderations: [
    'Existing Anyone links stop working when Anyone sharing is turned off at the organization level; people who relied on them will need to be invited as guests.',
    'Guests must sign in or use a one-time verification code, which adds friction for external partners.',
    'If you must keep Anyone links, limit them with link expiration and view-only permissions, and restrict Anyone sharing to specific sites instead of the whole organization.',
  ],
  impact:
    'Users can no longer create links that work without sign-in. External recipients must authenticate as guests.',
  rollback: [
    'In the SharePoint admin center > Policies > Sharing, move the SharePoint slider back to Anyone, or run Set-SPOTenant -SharingCapability ExternalUserAndGuestSharing.',
  ],
  validation: [
    'Re-run the AdminSecOps collector and confirm M365-SPO-001 is PASS.',
    'In the SharePoint admin center > Policies > Sharing, confirm the SharePoint and OneDrive sliders are not set to Anyone.',
  ],
  references: [
    M365_REF.sharingOverview,
    M365_REF.manageSharing,
    M365_REF.graphSharePointSettings,
    M365_REF.attackCloudStorageData,
    REF.scubaGearBaselines,
  ],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-3' },
    { framework: 'NIST-800-53r5', id: 'AC-21' },
    {
      framework: 'CISA-SCuBA',
      id: 'MS.SHAREPOINT.1.1v1',
      note: 'partial: SCuBA requires Existing guests or less; this control only rejects Anyone',
    },
    { framework: 'MITRE-ATTACK', id: 'T1530' },
  ],
  tags: ['data-exfiltration', 'external-sharing', 'sharepoint', 'onedrive'],
  evaluate: (ctx) => {
    const settings = ctx.data('m365.sharePointSettings');
    const capability = settings.sharingCapability.trim();
    const key = capability.toLowerCase();
    const label = SHARING_LABELS[key];
    const facts = [
      fact('Sharing capability', capability),
      fact('Sharing domain restriction mode', settings.sharingDomainRestrictionMode),
      fact('Guests can reshare', settings.isResharingByExternalUsersEnabled),
    ];
    const notes: string[] = [];
    if (settings.isResharingByExternalUsersEnabled === true && key !== 'disabled') {
      notes.push(
        'Guests can share items they do not own (isResharingByExternalUsersEnabled). Consider turning this off so only members control who has access.',
      );
    }
    if (key === 'externalusersharingonly') {
      notes.push(
        'Sharing with new guests is allowed. Stricter baselines (for example CISA SCuBA MS.SHAREPOINT.1.1v1) limit sharing to existing guests; consider this if your organization does not need ad hoc guest invitations.',
      );
      if ((settings.sharingDomainRestrictionMode ?? 'none').toLowerCase() === 'none') {
        notes.push(
          'External sharing is not limited to allowed domains (sharingDomainRestrictionMode is none).',
        );
      }
    }
    if (label === undefined) {
      return review({
        reason: `The sharing capability value "${capability}" is not recognized, so AdminSecOps cannot tell whether Anyone links are allowed; check the setting in the SharePoint admin center.`,
        summary: 'Unrecognized SharePoint sharing setting.',
        facts,
        notes,
      });
    }
    if (key === 'externaluserandguestsharing') {
      return fail({
        reason:
          'SharePoint external sharing is set to Anyone, so users can create links that give access without signing in.',
        summary:
          'Anyone (unauthenticated) links can be created for SharePoint and OneDrive content.',
        facts,
        affectedObjects: [
          affected(
            'tenantSetting',
            'sharepoint.sharingCapability',
            'SharePoint external sharing',
            `sharingCapability=${capability} (${label})`,
          ),
        ],
        notes,
      });
    }
    return pass({
      reason: `SharePoint external sharing is set to "${label}", which does not allow Anyone links.`,
      summary: 'External recipients must authenticate to access shared content.',
      facts,
      notes,
    });
  },
});

export const m365SharePointLegacyAuth = defineControl({
  id: 'M365-SPO-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'SharePoint legacy authentication protocols are disabled',
  technology: 'm365',
  category: 'Authentication',
  subcategory: 'Legacy protocols',
  description:
    'Checks that SharePoint Online and OneDrive do not accept apps that use legacy (non-modern) authentication protocols (isLegacyAuthProtocolsEnabled is false).',
  rationale:
    'Apps that do not use modern authentication cannot perform MFA and cannot enforce device-based Conditional Access restrictions, so they let a stolen password reach SharePoint and OneDrive content while bypassing those controls. Microsoft recommends blocking them, especially when access from unmanaged devices is limited.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'All Microsoft 365 tenants with SharePoint Online.' },
  requiredEvidence: ['m365.sharePointSettings'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'PASS when isLegacyAuthProtocolsEnabled is false. FAIL when it is true. NOT_ASSESSED when the value was not returned by Microsoft Graph (null), because an unknown value must not be treated as compliant.',
    parameters: {},
  },
  expectedState:
    'Apps that do not use modern authentication are blocked from SharePoint and OneDrive (LegacyAuthProtocolsEnabled is False).',
  remediation: {
    summary:
      'Block access from apps that do not use modern authentication in the SharePoint admin center.',
    steps: [
      'Check Microsoft Entra sign-in logs for SharePoint Online sign-ins from legacy clients to identify affected users and apps.',
      "In the SharePoint admin center go to Policies > Access control > Apps that don't use modern authentication.",
      'Select Block access and Save.',
    ],
    scriptExample:
      '# SharePoint Online Management Shell\nConnect-SPOService -Url https://contoso-admin.sharepoint.com\nSet-SPOTenant -LegacyAuthProtocolsEnabled $false\nGet-SPOTenant | Format-List LegacyAuthProtocolsEnabled',
    effort: 'low',
  },
  implementationConsiderations: [
    'Old Office versions (before Office 2013) and some third-party apps and scripts that sign in with a user name and password stop connecting to SharePoint and OneDrive.',
    'Blocking legacy authentication is especially important when you limit or block access from unmanaged devices, because legacy apps cannot enforce those device-based restrictions.',
  ],
  impact: 'Only apps that use modern authentication can access SharePoint and OneDrive.',
  rollback: [
    "Run Set-SPOTenant -LegacyAuthProtocolsEnabled $true, or select Allow access under Apps that don't use modern authentication.",
  ],
  validation: [
    'Re-run the AdminSecOps collector and confirm M365-SPO-002 is PASS.',
    'Run Get-SPOTenant | Format-List LegacyAuthProtocolsEnabled and confirm the value is False.',
  ],
  references: [
    M365_REF.spoUnmanagedDevices,
    M365_REF.setSpoTenant,
    M365_REF.graphSharePointSettings,
    REF.caBlockLegacyAuth,
    REF.attackPasswordSpraying,
  ],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'CM-7' },
    { framework: 'NIST-800-53r5', id: 'IA-2' },
    { framework: 'MITRE-ATTACK', id: 'T1110.003' },
  ],
  tags: ['legacy-authentication', 'sharepoint', 'onedrive'],
  evaluate: (ctx) => {
    const value = ctx.data('m365.sharePointSettings').isLegacyAuthProtocolsEnabled;
    const facts = [fact('isLegacyAuthProtocolsEnabled', value)];
    if (value === null) {
      return notAssessed({
        reason:
          'Microsoft Graph did not return isLegacyAuthProtocolsEnabled, so the setting could not be evaluated.',
        summary: 'Legacy authentication setting not available in the evidence.',
        facts,
      });
    }
    if (!value) {
      return pass({
        reason: 'SharePoint legacy authentication protocols are disabled.',
        summary: 'Apps that do not use modern authentication are blocked.',
        facts,
      });
    }
    return fail({
      reason:
        'SharePoint legacy authentication protocols are enabled (isLegacyAuthProtocolsEnabled is true).',
      summary: 'Apps that do not use modern authentication can access SharePoint and OneDrive.',
      facts,
    });
  },
});
