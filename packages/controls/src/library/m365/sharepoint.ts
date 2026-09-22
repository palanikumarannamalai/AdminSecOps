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

export const m365SharePointGuestResharing = defineControl({
  id: 'M365-SPO-003',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'SharePoint guests cannot reshare content they do not own',
  technology: 'm365',
  category: 'Data protection',
  subcategory: 'External sharing',
  description:
    'Checks the organization-level SharePoint setting "Allow guests to share items they don\'t own" (isResharingByExternalUsersEnabled). When it is on, guests who were given edit access can share files, folders and sites with further people.',
  rationale:
    'When guests can reshare, the people who hold access to organization content are no longer chosen only by members; a guest can pass access on to people the organization never invited. Whether this is acceptable depends on how the organization collaborates with partners, so AdminSecOps asks for a decision rather than reporting a failure.',
  severity: 'low',
  confidence: 'high',
  applicability: {
    description:
      'Microsoft 365 tenants with SharePoint Online. NOT_APPLICABLE when external sharing is set to "Only people in your organization".',
  },
  requiredEvidence: ['m365.sharePointSettings'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'NOT_APPLICABLE when sharingCapability is disabled (no external sharing). PASS when isResharingByExternalUsersEnabled is false. REVIEW when it is true, because guest resharing is a collaboration design decision rather than a universal vulnerability. NOT_ASSESSED when Microsoft Graph did not return the value (null is never treated as off).',
    parameters: {},
  },
  expectedState:
    'Guests cannot share items they do not own, or the organization has documented why guest resharing is needed.',
  remediation: {
    summary: 'Turn off "Allow guests to share items they don\'t own" in the SharePoint admin center if guests do not need it.',
    steps: [
      'Confirm with site owners that no partner process depends on guests sharing content onward.',
      'In the SharePoint admin center go to Policies > Sharing and expand More external sharing settings.',
      'Clear "Allow guests to share items they don\'t own" and select Save.',
    ],
    scriptExample:
      '# SharePoint Online Management Shell\nConnect-SPOService -Url https://contoso-admin.sharepoint.com\nSet-SPOTenant -PreventExternalUsersFromResharing $true\nGet-SPOTenant | Format-List PreventExternalUsersFromResharing',
    effort: 'low',
  },
  implementationConsiderations: [
    'Existing access granted by guests is not removed; review sharing reports for sites that are shared externally.',
    'Members can still share with guests according to the organization and site sharing settings.',
  ],
  impact: 'Guests can no longer grant other people access to content they do not own.',
  rollback: [
    'Select "Allow guests to share items they don\'t own" again in Policies > Sharing, or run Set-SPOTenant -PreventExternalUsersFromResharing $false.',
  ],
  validation: [
    'Re-run the AdminSecOps assessment and confirm M365-SPO-003 is PASS or that the REVIEW finding reflects a documented decision.',
    'Run Get-SPOTenant | Format-List PreventExternalUsersFromResharing and confirm the value is True.',
  ],
  references: [M365_REF.manageSharing, M365_REF.sharingOverview, M365_REF.graphSharePointSettings],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-21' },
    { framework: 'NIST-800-53r5', id: 'AC-3' },
  ],
  tags: ['external-sharing', 'sharepoint', 'onedrive', 'guest-access'],
  applies: (ctx) =>
    ctx.data('m365.sharePointSettings').sharingCapability.trim().toLowerCase() === 'disabled'
      ? { applicable: false, reason: 'External sharing is set to "Only people in your organization".' }
      : { applicable: true },
  evaluate: (ctx) => {
    const settings = ctx.data('m365.sharePointSettings');
    const value = settings.isResharingByExternalUsersEnabled;
    const facts = [
      fact('Sharing capability', settings.sharingCapability),
      fact('Guests can share items they do not own', value),
    ];
    if (value === null) {
      return notAssessed({
        reason: 'Microsoft Graph did not return isResharingByExternalUsersEnabled, so guest resharing could not be evaluated.',
        summary: 'Guest resharing setting not available in the evidence.',
        facts,
      });
    }
    if (!value) {
      return pass({
        reason: 'Guests cannot share items they do not own.',
        summary: 'Only members decide who else gets access to shared content.',
        facts,
      });
    }
    return review({
      reason:
        'Guests can share items they do not own (isResharingByExternalUsersEnabled is true). Confirm that partner collaboration requires this; otherwise turn it off.',
      summary: 'Guests can extend access to content they do not own.',
      facts,
      affectedObjects: [
        affected('tenantSetting', 'sharepoint.isResharingByExternalUsersEnabled', 'Allow guests to share items they don\'t own', 'isResharingByExternalUsersEnabled=true'),
      ],
    });
  },
});

export const m365SharePointIdleSignOut = defineControl({
  id: 'M365-SPO-004',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Idle session sign-out is configured for SharePoint and OneDrive',
  technology: 'm365',
  category: 'Data protection',
  subcategory: 'Session management',
  description:
    'Checks whether idle session sign-out is turned on for SharePoint and OneDrive browser sessions (idleSessionSignOut.isEnabled). Microsoft applies it to browser sessions on unmanaged devices; users on managed devices are not signed out.',
  rationale:
    'Browser sessions left open on shared or personal computers give the next person at the device access to organization files. Signing out inactive browser sessions limits that exposure. The appropriate timeout depends on how people work, so a disabled setting is reported for review rather than as a failure.',
  severity: 'low',
  confidence: 'high',
  applicability: {
    description:
      'Microsoft 365 tenants with SharePoint Online. Microsoft documents that the feature relies on Conditional Access (Microsoft Entra ID P1 or P2).',
  },
  requiredEvidence: ['m365.sharePointSettings'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'PASS when idleSessionSignOut.isEnabled is true (the warning and sign-out times are reported as facts). REVIEW when it is false: whether to sign out idle browser sessions on unmanaged devices is an organizational decision. NOT_ASSESSED when Microsoft Graph did not return the setting.',
    parameters: {},
  },
  expectedState:
    'Idle session sign-out is on with warning and sign-out times that match the organization\'s policy, or the decision not to use it is documented.',
  remediation: {
    summary: 'Turn on idle session sign-out in the SharePoint admin center.',
    steps: [
      'In the SharePoint admin center go to Policies > Access control > Idle session sign-out.',
      'Turn on "Sign out inactive users automatically", choose when to warn users and when to sign them out, and select Save.',
      'Allow about 15 minutes for the policy to take effect; existing sessions are not affected.',
    ],
    scriptExample:
      '# SharePoint Online Management Shell\nConnect-SPOService -Url https://contoso-admin.sharepoint.com\nSet-SPOBrowserIdleSignOut -Enabled $true -WarnAfter (New-TimeSpan -Seconds 2700) -SignOutAfter (New-TimeSpan -Seconds 3600)\nGet-SPOBrowserIdleSignOut',
    effort: 'low',
  },
  implementationConsiderations: [
    'Users inactive in SharePoint and OneDrive are signed out across Microsoft 365 in that browser, even if they are active in another service.',
    'Users who chose to stay signed in, and users on managed devices, are not signed out. For finer control use Conditional Access sign-in frequency.',
  ],
  impact: 'Inactive browser sessions on unmanaged devices are warned and then signed out.',
  rollback: [
    'Turn off "Sign out inactive users automatically" in Policies > Access control > Idle session sign-out, or run Set-SPOBrowserIdleSignOut -Enabled $false.',
  ],
  validation: [
    'Re-run the AdminSecOps assessment and confirm M365-SPO-004 is PASS.',
    'Run Get-SPOBrowserIdleSignOut and confirm Enabled is True with the intended times.',
  ],
  references: [M365_REF.spoIdleSignOut, M365_REF.spoUnmanagedDevices, M365_REF.graphSharePointSettings],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-12' },
    { framework: 'NIST-800-53r5', id: 'AC-11' },
  ],
  tags: ['session-management', 'sharepoint', 'onedrive', 'unmanaged-devices'],
  evaluate: (ctx) => {
    const idle = ctx.data('m365.sharePointSettings').idleSessionSignOut;
    const enabled = idle?.isEnabled ?? null;
    const facts = [
      fact('Idle session sign-out enabled', enabled),
      fact('Warn after (seconds)', idle?.warnAfterInSeconds ?? null),
      fact('Sign out after (seconds)', idle?.signOutAfterInSeconds ?? null),
    ];
    if (enabled === null) {
      return notAssessed({
        reason: 'Microsoft Graph did not return the idle session sign-out setting, so it could not be evaluated.',
        summary: 'Idle session sign-out setting not available in the evidence.',
        facts,
      });
    }
    if (enabled) {
      return pass({
        reason: 'Idle session sign-out is enabled for SharePoint and OneDrive browser sessions.',
        summary: 'Inactive browser sessions on unmanaged devices are signed out.',
        facts,
      });
    }
    return review({
      reason:
        'Idle session sign-out is off, so SharePoint and OneDrive browser sessions on unmanaged devices stay signed in while idle. Decide whether a timeout is required for your organization.',
      summary: 'Idle browser sessions are not signed out.',
      facts,
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
