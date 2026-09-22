import { defineControl } from '../../define.js';
import { affected, fact, notAssessed, pass, plural, review } from '../../helpers.js';
import { M365_REF } from './references.js';

/**
 * Microsoft Teams controls built on the settings delegated Microsoft Graph exposes.
 * Tenant-wide Teams policies (meeting, messaging, external access, app permission) are
 * not readable with delegated Graph, so these controls cover app consent settings and
 * owner-chosen per-team settings only, and describe that scope in every result.
 */

export const m365TeamsPersonalScopeRsc = defineControl({
  id: 'M365-TMS-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Teams apps needing resource-specific consent in the personal scope are a deliberate choice',
  technology: 'm365',
  category: 'Collaboration',
  subcategory: 'Teams apps',
  description:
    'Checks the tenant-wide Teams app setting isUserPersonalScopeResourceSpecificConsentEnabled. When it is true, Teams apps that are allowed in the tenant and request resource-specific consent (RSC) permissions can be installed in a user\'s personal scope; when false, such installations are blocked.',
  rationale:
    'Resource-specific consent lets users grant an app access to data of the resources they install it in, without tenant-wide admin consent. That is convenient but widens who decides which apps can reach organization data. Whether it should be allowed depends on the app governance model (which apps are allowed in the tenant), so an enabled setting is reported for review, not as a failure.',
  severity: 'low',
  confidence: 'medium',
  applicability: { description: 'Microsoft 365 tenants that use Microsoft Teams.' },
  requiredEvidence: ['m365.teamsAppSettings'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'PASS when isUserPersonalScopeResourceSpecificConsentEnabled is false (RSC apps are blocked in the personal scope). REVIEW when it is true: confirm that the Teams apps allowed in the tenant are governed so that user-granted RSC is acceptable. NOT_ASSESSED when the value was not returned. Only this Graph v1.0 setting is evaluated; chat and team RSC settings and Teams app permission policies are not available through delegated Microsoft Graph v1.0.',
    parameters: {},
  },
  expectedState:
    'Installing apps that require resource-specific consent in the personal scope is blocked, or allowed only with documented app governance.',
  remediation: {
    summary: 'Decide whether users may install RSC apps in their personal scope and set the Teams app setting accordingly.',
    steps: [
      'Review which Teams apps are allowed in the tenant (Teams admin center > Teams apps > Manage apps) and which request resource-specific permissions.',
      'If users should not grant RSC to apps in their personal scope, turn the setting off in the Teams admin center app settings, or update teamsAppSettings with isUserPersonalScopeResourceSpecificConsentEnabled set to false through Microsoft Graph.',
      'Communicate the change to app owners before blocking installations.',
    ],
    effort: 'low',
  },
  implementationConsiderations: [
    'Blocking RSC in the personal scope prevents installing apps that need it; apps already installed may need review.',
    'App availability is governed separately by app permission and app setup policies, which this control cannot read.',
  ],
  impact: 'Users can no longer install Teams apps that require resource-specific consent in their personal scope.',
  rollback: ['Set isUserPersonalScopeResourceSpecificConsentEnabled back to true in the Teams app settings.'],
  validation: [
    'Re-run the AdminSecOps assessment and confirm M365-TMS-001 is PASS, or that the REVIEW finding reflects a documented decision.',
  ],
  references: [M365_REF.teamsRsc, M365_REF.graphTeamsAppSettings],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'CM-11' },
    { framework: 'NIST-800-53r5', id: 'AC-6' },
  ],
  tags: ['teams', 'app-consent', 'collaboration'],
  evaluate: (ctx) => {
    const settings = ctx.data('m365.teamsAppSettings');
    const value = settings.isUserPersonalScopeResourceSpecificConsentEnabled;
    const facts = [
      fact('Personal-scope resource-specific consent enabled', value),
      fact('Users can request access to unavailable apps', settings.allowUserRequestsForAppAccess),
    ];
    const notes = [
      'Teams app permission policies, and chat or team resource-specific consent settings, are not readable through delegated Microsoft Graph v1.0 and were not evaluated.',
    ];
    if (value === null) {
      return notAssessed({
        reason: 'Microsoft Graph did not return isUserPersonalScopeResourceSpecificConsentEnabled.',
        summary: 'Teams resource-specific consent setting not available in the evidence.',
        facts,
        notes,
      });
    }
    if (!value) {
      return pass({
        reason: 'Teams apps that require resource-specific consent cannot be installed in the personal scope.',
        summary: 'Personal-scope RSC app installation is blocked.',
        facts,
        notes,
      });
    }
    return review({
      reason:
        'Teams apps that require resource-specific consent can be installed in users\' personal scope. Confirm that the apps allowed in the tenant are governed so that user-granted access is acceptable.',
      summary: 'Users can grant resource-specific consent to Teams apps in their personal scope.',
      facts,
      affectedObjects: [
        affected('tenantSetting', 'teams.isUserPersonalScopeResourceSpecificConsentEnabled', 'Teams personal-scope resource-specific consent', 'isUserPersonalScopeResourceSpecificConsentEnabled=true'),
      ],
      notes,
    });
  },
});

export const m365TeamsGuestChannelManagement = defineControl({
  id: 'M365-TMS-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Guests cannot create, update or delete channels in teams',
  technology: 'm365',
  category: 'Collaboration',
  subcategory: 'Teams guest access',
  description:
    'Checks the per-team guest settings (guestSettings.allowCreateUpdateChannels and allowDeleteChannels) of the teams that could be read, and lists teams where guests can manage channels. These are settings chosen by team owners, not a tenant-wide policy.',
  rationale:
    'Guests who can create, rename or delete channels can change how a team\'s content is organised and remove channels together with their conversations. Both settings are off unless a team owner enables them, so teams that allow it are listed for the owners to confirm.',
  severity: 'low',
  confidence: 'medium',
  applicability: {
    description: 'Microsoft 365 tenants with Microsoft Teams. NOT_APPLICABLE when no teams exist.',
  },
  requiredEvidence: ['m365.teamsTeamSettings'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'NOT_APPLICABLE when the tenant has no teams. REVIEW listing each team whose guestSettings allow guests to create/update or delete channels. REVIEW as well when the guest settings of some teams were not returned (unknown is never treated as restricted). PASS when every team read has both settings off. Only teams returned by Microsoft Graph are evaluated; when the collector could not read every team the evidence is Partial and a PASS becomes REVIEW. Tenant-wide Teams guest access settings are not readable through delegated Microsoft Graph and are not evaluated.',
    parameters: {},
  },
  expectedState: 'No team allows guests to create, update or delete channels unless its owners have a documented reason.',
  remediation: {
    summary: 'Ask the owners of the listed teams to turn off guest channel permissions where guests do not need them.',
    steps: [
      'Share the list of teams with their owners and confirm whether guests need to manage channels.',
      'In Teams, the team owner opens the team, selects More options > Manage team > Settings > Guest permissions, and clears "Allow guests to create and update channels" and "Allow guests to delete channels".',
      'Teams administrators can also update the team through the Teams admin center.',
    ],
    effort: 'low',
  },
  implementationConsiderations: [
    'Changing the setting does not remove guests or existing channels.',
    'Guest access to teams as a whole is controlled in the Teams admin center and Microsoft Entra ID external collaboration settings, which this control does not read.',
  ],
  impact: 'Guests in the listed teams can no longer create, rename or delete channels.',
  rollback: ['Re-enable the guest channel permissions in the team\'s Guest permissions settings.'],
  validation: [
    'Re-run the AdminSecOps assessment and confirm M365-TMS-002 lists no teams.',
  ],
  references: [M365_REF.teamsGuestAccess, M365_REF.graphTeam],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-3' },
    { framework: 'NIST-800-53r5', id: 'AC-6' },
  ],
  tags: ['teams', 'guest-access', 'collaboration'],
  applies: (ctx) =>
    ctx.data('m365.teamsTeamSettings').length === 0
      ? { applicable: false, reason: 'No teams were found in the tenant.' }
      : { applicable: true },
  evaluate: (ctx) => {
    const teams = ctx.data('m365.teamsTeamSettings');
    const permissive = teams.filter(
      (t) => t.guestSettings?.allowCreateUpdateChannels === true || t.guestSettings?.allowDeleteChannels === true,
    );
    const unknown = teams.filter(
      (t) =>
        t.guestSettings === null ||
        t.guestSettings.allowCreateUpdateChannels === null ||
        t.guestSettings.allowDeleteChannels === null,
    );
    const name = (t: (typeof teams)[number]) => t.displayName ?? t.id;
    const facts = [
      fact('Teams evaluated', teams.length),
      fact('Teams where guests can manage channels', permissive.length),
      fact('Teams with unknown guest settings', unknown.length),
    ];
    const notes = [
      'These are per-team settings chosen by team owners. Tenant-wide Teams guest access settings are not readable through delegated Microsoft Graph and were not evaluated.',
    ];
    if (permissive.length > 0 || unknown.length > 0) {
      return review({
        reason: `${plural(permissive.length, 'team')} allow guests to manage channels${unknown.length > 0 ? ` and the guest settings of ${plural(unknown.length, 'team')} could not be read` : ''}. Confirm with the team owners that this is intended.`,
        summary: 'Some teams allow guests to manage channels, or their guest settings are unknown.',
        facts,
        affectedObjects: [
          ...permissive.map((t) =>
            affected('team', t.id, name(t), `guests can create/update channels=${String(t.guestSettings?.allowCreateUpdateChannels)}; delete channels=${String(t.guestSettings?.allowDeleteChannels)}`),
          ),
          ...unknown.filter((t) => !permissive.includes(t)).map((t) => affected('team', t.id, name(t), 'guest settings not returned')),
        ],
        notes,
      });
    }
    return pass({
      reason: `None of the ${plural(teams.length, 'team')} read allows guests to create, update or delete channels.`,
      summary: 'Guests cannot manage channels in the teams that were read.',
      facts,
      notes,
    });
  },
});
