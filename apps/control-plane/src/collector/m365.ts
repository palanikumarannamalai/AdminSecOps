import { m365SharePointSettings, m365TeamsAppSettings, m365TeamsTeamSettings } from '@adminsecops/schemas';
import { GRAPH_BASE } from './graph-client.js';
import type { PlannedDataset } from './package.js';
import {
  arr,
  fanout,
  getAll,
  getOne,
  message,
  pick,
  pickOrNull,
  rec,
  safeId,
  val,
  type DatasetCollector,
  type Rec,
} from './runtime.js';

/**
 * Microsoft 365 collaboration datasets through Microsoft Graph v1.0 (GET only):
 * SharePoint/OneDrive tenant settings and the Teams settings that delegated Graph exposes.
 * Exchange Online and Defender for Office 365 configuration is not available through
 * delegated Graph and is deliberately not collected here (see online.ts).
 */

const sharePointSettings: DatasetCollector = async (state, context) => {
  const body = await getOne(state, context, `${GRAPH_BASE}/admin/sharepoint/settings`);
  // The documented response example wraps the settings in "value"; accept both forms.
  const s = rec(body['value']) ?? body;
  if (typeof s['isRequireAcceptingUserToMatchInvitedUserEnabled'] !== 'boolean') {
    state.warnings.push(message('SETTING_NOT_RETURNED', 'Microsoft Graph omitted the SharePoint invitation account-matching setting. Verify RequireAcceptingAccountMatchInvitedAccount with an authorised SharePoint administrator; the related control remains not assessed.'));
  }

  return {
    ...pick(s, [
      'sharingCapability',
      'sharingDomainRestrictionMode',
      'isResharingByExternalUsersEnabled',
      'isLegacyAuthProtocolsEnabled',
      'isUnmanagedSyncAppForTenantRestricted',
      'isRequireAcceptingUserToMatchInvitedUserEnabled',
    ]),
    sharingAllowedDomainList: arr(val(s, 'sharingAllowedDomainList')),
    sharingBlockedDomainList: arr(val(s, 'sharingBlockedDomainList')),
    idleSessionSignOut: pickOrNull(val(s, 'idleSessionSignOut'), [
      'isEnabled',
      'warnAfterInSeconds',
      'signOutAfterInSeconds',
    ]),
  };
};

const teamsAppSettings: DatasetCollector = async (state, context) => {
  const s = await getOne(state, context, `${GRAPH_BASE}/teamwork/teamsAppSettings`);
  return pick(rec(s['value']) ?? s, ['allowUserRequestsForAppAccess', 'isUserPersonalScopeResourceSpecificConsentEnabled']);
};

const TEAM_SELECT = 'id,displayName,visibility,isArchived,memberSettings,guestSettings';
const MEMBER_KEYS = [
  'allowCreateUpdateChannels',
  'allowDeleteChannels',
  'allowAddRemoveApps',
  'allowCreateUpdateRemoveTabs',
  'allowCreateUpdateRemoveConnectors',
];
const GUEST_KEYS = ['allowCreateUpdateChannels', 'allowDeleteChannels'];

const teamsTeamSettings: DatasetCollector = async (state, context) => {
  // List teams returns only basic properties; settings require one GET per team.
  const teams = (await getAll(state, context, `${GRAPH_BASE}/teams?$select=id,displayName,visibility`))
    .map((t) => rec(t))
    .filter((t): t is Rec => t !== undefined);
  const details = await fanout(state, context, teams, {
    operation: `${GRAPH_BASE}/teams/{id}?$select=${TEAM_SELECT}`,
    url: (t) => {
      const id = safeId(t['id']);
      return id === undefined ? undefined : `${GRAPH_BASE}/teams/${encodeURIComponent(id)}?$select=${TEAM_SELECT}`;
    },
    target: (t) => (typeof t['id'] === 'string' ? t['id'] : null),
    what: 'team settings',
  });
  return teams.map((listed) => {
    // A team whose settings could not be read keeps null settings (unknown, never "restricted").
    const team = details.get(listed);
    if (team !== undefined && (rec(team['memberSettings']) === undefined || rec(team['guestSettings']) === undefined)) {
      state.partial = true;
      state.errors.push(
        message('TEAM_SETTINGS_MISSING', 'Microsoft Graph returned a team without its member or guest settings.', typeof listed['id'] === 'string' ? listed['id'] : null),
      );
    }
    return {
      id: val(listed, 'id'),
      displayName: val(team ?? listed, 'displayName'),
      visibility: val(team ?? listed, 'visibility'),
      isArchived: val(team, 'isArchived'),
      memberSettings: pickOrNull(val(team, 'memberSettings'), MEMBER_KEYS),
      guestSettings: pickOrNull(val(team, 'guestSettings'), GUEST_KEYS),
    };
  });
};

export const M365_PLAN: readonly PlannedDataset[] = [
  { definition: m365SharePointSettings, collector: sharePointSettings },
  { definition: m365TeamsAppSettings, collector: teamsAppSettings },
  { definition: m365TeamsTeamSettings, collector: teamsTeamSettings },
];
