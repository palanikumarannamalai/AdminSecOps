import { intuneCompliancePolicies, intuneDeviceOverview, intuneSettings } from '@adminsecops/schemas';
import { GRAPH_BASE, GRAPH_ORIGIN, GraphRequestError } from './graph-client.js';
import type { PlannedDataset } from './package.js';
import {
  arr,
  fanout,
  firstOf,
  getAll,
  getOne,
  licensed,
  message,
  odataType,
  rec,
  safeId,
  val,
  type DatasetCollector,
  type DatasetState,
  type Rec,
} from './runtime.js';

/**
 * Microsoft Intune datasets through Microsoft Graph v1.0 (GET only), mirroring the
 * PowerShell collector (collectors/powershell/intune/Intune.ps1) without its coercions:
 * a missing Graph value stays null so the dataset schema rejects it instead of it
 * becoming a default secure value.
 */

/** Intune service plans (same names as the PowerShell collector). */
export const INTUNE_PLANS = [
  'INTUNE_A',
  'INTUNE_EDU',
  'INTUNE_SMBIZ',
  'INTUNE_A_VL',
  'Intune_Defender',
  'INTUNE_P1',
];
const FEATURE = 'Microsoft Intune';

/** Exact Graph beta URL of the one allowed beta exception (GRAPH_BETA_EXCEPTIONS). */
export const INTUNE_SETTINGS_BETA_URL = `${GRAPH_ORIGIN}/beta/deviceManagement/settings`;

/**
 * deviceManagementSettings is a documented complex property of the deviceManagement singleton
 * (v1.0 and beta resource pages). Live v1.0 responses omitted it with and without $select, and
 * the v1.0 "Get deviceManagement" pages were withdrawn, so after two v1.0 attempts the settings
 * are read once from the beta property path. Beta is used for this single path only; a missing
 * property is never replaced by a default (the schema then rejects the evidence).
 */
const settings: DatasetCollector = async (state, context) => {
  if (!licensed(state, context, INTUNE_PLANS, FEATURE)) return null;
  let dm = await getOne(state, context, `${GRAPH_BASE}/deviceManagement?$select=settings`);
  let s = rec(val(dm, 'settings'));
  if (s === undefined) {
    // The deviceManagement singleton may ignore $select and omit settings (seen in live validation).
    dm = await getOne(state, context, `${GRAPH_BASE}/deviceManagement`);
    s = rec(val(dm, 'settings'));
  }
  if (s === undefined) {
    state.operations.push(`GET ${INTUNE_SETTINGS_BETA_URL}`);
    const body = rec(await context.client.getGraphBetaException(INTUNE_SETTINGS_BETA_URL));
    // A complex-property response carries the properties at the top level; tolerate a "value" wrapper.
    const beta = rec(val(body, 'value')) ?? body;
    s = beta;
    if (beta !== undefined && ['secureByDefault', 'deviceComplianceCheckinThresholdDays', 'isScheduledActionEnabled'].some((k) => k in beta)) {
      state.warnings.push(
        message(
          'GRAPH_BETA_SOURCE',
          'Microsoft Graph v1.0 did not return deviceManagement settings; they were read from the Microsoft Graph beta property /beta/deviceManagement/settings. Beta APIs can change without notice.',
        ),
      );
    } else {
      s = undefined;
    }
  }
  if (s === undefined)
    throw new GraphRequestError(
      'invalid-response',
      'Microsoft Graph did not return the Intune deviceManagement settings (v1.0 with and without $select, and the beta settings property). This is a service response gap, not a missing consent; the setting is not assessed.',
    );
  return {
    secureByDefault: val(s, 'secureByDefault'),
    deviceComplianceCheckinThresholdDays: val(s, 'deviceComplianceCheckinThresholdDays'),
    isScheduledActionEnabled: val(s, 'isScheduledActionEnabled'),
  };
};

const deviceOverview: DatasetCollector = async (state, context) => {
  if (!licensed(state, context, INTUNE_PLANS, FEATURE)) return null;
  const o = await getOne(state, context, `${GRAPH_BASE}/deviceManagement/managedDeviceOverview`);
  const os = rec(val(o, 'deviceOperatingSystemSummary'));
  return {
    enrolledDeviceCount: val(o, 'enrolledDeviceCount'),
    windowsCount: val(os, 'windowsCount'),
    macOSCount: val(os, 'macOSCount'),
    iosCount: val(os, 'iosCount'),
    androidCount: val(os, 'androidCount'),
  };
};

function assignmentsOf(raw: unknown): Rec[] | null {
  const list = arr(raw);
  if (list === null) return null;
  return list.map((a) => {
    const target = rec(val(rec(a), 'target'));
    return { targetType: odataType(target), groupId: val(target, 'groupId') };
  });
}

function unreadableAssignments(state: DatasetState, id: string | null): void {
  state.partial = true;
  state.errors.push(
    message(
      'ASSIGNMENTS_UNAVAILABLE',
      'The assignments of a compliance policy could not be read; the policy is reported without assignments and coverage is incomplete.',
      id,
    ),
  );
}

const compliancePolicies: DatasetCollector = async (state, context) => {
  if (!licensed(state, context, INTUNE_PLANS, FEATURE)) return null;
  const policies = (
    await getAll(state, context, `${GRAPH_BASE}/deviceManagement/deviceCompliancePolicies?$expand=assignments`)
  ).map((p) => rec(p));

  // $expand=assignments is documented for this collection; when the service omits the
  // navigation property, read the assignments of each policy (bounded fan-out).
  const missing = policies.filter((p): p is Rec => p !== undefined && !Array.isArray(p['assignments']));
  const fetched = await fanout(state, context, missing, {
    operation: `${GRAPH_BASE}/deviceManagement/deviceCompliancePolicies/{id}/assignments`,
    url: (p) => {
      const id = safeId(p['id']);
      return id === undefined
        ? undefined
        : `${GRAPH_BASE}/deviceManagement/deviceCompliancePolicies/${encodeURIComponent(id)}/assignments`;
    },
    target: (p) => (typeof p['id'] === 'string' ? p['id'] : null),
    what: 'compliance policy assignments',
  });

  return policies.map((p) => {
    if (p !== undefined && p['assignments@odata.nextLink'] !== undefined && p['assignments@odata.nextLink'] !== null) {
      state.partial = true;
      state.errors.push(message('ASSIGNMENTS_TRUNCATED', 'Expanded compliance policy assignments are incomplete.', typeof p['id'] === 'string' ? p['id'] : null));
    }
    let assignments = assignmentsOf(val(p, 'assignments'));
    if (assignments === null && p !== undefined) {
      const body = fetched.get(p);
      // A collection response must carry a value array; anything else is incomplete.
      assignments = body === undefined ? null : assignmentsOf(body['value']);
      if (body !== undefined && assignments === null)
        unreadableAssignments(state, typeof p['id'] === 'string' ? p['id'] : null);
      if (body !== undefined && typeof body['@odata.nextLink'] === 'string') {
        state.partial = true;
        state.errors.push(
          message('ASSIGNMENTS_TRUNCATED', 'A compliance policy has more assignment pages than were read.', typeof p['id'] === 'string' ? p['id'] : null),
        );
      }
    }
    // Missing assignments are incomplete evidence (Partial); the empty list only lets the
    // policy's settings be reported. The Partial status keeps any PASS from being claimed.
    if (assignments === null) state.partial = true;
    return {
      id: val(p, 'id'),
      displayName: val(p, 'displayName'),
      odataType: odataType(p),
      lastModifiedDateTime: val(p, 'lastModifiedDateTime'),
      assignments: assignments ?? [],
      settings: {
        bitLockerEnabled: val(p, 'bitLockerEnabled'),
        secureBootEnabled: val(p, 'secureBootEnabled'),
        codeIntegrityEnabled: val(p, 'codeIntegrityEnabled'),
        storageRequireEncryption: firstOf(p, ['storageRequireEncryption', 'storageRequireDeviceEncryption']),
        passwordRequired: firstOf(p, ['passwordRequired', 'passcodeRequired']),
        defenderEnabled: val(p, 'defenderEnabled'),
        rtpEnabled: val(p, 'rtpEnabled'),
        antivirusRequired: val(p, 'antivirusRequired'),
        firewallEnabled: firstOf(p, ['firewallEnabled', 'activeFirewallRequired']),
        tpmRequired: val(p, 'tpmRequired'),
        osMinimumVersion: val(p, 'osMinimumVersion'),
      },
    };
  });
};

export const INTUNE_PLAN: readonly PlannedDataset[] = [
  { definition: intuneSettings, collector: settings },
  { definition: intuneDeviceOverview, collector: deviceOverview },
  { definition: intuneCompliancePolicies, collector: compliancePolicies },
];
