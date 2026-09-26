import {
  CONNECTOR_IDS,
  CONNECTOR_RESOURCES,
  ConsentRequiredError,
  checkConnectorAccessToken,
  decryptConnectorTokens,
  encryptConnectorTokens,
  parseConnectorMap,
  serializeConnectorMap,
  type ConnectorId,
  type ConnectorMap,
  type ConnectorTokens,
  type createAuth,
} from './auth.js';
import type { Config } from './config.js';
import type { ConnectorGap, ConnectorInput, ExchangeRunner } from './collector/index.js';

/**
 * Per-resource connector state for the online UI and the worker. A connector is one separate
 * delegated consent and token (Azure Resource Manager or Exchange Online) of the signed-in
 * administrator for the session tenant. On-premises sources have no online connector.
 */

export type ConnectorViewState = 'connected' | 'not-connected' | 'expired' | 'disabled' | 'runtime-unavailable' | 'unsupported';

export interface ConnectorView {
  readonly id: ConnectorId | 'onPremises';
  readonly label: string;
  readonly state: ConnectorViewState;
  readonly reason: string;
  /** Delegated permission and directory/Azure role the connector needs. */
  readonly permission: string;
  readonly role: string;
  readonly connectUrl: string | null;
  readonly reconnectUrl: string | null;
  readonly connectedAt: string | null;
}

type Auth = ReturnType<typeof createAuth>;

const REQUIREMENTS: Record<ConnectorId, { permission: string; role: string }> = {
  azure: {
    permission: 'Azure Service Management: user_impersonation (delegated). This permission is not read-only by itself; the token carries the signed-in user\u0027s Azure authority. AdminSecOps sends only allow-listed read requests; use Reader to limit token authority.',
    role: 'Azure Reader (or higher) on each subscription to assess; no Azure role is assigned or changed by AdminSecOps',
  },
  exchange: {
    permission: 'Office 365 Exchange Online: Exchange.Manage (delegated). This permission is not read-only by itself: the service runs only a fixed list of Get-* cmdlets, and the signed-in role decides what can be read',
    role: 'Global Reader or Exchange View-Only Organization Management is recommended; Security Reader alone does not cover every setting',
  },
};

export function connectorLabel(id: ConnectorId): string {
  return CONNECTOR_RESOURCES[id].label;
}

/** Job-level connector payload: separately sealed tokens plus connectors known to be unusable. */
export interface JobConnectors {
  readonly tokens: ConnectorMap;
  readonly gaps: Partial<Record<ConnectorId, 'expired' | 'consent-required'>>;
}

export function serializeJobConnectors(value: JobConnectors): string | null {
  const tokens = serializeConnectorMap(value.tokens);
  const gaps = Object.entries(value.gaps).filter(([id, state]) => CONNECTOR_IDS.includes(id as ConnectorId) && (state === 'expired' || state === 'consent-required'));
  if (tokens === null && gaps.length === 0) return null;
  return JSON.stringify({ ...(tokens === null ? {} : (JSON.parse(tokens) as object)), ...(gaps.length > 0 ? { gaps: Object.fromEntries(gaps) } : {}) });
}

export function parseJobConnectors(value: string | null | undefined): JobConnectors {
  const tokens = parseConnectorMap(value);
  const gaps: JobConnectors['gaps'] = {};
  try {
    const raw = value ? (JSON.parse(value) as { gaps?: unknown }).gaps : undefined;
    if (typeof raw === 'object' && raw !== null) {
      for (const id of CONNECTOR_IDS) {
        const state = (raw as Record<string, unknown>)[id];
        if (state === 'expired' || state === 'consent-required') gaps[id] = state;
      }
    }
  } catch {
    // Unreadable connector data is ignored: those connectors count as not connected.
  }
  return { tokens, gaps };
}

function tryDecrypt(config: Config, map: ConnectorMap, id: ConnectorId, tenantId: string, userId: string): ConnectorTokens | undefined {
  const sealed = map[id];
  if (sealed === undefined) return undefined;
  try {
    return decryptConnectorTokens(sealed, config.tokenEncryptionKey, { connector: id, tenantId, userId });
  } catch {
    return undefined;
  }
}

/** What the online home page shows for each connector. Never exposes tokens. */
export async function describeConnectors(
  config: Config,
  session: { tenantId: string; userId: string; encryptedConnectors?: string | null },
  exchangeRunner: ExchangeRunner | undefined,
): Promise<ConnectorView[]> {
  const map = parseConnectorMap(session.encryptedConnectors);
  const views: ConnectorView[] = [];
  for (const id of CONNECTOR_IDS) {
    const base = { id, label: connectorLabel(id), ...REQUIREMENTS[id], connectUrl: null, reconnectUrl: null, connectedAt: null };
    if (!config.connectors[id]) {
      views.push({ ...base, state: 'disabled', reason: `The ${connectorLabel(id)} connector is not enabled on this deployment, so these controls are not assessed.` });
      continue;
    }
    if (id === 'exchange') {
      const runtime = exchangeRunner === undefined ? { available: false, reason: 'No Exchange Online runner is configured.' } : await exchangeRunner.status();
      if (!runtime.available) {
        views.push({ ...base, state: 'runtime-unavailable', reason: `The Exchange Online runtime is not available on this server. ${runtime.reason}` });
        continue;
      }
    }
    const tokens = tryDecrypt(config, map, id, session.tenantId, session.userId);
    const links = { connectUrl: `/auth/connect/${id}`, reconnectUrl: `/auth/connect/${id}?consent=true` };
    if (tokens === undefined) {
      views.push({ ...base, ...links, state: 'not-connected', reason: `Not connected. Connect ${connectorLabel(id)} to include it in the next assessment (a separate Microsoft sign-in and consent).` });
    } else if (tokens.refreshToken === undefined && tokens.expiresAt <= Date.now() + 120_000) {
      views.push({ ...base, ...links, state: 'expired', reason: 'The connection has expired. Reconnect to include it in the next assessment.', connectedAt: new Date(tokens.connectedAt).toISOString() });
    } else {
      views.push({ ...base, ...links, state: 'connected', reason: 'Connected for read-only collection in the next assessment.', connectedAt: new Date(tokens.connectedAt).toISOString() });
    }
  }
  views.push({
    id: 'onPremises',
    label: 'On-premises Active Directory, AD CS, Group Policy and Windows',
    state: 'unsupported',
    reason: 'Private networks cannot be reached by the online service. An outbound-only on-premises connector is designed but not available (see the Coverage page); these controls are not assessed online.',
    permission: 'Not applicable',
    role: 'Not applicable',
    connectUrl: null,
    reconnectUrl: null,
    connectedAt: null,
  });
  return views;
}

/**
 * Refresh the session's connector tokens for a new job. Each connector is refreshed and
 * checked independently; one that cannot be refreshed is recorded as expired or
 * consent-required for the job (and removed from the session) instead of failing the job.
 */
export async function prepareJobConnectors(
  auth: Auth,
  config: Config,
  session: { tenantId: string; userId: string; encryptedConnectors?: string | null },
): Promise<{ job: string | null; session: string | null }> {
  const map = parseConnectorMap(session.encryptedConnectors);
  const next: ConnectorMap = {};
  const gaps: JobConnectors['gaps'] = {};
  for (const id of CONNECTOR_IDS) {
    if (!config.connectors[id]) continue;
    const tokens = tryDecrypt(config, map, id, session.tenantId, session.userId);
    if (tokens === undefined) continue;
    try {
      next[id] = encryptConnectorTokens(await auth.refreshConnector(tokens, session), config.tokenEncryptionKey);
    } catch (error) {
      gaps[id] = error instanceof ConsentRequiredError ? 'consent-required' : 'expired';
    }
  }
  return { job: serializeJobConnectors({ tokens: next, gaps }), session: serializeConnectorMap(next) };
}

const GAP_REASONS: Record<ConnectorId, Record<'not-connected' | 'expired' | 'consent-required' | 'disabled', string>> = {
  azure: {
    'not-connected': 'Azure Resource Manager was not connected when this assessment started. Connect Azure on the online home page to assess Azure subscriptions.',
    expired: 'The Azure Resource Manager connection had expired. Reconnect Azure on the online home page, then run the assessment again.',
    'consent-required': 'Microsoft reported that consent for Azure Resource Manager (user_impersonation) is missing. A tenant administrator must consent; use "Reconnect Azure" on the online home page.',
    disabled: 'The Azure Resource Manager connector is not enabled on this deployment.',
  },
  exchange: {
    'not-connected': 'Exchange Online was not connected when this assessment started. Connect Exchange Online on the online home page to assess these settings.',
    expired: 'The Exchange Online connection had expired. Reconnect Exchange Online on the online home page, then run the assessment again.',
    'consent-required': 'Microsoft reported that consent for Exchange Online (Exchange.Manage) is missing. A tenant administrator must consent; use "Reconnect Exchange Online" on the online home page.',
    disabled: 'The Exchange Online connector is not enabled on this deployment.',
  },
};

/**
 * Connector inputs for the collector from a claimed job: decrypt (bound to the job tenant and
 * user), refresh and check each token. Anything unusable becomes an explicit gap.
 */
export async function resolveJobConnectors(
  auth: Auth,
  config: Config,
  job: { tenantId: string; userId: string; encryptedConnectors?: string | null },
  exchangeRunner: ExchangeRunner | undefined,
): Promise<{
  azure: ConnectorInput<{ readonly accessToken: string }>;
  exchange: ConnectorInput<{ readonly accessToken: string; readonly userPrincipalName: string; readonly runner: ExchangeRunner }>;
}> {
  const { tokens: map, gaps } = parseJobConnectors(job.encryptedConnectors);
  const resolve = async (id: ConnectorId): Promise<ConnectorGap | ConnectorTokens> => {
    if (!config.connectors[id]) return { state: 'unavailable', reason: GAP_REASONS[id].disabled };
    const gap = gaps[id];
    if (gap !== undefined) return { state: gap, reason: GAP_REASONS[id][gap] };
    const tokens = tryDecrypt(config, map, id, job.tenantId, job.userId);
    if (tokens === undefined) return { state: 'not-connected', reason: GAP_REASONS[id]['not-connected'] };
    try {
      const fresh = await auth.refreshConnector(tokens, job);
      checkConnectorAccessToken(fresh.accessToken, id, job.tenantId, job.userId);
      return fresh;
    } catch (error) {
      const state = error instanceof ConsentRequiredError ? 'consent-required' : 'expired';
      return { state, reason: GAP_REASONS[id][state] };
    }
  };
  const azure = await resolve('azure');
  const exchange = await resolve('exchange');
  const isGap = (v: ConnectorGap | ConnectorTokens): v is ConnectorGap => 'state' in v;
  return {
    azure: isGap(azure) ? azure : { state: 'connected', accessToken: azure.accessToken },
    exchange: isGap(exchange)
      ? exchange
      : exchangeRunner === undefined || exchange.userPrincipalName === undefined
        ? { state: 'unavailable', reason: 'The Exchange Online runner is not configured on this server.' }
        : { state: 'connected', accessToken: exchange.accessToken, userPrincipalName: exchange.userPrincipalName, runner: exchangeRunner },
  };
}
