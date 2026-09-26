import type { CollectionStatus } from '@adminsecops/core';
import {
  exchangeAcceptedDomains,
  exchangeAdminAuditLogConfig,
  exchangeAtpPolicy,
  exchangeDkimSigningConfigs,
  exchangeMailDnsRecords,
  exchangeMailboxForwarding,
  exchangeOrganizationConfig,
  exchangeOutboundSpamPolicies,
  exchangeRemoteDomains,
  exchangeSmtpAuthMailboxes,
  exchangeTransportConfig,
} from '@adminsecops/schemas';
import { createSystemTxtResolver, isQueryableDomain, type TxtLookup, type TxtResolver } from './dns.js';
import {
  EXCHANGE_MODULE_VERSION,
  EXCHANGE_OPERATIONS,
  ExchangeRunnerError,
  type ExchangeItem,
  type ExchangeOperationId,
  type ExchangeRunResult,
  type ExchangeRunner,
} from './exchange-runner.js';
import { CollectionCancelledError, GraphRequestError } from './graph-client.js';
import type { ConnectorInput, PlannedDataset } from './package.js';
import {
  connectorUnavailable,
  licensed,
  message,
  type CollectionContext,
  type ConnectorGap,
  type DatasetCollector,
  type DatasetState,
} from './runtime.js';

export type { ExchangeRunner } from './exchange-runner.js';

/**
 * Exchange Online and Defender for Office 365 datasets, read server-side by the fixed
 * PowerShell runner with the signed-in administrator's delegated Exchange Online token, and
 * public mail DNS records. Delegated Microsoft Graph cannot read these settings and is never
 * used as a substitute. Values are mapped without coercion: a missing value stays null and the
 * dataset schema decides whether the evidence is usable.
 */

export type ExchangeConnectorInput = ConnectorInput<{ readonly accessToken: string; readonly userPrincipalName: string; readonly runner: ExchangeRunner }>;

/** Bounds of list operations; exceeding them makes the dataset Partial. */
export const EXCHANGE_LIMITS = { maxItems: 5000, maxMailboxScan: 20_000, maxDnsDomains: 50 } as const;

type RunOutcome =
  | { readonly kind: 'ok'; readonly result: ExchangeRunResult }
  | { readonly kind: 'gap'; readonly gap: ConnectorGap }
  | { readonly kind: 'status'; readonly status: CollectionStatus; readonly code: string; readonly message: string };

const ATP_PLANS = ['ATP_ENTERPRISE', 'THREAT_INTELLIGENCE'];
const ROLE_HINT = 'The signed-in account needs an Exchange Online role that can read configuration, such as Global Reader or View-Only Organization Management.';

async function runOnce(context: CollectionContext, input: ExchangeConnectorInput): Promise<RunOutcome> {
  if (input.state !== 'connected') return { kind: 'gap', gap: input };
  const signal = context.shared.get('signal') as AbortSignal | undefined;
  const runtime = await input.runner.status(signal);
  if (!runtime.available) return { kind: 'gap', gap: { state: 'unavailable', reason: `The Exchange Online runtime is not available on this server. ${runtime.reason}` } };
  let result: ExchangeRunResult;
  try {
    result = await input.runner.run(
      { tenantId: context.tenantId, userPrincipalName: input.userPrincipalName, accessToken: input.accessToken, maxItems: EXCHANGE_LIMITS.maxItems, maxMailboxScan: EXCHANGE_LIMITS.maxMailboxScan },
      signal,
    );
  } catch (error) {
    if (error instanceof CollectionCancelledError) throw error;
    if (error instanceof ExchangeRunnerError) {
      if (error.code === 'RUNTIME_UNAVAILABLE') return { kind: 'gap', gap: { state: 'unavailable', reason: error.message } };
      return { kind: 'status', status: 'Failed', code: `EXCHANGE_${error.code}`, message: error.message };
    }
    throw error;
  }
  if (result.status === 'runtime-unavailable') return { kind: 'gap', gap: { state: 'unavailable', reason: `The server does not have PowerShell with ExchangeOnlineManagement ${EXCHANGE_MODULE_VERSION}.` } };
  if (result.status === 'connect-unauthorized') return { kind: 'status', status: 'Unauthorized', code: 'EXCHANGE_CONNECT_UNAUTHORIZED', message: `Exchange Online refused the delegated connection. ${ROLE_HINT} Reconnect Exchange Online if consent was changed.` };
  if (result.status !== 'ok') return { kind: 'status', status: 'Failed', code: 'EXCHANGE_CONNECT_FAILED', message: 'The Exchange Online connection could not be established; no Exchange data was collected.' };
  if (result.connectedTenantId === null || result.connectedTenantId.toLowerCase() !== context.tenantId) {
    // The access token was already bound to the verified tenant; a different or unreported
    // connected tenant means the evidence cannot be attributed, so everything is discarded.
    return { kind: 'status', status: 'Failed', code: 'EXCHANGE_TENANT_NOT_VERIFIED', message: 'The Exchange Online session could not be confirmed to belong to the verified tenant; no Exchange data was used.' };
  }
  return { kind: 'ok', result };
}

/** Runs the Exchange collection once per assessment and returns the operation result or null. */
async function operation(state: DatasetState, context: CollectionContext, id: ExchangeOperationId): Promise<readonly ExchangeItem[] | null> {
  const input = context.shared.get('exchange') as ExchangeConnectorInput | undefined;
  if (input === undefined) return connectorUnavailable(state, { state: 'not-connected', reason: 'Exchange Online is not connected for this session.' });
  let pending = context.shared.get('exchange.run') as Promise<RunOutcome> | undefined;
  if (pending === undefined) {
    pending = runOnce(context, input);
    context.shared.set('exchange.run', pending);
  }
  const outcome = await pending;
  if (outcome.kind === 'gap') return connectorUnavailable(state, outcome.gap);
  state.operations.push(`${EXCHANGE_OPERATIONS[id].cmdlet} (ExchangeOnlineManagement ${EXCHANGE_MODULE_VERSION}, delegated, read-only allowlist)`);
  if (outcome.kind === 'status') {
    state.forcedStatus = { status: outcome.status, code: outcome.code, message: outcome.message };
    return null;
  }
  const op = outcome.result.operations[id];
  if (op === undefined) {
    state.forcedStatus = { status: 'Failed', code: 'EXCHANGE_OPERATION_MISSING', message: `${EXCHANGE_OPERATIONS[id].cmdlet} did not return a result.` };
    return null;
  }
  if (op.status !== 'ok') {
    const cmdlet = EXCHANGE_OPERATIONS[id].cmdlet;
    state.forcedStatus =
      op.status === 'unauthorized'
        ? { status: 'Unauthorized', code: 'UNAUTHORIZED', message: `${cmdlet} was denied. ${ROLE_HINT}` }
        : op.status === 'not-available'
          ? { status: 'Failed', code: 'CMDLET_NOT_AVAILABLE', message: `${cmdlet} is not available in this Exchange Online session.` }
          : { status: 'Failed', code: 'EXCHANGE_OPERATION_FAILED', message: `${cmdlet} failed; the dataset was not collected.` };
    return null;
  }
  if (op.truncated) {
    state.partial = true;
    state.errors.push(message('RESULT_LIMIT', `${EXCHANGE_OPERATIONS[id].cmdlet} returned more objects than the collection limit; results are incomplete.`));
  }
  return op.items;
}

const v = (item: ExchangeItem | undefined, key: string): unknown => item?.[key] ?? null;

function single(items: readonly ExchangeItem[], cmdlet: string): ExchangeItem {
  const first = items[0];
  if (first === undefined) throw new GraphRequestError('invalid-response', `${cmdlet} returned no configuration object.`);
  return first;
}

const organizationConfig: DatasetCollector = async (state, context) => {
  const items = await operation(state, context, 'organizationConfig');
  if (items === null) return null;
  const o = single(items,'Get-OrganizationConfig');
  return {
    auditDisabled: v(o, 'AuditDisabled'),
    oAuth2ClientProfileEnabled: v(o, 'OAuth2ClientProfileEnabled'),
    customerLockBoxEnabled: v(o, 'CustomerLockBoxEnabled'),
    mailTipsExternalRecipientsTipsEnabled: v(o, 'MailTipsExternalRecipientsTipsEnabled'),
  };
};

const transportConfig: DatasetCollector = async (state, context) => {
  const items = await operation(state, context, 'transportConfig');
  if (items === null) return null;
  return { smtpClientAuthenticationDisabled: v(single(items,'Get-TransportConfig'), 'SmtpClientAuthenticationDisabled') };
};

const adminAuditLogConfig: DatasetCollector = async (state, context) => {
  const items = await operation(state, context, 'adminAuditLogConfig');
  if (items === null) return null;
  return { unifiedAuditLogIngestionEnabled: v(single(items,'Get-AdminAuditLogConfig'), 'UnifiedAuditLogIngestionEnabled') };
};

const acceptedDomains: DatasetCollector = async (state, context) => {
  const items = await operation(state, context, 'acceptedDomains');
  if (items === null) return null;
  const out = items.map((d) => ({ domainName: v(d, 'DomainName'), domainType: v(d, 'DomainType'), default: v(d, 'Default'), isCoexistenceDomain: v(d, 'IsCoexistenceDomain') }));
  if (!state.partial) {
    // Complete accepted domains are the authoritative source of the mail DNS domain list.
    context.shared.set(
      'exchange.authoritativeDomains',
      out.filter((d) => typeof d.domainType === 'string' && d.domainType.toLowerCase() === 'authoritative' && typeof d.domainName === 'string').map((d) => d.domainName as string),
    );
  }
  return out;
};

const dkimSigningConfigs: DatasetCollector = async (state, context) => {
  const items = await operation(state, context, 'dkimSigningConfigs');
  if (items === null) return null;
  return items.map((d) => ({ domain: v(d, 'Domain'), enabled: v(d, 'Enabled'), status: v(d, 'Status') }));
};

const outboundSpamPolicies: DatasetCollector = async (state, context) => {
  const items = await operation(state, context, 'outboundSpamPolicies');
  if (items === null) return null;
  return items.map((p) => ({ name: v(p, 'Name'), isDefault: v(p, 'IsDefault'), autoForwardingMode: v(p, 'AutoForwardingMode') }));
};

const remoteDomains: DatasetCollector = async (state, context) => {
  const items = await operation(state, context, 'remoteDomains');
  if (items === null) return null;
  return items.map((d) => ({ name: v(d, 'Name'), domainName: v(d, 'DomainName'), autoForwardEnabled: v(d, 'AutoForwardEnabled') }));
};

const mailboxForwarding: DatasetCollector = async (state, context) => {
  const items = await operation(state, context, 'mailboxForwarding');
  if (items === null) return null;
  return items.map((m) => ({
    userPrincipalName: v(m, 'UserPrincipalName'),
    recipientTypeDetails: v(m, 'RecipientTypeDetails'),
    forwardingSmtpAddress: v(m, 'ForwardingSmtpAddress'),
    forwardingAddress: v(m, 'ForwardingAddress'),
    deliverToMailboxAndForward: v(m, 'DeliverToMailboxAndForward'),
  }));
};

const smtpAuthMailboxes: DatasetCollector = async (state, context) => {
  const items = await operation(state, context, 'smtpAuthMailboxes');
  if (items === null) return null;
  state.warnings.push(message('IDENTIFIER_PRIMARY_SMTP', 'Get-EXOCASMailbox does not return UserPrincipalName; userPrincipalName contains the primary SMTP address.'));
  return items.map((m) => ({ userPrincipalName: v(m, 'PrimarySmtpAddress'), smtpClientAuthenticationDisabled: v(m, 'SmtpClientAuthenticationDisabled') }));
};

const atpPolicy: DatasetCollector = async (state, context) => {
  if (!licensed(state, context, ATP_PLANS, 'Microsoft Defender for Office 365')) return null;
  const items = await operation(state, context, 'atpPolicy');
  if (items === null) {
    if (state.forcedStatus?.code === 'CMDLET_NOT_AVAILABLE') {
      state.forcedStatus = { status: 'NotApplicable', code: 'FEATURE_NOT_AVAILABLE', message: 'Get-AtpPolicyForO365 is not available in this Exchange Online session, which indicates Microsoft Defender for Office 365 is not licensed.' };
    }
    return null;
  }
  const o = single(items,'Get-AtpPolicyForO365');
  return { enableATPForSPOTeamsODB: v(o, 'EnableATPForSPOTeamsODB'), enableSafeDocs: v(o, 'EnableSafeDocs'), allowSafeDocsOpen: v(o, 'AllowSafeDocsOpen') };
};

// ---------------------------------------------------------------------------------------------
// Public mail DNS records
// ---------------------------------------------------------------------------------------------

function matching(lookup: TxtLookup, prefix: RegExp): { lookupStatus: 'Found' | 'NotFound' | 'Error'; records: string[] } {
  if (lookup.status === 'Error') return { lookupStatus: 'Error', records: [] };
  const records = lookup.records.filter((r) => prefix.test(r)).map((r) => r.slice(0, 4096));
  return { lookupStatus: records.length > 0 ? 'Found' : 'NotFound', records };
}

const SPF = /^\s*v=spf1(\s|;|$)/i;
const DMARC = /^\s*v=DMARC1(\s|;|$)/i;

const mailDnsRecords: DatasetCollector = async (state, context) => {
  const fromExchange = context.shared.get('exchange.authoritativeDomains') as readonly string[] | undefined;
  let source: string[];
  if (fromExchange !== undefined) {
    source = [...fromExchange];
  } else {
    const verified = context.verifiedDomains;
    if (verified === undefined) throw new GraphRequestError('invalid-response', 'The tenant domains are unknown, so no mail DNS records were checked.');
    source = verified.filter((d) => d.capabilities !== null && /(^|,\s*)Email(\s*,|$)/i.test(d.capabilities)).map((d) => d.name);
    state.warnings.push(
      message(
        'DOMAINS_FROM_VERIFIED_DOMAINS',
        'Exchange Online accepted domains were not available, so the tenant verified domains with the Email capability were checked instead. This list can differ from the Exchange Online authoritative accepted domains.',
      ),
    );
  }
  state.warnings.push(
    message(
      'DNS_PROVENANCE',
      "Records were read from public DNS through the hosting platform's recursive resolver (not the domains' authoritative servers, not DNSSEC-validated) at collection time. They show published SPF and DMARC records only and do not show Exchange accepted domains or DKIM signing state.",
    ),
  );
  const domains = [...new Set(source.map((d) => d.trim().toLowerCase()))].filter((d) => !/(^|\.)onmicrosoft\.com$/.test(d)).sort();
  const invalid = domains.filter((d) => !isQueryableDomain(d));
  if (invalid.length > 0) {
    state.partial = true;
    state.errors.push(message('DOMAIN_NOT_QUERYABLE', `${invalid.length} domain name(s) were not valid DNS names and were not checked.`));
  }
  let queryable = domains.filter(isQueryableDomain);
  if (queryable.length > EXCHANGE_LIMITS.maxDnsDomains) {
    state.partial = true;
    state.errors.push(message('FANOUT_LIMIT', `Only the first ${EXCHANGE_LIMITS.maxDnsDomains} of ${queryable.length} domains were checked; results are incomplete.`));
    queryable = queryable.slice(0, EXCHANGE_LIMITS.maxDnsDomains);
  }
  const resolver = (context.shared.get('dnsResolver') as TxtResolver | undefined) ?? createSystemTxtResolver();
  const signal = context.shared.get('signal') as AbortSignal | undefined;
  state.operations.push('DNS TXT <domain>', 'DNS TXT _dmarc.<domain>');
  const out = [];
  let errors = 0;
  for (const domain of queryable) {
    context.client.throwIfCancelled();
    const spf = matching(await resolver.resolveTxt(domain, signal), SPF);
    const dmarc = matching(await resolver.resolveTxt(`_dmarc.${domain}`, signal), DMARC);
    for (const r of [spf, dmarc]) {
      if (r.lookupStatus === 'Error') {
        errors += 1;
        state.warnings.push(message('DNS_LOOKUP_ERROR', 'A TXT lookup failed; the domain is evaluated as not assessed for that record.', domain));
      }
    }
    out.push({ domain, spf, dmarc });
  }
  if (queryable.length > 0 && errors >= queryable.length * 2) {
    throw new GraphRequestError('network', 'All DNS lookups failed; mail DNS records could not be checked.');
  }
  return out;
};

export const EXCHANGE_PLAN: readonly PlannedDataset[] = [
  { definition: exchangeOrganizationConfig, collector: organizationConfig },
  { definition: exchangeTransportConfig, collector: transportConfig },
  { definition: exchangeAdminAuditLogConfig, collector: adminAuditLogConfig },
  { definition: exchangeAcceptedDomains, collector: acceptedDomains },
  { definition: exchangeDkimSigningConfigs, collector: dkimSigningConfigs },
  { definition: exchangeOutboundSpamPolicies, collector: outboundSpamPolicies },
  { definition: exchangeRemoteDomains, collector: remoteDomains },
  { definition: exchangeMailboxForwarding, collector: mailboxForwarding },
  { definition: exchangeSmtpAuthMailboxes, collector: smtpAuthMailboxes },
  { definition: exchangeAtpPolicy, collector: atpPolicy },
  // After acceptedDomains so the authoritative domain list is used when available.
  { definition: exchangeMailDnsRecords, collector: mailDnsRecords },
];
