/**
 * Builders for schema-valid Microsoft 365 (Exchange Online, mail DNS, SharePoint,
 * Defender for Office 365) evidence used by control tests. They produce
 * collector-shaped input that the test inventory validates with the real schemas.
 */

export function organizationConfig(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    auditDisabled: false,
    oAuth2ClientProfileEnabled: true,
    customerLockBoxEnabled: null,
    mailTipsExternalRecipientsTipsEnabled: null,
    ...overrides,
  };
}

export function acceptedDomain(
  domainName: string,
  overrides: { domainType?: string; default?: boolean; isCoexistenceDomain?: boolean | null } = {},
): Record<string, unknown> {
  return {
    domainName,
    domainType: overrides.domainType ?? 'Authoritative',
    default: overrides.default ?? false,
    isCoexistenceDomain: overrides.isCoexistenceDomain ?? null,
  };
}

export function dkimConfig(
  domain: string,
  enabled: boolean,
  status: string | null = enabled ? 'Valid' : null,
): Record<string, unknown> {
  return { domain, enabled, status };
}

export function outboundPolicy(
  name: string,
  autoForwardingMode: string,
  isDefault = false,
): Record<string, unknown> {
  return { name, isDefault, autoForwardingMode };
}

export function remoteDomain(
  name: string,
  domainName: string,
  autoForwardEnabled: boolean,
): Record<string, unknown> {
  return { name, domainName, autoForwardEnabled };
}

export interface ForwardingInput {
  recipientTypeDetails?: string | null;
  forwardingSmtpAddress?: string | null;
  forwardingAddress?: string | null;
  deliverToMailboxAndForward?: boolean | null;
}

export function mailboxForwarding(
  userPrincipalName: string,
  input: ForwardingInput = {},
): Record<string, unknown> {
  return {
    userPrincipalName,
    recipientTypeDetails:
      input.recipientTypeDetails === undefined ? 'UserMailbox' : input.recipientTypeDetails,
    forwardingSmtpAddress: input.forwardingSmtpAddress ?? null,
    forwardingAddress: input.forwardingAddress ?? null,
    deliverToMailboxAndForward:
      input.deliverToMailboxAndForward === undefined ? true : input.deliverToMailboxAndForward,
  };
}

export function smtpAuthMailbox(
  userPrincipalName: string,
  smtpClientAuthenticationDisabled: boolean,
): Record<string, unknown> {
  return { userPrincipalName, smtpClientAuthenticationDisabled };
}

type Lookup = { lookupStatus: 'Found' | 'NotFound' | 'Error'; records: string[] };

/** A DNS lookup: an array of TXT strings (Found, or NotFound when empty) or an explicit status. */
export type LookupInput = string[] | 'NotFound' | 'Error';

function lookup(input: LookupInput): Lookup {
  if (input === 'NotFound') return { lookupStatus: 'NotFound', records: [] };
  if (input === 'Error') return { lookupStatus: 'Error', records: [] };
  return { lookupStatus: input.length === 0 ? 'NotFound' : 'Found', records: input };
}

export const GOOD_SPF = 'v=spf1 include:spf.protection.outlook.com -all';
export const GOOD_DMARC = 'v=DMARC1; p=reject; rua=mailto:dmarc@contoso.example';

export function dnsRecord(
  domain: string,
  input: { spf?: LookupInput; dmarc?: LookupInput } = {},
): Record<string, unknown> {
  return {
    domain,
    spf: lookup(input.spf ?? [GOOD_SPF]),
    dmarc: lookup(input.dmarc ?? [GOOD_DMARC]),
  };
}

export function sharePointSettings(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    sharingCapability: 'externalUserSharingOnly',
    sharingDomainRestrictionMode: 'none',
    isResharingByExternalUsersEnabled: false,
    isLegacyAuthProtocolsEnabled: false,
    isUnmanagedSyncAppForTenantRestricted: false,
    ...overrides,
  };
}

export function atpPolicy(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    enableATPForSPOTeamsODB: true,
    enableSafeDocs: null,
    allowSafeDocsOpen: null,
    ...overrides,
  };
}
