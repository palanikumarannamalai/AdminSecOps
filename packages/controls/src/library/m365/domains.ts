import type { DatasetData } from '@adminsecops/schemas';

/**
 * Domain helpers shared by the Microsoft 365 controls. These normalize values
 * (case, "smtp:" prefixes, trailing dots); the security judgements stay in the
 * controls.
 */

type AcceptedDomain = DatasetData<'exchange.acceptedDomains'>[number];

/** Lower-case a domain name and remove surrounding whitespace and a trailing root dot. */
export function normalizeDomain(domain: string): string {
  return domain.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * Microsoft-managed initial domains (contoso.onmicrosoft.com and the hybrid routing
 * domain contoso.mail.onmicrosoft.com). Microsoft publishes and maintains the SPF
 * and DKIM configuration of these domains, so customer DNS controls exclude them.
 */
export function isMicrosoftManagedDomain(domain: string): boolean {
  const d = normalizeDomain(domain);
  return d === 'onmicrosoft.com' || d.endsWith('.onmicrosoft.com');
}

export function isAuthoritative(domain: AcceptedDomain): boolean {
  return domain.domainType.trim().toLowerCase() === 'authoritative';
}

/** Authoritative accepted domains that the customer manages (not *.onmicrosoft.com). */
export function customAuthoritativeDomains(domains: readonly AcceptedDomain[]): AcceptedDomain[] {
  return domains.filter((d) => isAuthoritative(d) && !isMicrosoftManagedDomain(d.domainName));
}

/**
 * Parse a forwarding address as stored by Exchange ("smtp:user@example.com" or
 * "user@example.com"). Returns the normalized address and domain, or null when the
 * value is not a recognizable SMTP address.
 */
export function parseSmtpAddress(value: string): { address: string; domain: string } | null {
  const address = value
    .trim()
    .replace(/^smtp:/i, '')
    .trim();
  const at = address.lastIndexOf('@');
  if (at <= 0 || at === address.length - 1) return null;
  const domain = normalizeDomain(address.slice(at + 1));
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain)) return null;
  return { address: address.toLowerCase(), domain };
}

/**
 * True when `domain` is one of the organization's accepted domains. Accepted domain
 * entries of the form "*.contoso.com" match any subdomain of contoso.com (but not
 * contoso.com itself, which needs its own accepted domain entry); other
 * entries match exactly (the dataset does not record the "match subdomains"
 * option, so a subdomain of a plain accepted domain is not assumed to be internal).
 */
export function isAcceptedDomain(domain: string, accepted: readonly AcceptedDomain[]): boolean {
  const d = normalizeDomain(domain);
  return accepted.some((entry) => {
    const name = normalizeDomain(entry.domainName);
    if (name.startsWith('*.')) {
      const parent = name.slice(2);
      return d.endsWith(`.${parent}`);
    }
    return d === name;
  });
}
