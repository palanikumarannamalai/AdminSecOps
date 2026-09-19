import { analyzeDmarc, analyzeSpf, type DmarcAnalysis } from '@adminsecops/inventory';
import type { AffectedObject, DatasetData, ObservedFact } from '@adminsecops/schemas';
import { defineControl, type EvaluationOutcome } from '../../define.js';
import { affected, fact, fail, notAssessed, pass, plural, review } from '../../helpers.js';
import { REF } from '../../references.js';
import {
  customAuthoritativeDomains,
  isMicrosoftManagedDomain,
  normalizeDomain,
} from './domains.js';
import { M365_REF } from './references.js';

type DnsEntry = DatasetData<'exchange.mailDnsRecords'>[number];

/** Per-domain verdict used to aggregate multi-domain DNS controls deterministically. */
interface DomainVerdict {
  domain: string;
  verdict: 'pass' | 'fail' | 'review' | 'error';
  detail: string;
}

function domainObject(v: DomainVerdict): AffectedObject {
  return affected('domain', v.domain, v.domain, v.detail);
}

const byDomain = (a: DomainVerdict, b: DomainVerdict) => a.domain.localeCompare(b.domain);

/**
 * Aggregate per-domain verdicts: FAIL if any domain fails, otherwise REVIEW if any
 * needs review, otherwise NOT_ASSESSED if any lookup failed (missing evidence is
 * never a PASS), otherwise PASS.
 */
function aggregate(
  verdicts: DomainVerdict[],
  facts: ObservedFact[],
  text: {
    what: string;
    failReason: (n: number) => string;
    reviewReason: (n: number) => string;
    passReason: (n: number) => string;
  },
  notes: string[] = [],
): EvaluationOutcome {
  const sorted = [...verdicts].sort(byDomain);
  const failed = sorted.filter((v) => v.verdict === 'fail');
  const toReview = sorted.filter((v) => v.verdict === 'review');
  const errors = sorted.filter((v) => v.verdict === 'error');
  const errorNote =
    errors.length > 0
      ? [
          `The ${text.what} lookup failed for ${errors.map((e) => e.domain).join(', ')}; verify those domains manually.`,
        ]
      : [];
  if (failed.length > 0) {
    return fail({
      reason: text.failReason(failed.length),
      summary: `${plural(failed.length, 'domain')} of ${sorted.length} do not meet the ${text.what} requirement.`,
      facts,
      affectedObjects: [...failed, ...toReview, ...errors].map(domainObject),
      notes: [...notes, ...errorNote],
    });
  }
  if (toReview.length > 0) {
    return review({
      reason: text.reviewReason(toReview.length),
      summary: `${plural(toReview.length, 'domain')} need review of the ${text.what} configuration.`,
      facts,
      affectedObjects: [...toReview, ...errors].map(domainObject),
      notes: [...notes, ...errorNote],
    });
  }
  if (errors.length > 0) {
    return notAssessed({
      reason: `The ${text.what} DNS lookup failed for ${plural(errors.length, 'domain')} (${errors.map((e) => e.domain).join(', ')}), so the requirement cannot be confirmed. The other domains meet it.`,
      summary: `${text.what} could not be evaluated for every domain.`,
      facts,
      affectedObjects: errors.map(domainObject),
      notes,
    });
  }
  return pass({
    reason: text.passReason(sorted.length),
    summary: `All ${plural(sorted.length, 'domain')} meet the ${text.what} requirement.`,
    facts,
    notes,
  });
}

/** Customer-managed domains in the DNS evidence (Microsoft-managed *.onmicrosoft.com excluded), de-duplicated. */
function customDnsEntries(entries: readonly DnsEntry[]): DnsEntry[] {
  const seen = new Set<string>();
  const result: DnsEntry[] = [];
  for (const entry of entries) {
    const domain = normalizeDomain(entry.domain);
    if (isMicrosoftManagedDomain(domain) || seen.has(domain)) continue;
    seen.add(domain);
    result.push(entry);
  }
  return result;
}

/** A domain whose only SPF policy is "v=spf1 -all" declares that it sends no mail (a parked domain). */
function isParkedBySpf(entry: DnsEntry): boolean {
  if (entry.spf.lookupStatus !== 'Found') return false;
  const spf = analyzeSpf(entry.spf.records);
  return (
    spf.recordState === 'single' &&
    spf.record !== null &&
    /^v=spf1\s+-all$/i.test(spf.record.trim())
  );
}

const NO_CUSTOM_DOMAINS =
  'The organization has no customer-managed authoritative domains (only Microsoft-managed *.onmicrosoft.com domains, whose email authentication Microsoft configures).';

// --- DKIM ------------------------------------------------------------------------

export const m365DkimEnabled = defineControl({
  id: 'M365-MAIL-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'DKIM signing is enabled for every custom domain',
  technology: 'm365',
  category: 'Email security',
  subcategory: 'Email authentication',
  description:
    'Checks that Exchange Online DKIM signing is enabled for every authoritative accepted domain the organization manages (Microsoft-managed *.onmicrosoft.com domains are excluded).',
  rationale:
    'DKIM adds a cryptographic signature that lets receiving mail systems verify that a message from your domain was sent by an authorized system and was not altered. Together with SPF it is what allows DMARC to protect your domain from being spoofed in phishing, and major mailbox providers increasingly reject or junk unauthenticated mail.',
  severity: 'medium',
  confidence: 'high',
  applicability: {
    description:
      'Tenants with at least one custom (non-onmicrosoft.com) authoritative accepted domain.',
  },
  requiredEvidence: ['exchange.acceptedDomains', 'exchange.dkimSigningConfigs'],
  optionalEvidence: ['exchange.mailDnsRecords'],
  evaluation: {
    logic:
      'Considers authoritative accepted domains (domain type Authoritative, case-insensitive) excluding *.onmicrosoft.com. NOT_APPLICABLE when there are none. For each domain, the DKIM signing configuration is matched by domain name (case-insensitive); a missing configuration counts as not enabled. A domain fails when signing is not enabled, except that a domain whose SPF record is exactly "v=spf1 -all" (a parked domain that sends no mail, per the optional DNS evidence) is excluded and noted, following Microsoft guidance not to publish DKIM for parked domains. A domain needs review when signing is enabled but the reported status is something other than Valid (for example CnameMissing). FAIL if any domain fails, REVIEW if any needs review, otherwise PASS.',
    parameters: {},
  },
  expectedState:
    'DKIM signing is enabled with a Valid status for every custom domain that sends email.',
  remediation: {
    summary:
      'Publish the two DKIM CNAME records for each listed domain and enable DKIM signing in the Microsoft Defender portal.',
    steps: [
      'In the Microsoft Defender portal go to Email & collaboration > Policies & rules > Threat policies > Email authentication settings > DKIM (https://security.microsoft.com/authentication?viewid=DKIM).',
      'Select the domain. If no DKIM keys exist, select Create DKIM keys; copy the two CNAME records shown (selector1._domainkey and selector2._domainkey).',
      'Create both CNAME records at your DNS hosting provider exactly as shown, and wait for DNS propagation.',
      'Back in the DKIM tab, turn on "Sign messages for this domain with DKIM signatures" and confirm the status becomes Valid.',
    ],
    scriptExample:
      'Connect-ExchangeOnline\n# Show the CNAME values to publish for a domain that has no DKIM configuration yet\nNew-DkimSigningConfig -DomainName contoso.com -Enabled $false\nGet-DkimSigningConfig -Identity contoso.com | Format-List Selector1CNAME, Selector2CNAME\n# After the CNAME records are published in DNS:\nSet-DkimSigningConfig -Identity contoso.com -Enabled $true\nGet-DkimSigningConfig | Format-Table Domain, Enabled, Status',
    effort: 'low',
  },
  implementationConsiderations: [
    'The CNAME target values are specific to your tenant; always copy them from the portal or Get-DkimSigningConfig instead of constructing them.',
    'Mail sent by third-party services on your behalf (marketing, ticketing) must be DKIM-signed by those services separately.',
    'Microsoft does not recommend DKIM records for parked domains that never send email; protect those with "v=spf1 -all" and a DMARC p=reject record instead.',
  ],
  impact:
    'No user impact. Outbound messages carry a DKIM signature for the domain, which improves deliverability and enables DMARC enforcement.',
  rollback: [
    'Run Set-DkimSigningConfig -Identity <domain> -Enabled $false, or turn signing off for the domain in the DKIM tab.',
  ],
  validation: [
    'Re-run the AdminSecOps Exchange collector and confirm M365-MAIL-001 is PASS.',
    'Run Get-DkimSigningConfig | Format-Table Domain, Enabled, Status and confirm each domain is Enabled with Status Valid.',
    'Send a test message to an external mailbox and confirm the Authentication-Results header shows dkim=pass for your domain.',
  ],
  references: [M365_REF.dkim, M365_REF.dmarc, M365_REF.attackPhishing, REF.scubaGearBaselines],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SI-8' },
    { framework: 'CISA-SCuBA', id: 'MS.EXO.3.1v1' },
    { framework: 'MITRE-ATTACK', id: 'T1566' },
  ],
  tags: ['email-authentication', 'dkim', 'anti-spoofing', 'exchange-online'],
  applies: (ctx) =>
    customAuthoritativeDomains(ctx.data('exchange.acceptedDomains')).length > 0
      ? { applicable: true }
      : { applicable: false, reason: NO_CUSTOM_DOMAINS },
  evaluate: (ctx) => {
    const domains = customAuthoritativeDomains(ctx.data('exchange.acceptedDomains'));
    const configs = ctx.data('exchange.dkimSigningConfigs');
    const dns = ctx.fact('exchange.mailDnsRecords');
    const parked = new Set(
      dns.available ? dns.data.filter(isParkedBySpf).map((e) => normalizeDomain(e.domain)) : [],
    );
    const verdicts: DomainVerdict[] = [];
    const parkedDomains: string[] = [];
    for (const d of domains) {
      const name = normalizeDomain(d.domainName);
      const config = configs.find((c) => normalizeDomain(c.domain) === name);
      const enabled = config?.enabled === true;
      if (!enabled && parked.has(name)) {
        parkedDomains.push(name);
        continue;
      }
      if (config === undefined) {
        verdicts.push({
          domain: name,
          verdict: 'fail',
          detail: 'No DKIM signing configuration exists for this domain',
        });
      } else if (!config.enabled) {
        verdicts.push({
          domain: name,
          verdict: 'fail',
          detail: `DKIM signing is disabled${config.status ? ` (status ${config.status})` : ''}`,
        });
      } else if (config.status !== null && config.status.trim().toLowerCase() !== 'valid') {
        verdicts.push({
          domain: name,
          verdict: 'review',
          detail: `DKIM signing is enabled but the status is ${config.status}; confirm the CNAME records are published and signing works`,
        });
      } else {
        verdicts.push({ domain: name, verdict: 'pass', detail: 'DKIM signing enabled' });
      }
    }
    const facts = [
      fact('Custom authoritative domains', domains.length),
      fact(
        'Domains with DKIM signing enabled',
        verdicts.filter((v) => v.verdict !== 'fail').length,
      ),
      fact('Parked domains excluded (SPF "v=spf1 -all")', parkedDomains.length),
    ];
    const notes =
      parkedDomains.length > 0
        ? [
            `${parkedDomains.sort().join(', ')} publish "v=spf1 -all" (no mail sent) and were not required to have DKIM. If any of them does send mail, enable DKIM for it.`,
          ]
        : [];
    if (verdicts.length === 0) {
      return pass({
        reason:
          'Every custom domain is a parked domain that declares it sends no mail, so DKIM signing is not required.',
        summary: 'No sending custom domain requires DKIM.',
        facts,
        notes,
      });
    }
    return aggregate(
      verdicts,
      facts,
      {
        what: 'DKIM',
        failReason: (n) => `DKIM signing is not enabled for ${plural(n, 'custom domain')}.`,
        reviewReason: (n) =>
          `DKIM signing is enabled for ${plural(n, 'domain')} but its status is not Valid.`,
        passReason: (n) =>
          `DKIM signing is enabled with a valid status for all ${plural(n, 'sending custom domain')}.`,
      },
      notes,
    );
  },
});

// --- SPF -------------------------------------------------------------------------------

function spfVerdict(entry: DnsEntry): DomainVerdict {
  const domain = normalizeDomain(entry.domain);
  if (entry.spf.lookupStatus === 'Error')
    return { domain, verdict: 'error', detail: 'SPF TXT lookup failed' };
  if (entry.spf.lookupStatus === 'NotFound')
    return {
      domain,
      verdict: 'fail',
      detail: 'No TXT records found, so no SPF record is published',
    };
  const spf = analyzeSpf(entry.spf.records);
  if (spf.recordState === 'none')
    return { domain, verdict: 'fail', detail: 'No SPF (v=spf1) record is published' };
  if (spf.recordState === 'multiple') {
    return {
      domain,
      verdict: 'fail',
      detail:
        'More than one SPF record is published, which causes an SPF permanent error (permerror); merge them into one record',
    };
  }
  switch (spf.allQualifier) {
    case 'fail':
      return { domain, verdict: 'pass', detail: 'SPF ends with -all (hard fail)' };
    case 'softfail':
      return { domain, verdict: 'pass', detail: 'SPF ends with ~all (soft fail)' };
    case 'pass':
      return {
        domain,
        verdict: 'fail',
        detail:
          'SPF uses +all, which authorizes every server on the internet to send as this domain',
      };
    case 'neutral':
      return {
        domain,
        verdict: 'fail',
        detail:
          'SPF uses ?all (neutral), which gives receivers no instruction for unauthorized senders',
      };
    case null:
      return spf.redirect !== null
        ? {
            domain,
            verdict: 'review',
            detail: `SPF has no all mechanism and redirects to ${spf.redirect}; the enforcement rule is defined in that record, which was not collected`,
          }
        : {
            domain,
            verdict: 'fail',
            detail: 'SPF has no all mechanism, so unauthorized senders get a neutral result',
          };
  }
}

export const m365SpfPublished = defineControl({
  id: 'M365-MAIL-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'SPF records reject or soft-fail unauthorized senders for every custom domain',
  technology: 'm365',
  category: 'Email security',
  subcategory: 'Email authentication',
  description:
    'Checks the public SPF (TXT) record of each customer-managed authoritative domain: exactly one SPF record must be published and it must end with -all (hard fail) or ~all (soft fail).',
  rationale:
    'SPF tells receiving mail systems which servers may send mail for your domain. A missing SPF record, multiple SPF records (a permanent error), or a permissive ending (+all or ?all) lets attackers send email that appears to come from your domain, which is used in phishing and invoice fraud against your staff, customers and partners.',
  severity: 'medium',
  confidence: 'high',
  applicability: {
    description:
      'Tenants with at least one custom (non-onmicrosoft.com) domain in the mail DNS evidence.',
  },
  requiredEvidence: ['exchange.mailDnsRecords'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each domain in the mail DNS evidence (duplicates and Microsoft-managed *.onmicrosoft.com domains excluded; NOT_APPLICABLE when none remain), the TXT records are parsed with the RFC 7208 SPF parser. A domain fails when no TXT/SPF record exists, when more than one v=spf1 record exists, when the record ends with +all or ?all, or when it has neither an all mechanism nor a redirect. It needs review when it has no all mechanism but a redirect= modifier (the effective rule lives in the redirected record). It passes with -all or ~all. A failed DNS lookup is not treated as a pass. FAIL if any domain fails, REVIEW if any needs review, NOT_ASSESSED if lookups failed for the remaining domains, otherwise PASS.',
    parameters: {},
  },
  expectedState:
    'Each custom domain publishes a single SPF record listing its legitimate senders (for Microsoft 365, include:spf.protection.outlook.com) and ending with -all (recommended) or ~all.',
  remediation: {
    summary:
      'Publish or correct a single SPF TXT record for each listed domain at your DNS hosting provider.',
    steps: [
      'List every service that sends mail as the domain (Microsoft 365, on-premises servers, marketing and ticketing services).',
      'At your DNS hosting provider, create or edit the TXT record at the domain root so that there is exactly one record starting with v=spf1, for example: v=spf1 include:spf.protection.outlook.com -all.',
      'Remove any second v=spf1 record and replace +all or ?all with -all (or ~all while you are still discovering senders).',
      'For domains that never send email, publish v=spf1 -all.',
      'Keep the record under 10 DNS lookups (each include: counts) to avoid permanent errors.',
    ],
    scriptExample:
      '# Check the published SPF record (read-only)\nResolve-DnsName -Type TXT contoso.com | Where-Object { $_.Strings -match "^v=spf1" } | Select-Object -ExpandProperty Strings',
    effort: 'low',
  },
  implementationConsiderations: [
    'Microsoft recommends -all for Microsoft 365 domains that also use DKIM and DMARC; ~all is acceptable while you identify all legitimate senders.',
    'Missing a legitimate sender from the SPF record can cause its mail to be junked or rejected; use DMARC aggregate reports to find senders before tightening.',
    'SPF records are managed at your DNS provider, not in Microsoft 365.',
  ],
  impact:
    'Receiving systems can identify mail from unauthorized servers that claims to be from your domain. Legitimate senders missing from the record may see delivery problems.',
  rollback: ['Restore the previous TXT record value at your DNS hosting provider.'],
  validation: [
    'Re-run the AdminSecOps collector (mail DNS) and confirm M365-MAIL-002 is PASS.',
    'Run Resolve-DnsName -Type TXT <domain> and confirm there is exactly one v=spf1 record ending in -all or ~all.',
  ],
  references: [M365_REF.spf, M365_REF.dmarc, M365_REF.attackPhishing, REF.scubaGearBaselines],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SI-8' },
    { framework: 'CISA-SCuBA', id: 'MS.EXO.2.2v3' },
    { framework: 'MITRE-ATTACK', id: 'T1566' },
  ],
  tags: ['email-authentication', 'spf', 'anti-spoofing', 'dns'],
  applies: (ctx) =>
    customDnsEntries(ctx.data('exchange.mailDnsRecords')).length > 0
      ? { applicable: true }
      : { applicable: false, reason: NO_CUSTOM_DOMAINS },
  evaluate: (ctx) => {
    const entries = customDnsEntries(ctx.data('exchange.mailDnsRecords'));
    const verdicts = entries.map(spfVerdict);
    const softfail = verdicts
      .filter((v) => v.verdict === 'pass' && v.detail.includes('~all'))
      .map((v) => v.domain)
      .sort();
    const facts = [
      fact('Custom domains checked', entries.length),
      fact('Domains with -all or ~all', verdicts.filter((v) => v.verdict === 'pass').length),
      fact('Domains using ~all (soft fail)', softfail.length),
    ];
    const notes =
      softfail.length > 0
        ? [
            `${softfail.join(', ')} use ~all. Microsoft recommends -all once all legitimate senders are listed, so DMARC can act on SPF failures of unsigned messages.`,
          ]
        : [];
    return aggregate(
      verdicts,
      facts,
      {
        what: 'SPF',
        failReason: (n) =>
          `${plural(n, 'domain')} have a missing, duplicated or permissive SPF record.`,
        reviewReason: (n) =>
          `${plural(n, 'domain')} delegate their SPF policy with redirect=, which must be checked manually.`,
        passReason: (n) =>
          `All ${plural(n, 'custom domain')} publish a single SPF record ending in -all or ~all.`,
      },
      notes,
    );
  },
});

// --- DMARC -----------------------------------------------------------------------------

interface EffectiveDmarc {
  analysis: DmarcAnalysis;
  /** Domain whose record applies when the policy is inherited from a parent domain. */
  inheritedFrom: string | null;
}

/**
 * The DMARC record that applies to a domain: its own record, or - when it has none -
 * the record of the shortest listed parent domain (the most likely organizational
 * domain), whose sp= (or p=) policy applies to subdomains per RFC 7489.
 */
function effectiveDmarc(
  entry: DnsEntry,
  all: readonly DnsEntry[],
): EffectiveDmarc | 'error' | null {
  if (entry.dmarc.lookupStatus === 'Error') return 'error';
  const own = analyzeDmarc(entry.dmarc.lookupStatus === 'Found' ? entry.dmarc.records : []);
  if (own.recordState !== 'none') return { analysis: own, inheritedFrom: null };
  const domain = normalizeDomain(entry.domain);
  const parents = all
    .map((e) => ({ e, name: normalizeDomain(e.domain) }))
    .filter(({ name }) => domain.endsWith(`.${name}`))
    .sort((a, b) => a.name.length - b.name.length);
  for (const { e, name } of parents) {
    if (e.dmarc.lookupStatus !== 'Found') continue;
    const parent = analyzeDmarc(e.dmarc.records);
    if (parent.recordState !== 'single' || parent.policy === null) continue;
    return {
      analysis: { ...parent, policy: parent.subdomainPolicy ?? parent.policy },
      inheritedFrom: name,
    };
  }
  return null;
}

export const m365DmarcPolicy = defineControl({
  id: 'M365-MAIL-003',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'DMARC is published with a quarantine or reject policy for every custom domain',
  technology: 'm365',
  category: 'Email security',
  subcategory: 'Email authentication',
  description:
    'Checks the public DMARC record (_dmarc TXT) of each customer-managed authoritative domain: a single valid DMARC record must exist (or be inherited from a parent domain) with policy p=quarantine or p=reject applied to all messages.',
  rationale:
    'DMARC tells receiving systems what to do with mail that claims to be from your domain but fails SPF and DKIM alignment. Without an enforcing DMARC policy (quarantine or reject), spoofed messages using your exact domain can still reach inboxes, which attackers exploit for phishing and payment fraud. DMARC reports also reveal who is sending mail as your domain.',
  severity: 'medium',
  confidence: 'high',
  applicability: {
    description:
      'Tenants with at least one custom (non-onmicrosoft.com) domain in the mail DNS evidence.',
  },
  requiredEvidence: ['exchange.mailDnsRecords'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each domain in the mail DNS evidence (duplicates and *.onmicrosoft.com excluded; NOT_APPLICABLE when none remain), the _dmarc TXT records are parsed with the RFC 7489 parser. When a domain has no record of its own, the record of the shortest listed parent domain applies (its sp= policy, or p= when sp= is absent). A domain fails when no DMARC record applies, when more than one DMARC record is published, or when the p= policy is missing or invalid. It needs review when the policy is p=none (monitoring only; appropriate during a planned rollout, which only the administrator can confirm) or when quarantine/reject applies to less than minimumPercentage percent of messages (pct=). It passes with p=quarantine or p=reject at pct >= minimumPercentage. A failed DNS lookup is not a pass. FAIL if any domain fails, REVIEW if any needs review, NOT_ASSESSED if lookups failed for the remaining domains, otherwise PASS.',
    parameters: { minimumPercentage: 100 },
  },
  expectedState:
    'Each custom domain has one DMARC record with p=quarantine or p=reject (reject is the end goal), pct=100 or no pct tag, and aggregate reporting (rua=) configured.',
  remediation: {
    summary:
      'Publish or tighten the DMARC TXT record for each listed domain, moving from monitoring to enforcement in stages.',
    steps: [
      'Make sure SPF (M365-MAIL-002) and DKIM (M365-MAIL-001) are configured for the domain first.',
      'At your DNS hosting provider create a TXT record named _dmarc.<domain>. Start with v=DMARC1; p=none; rua=mailto:<reporting address> if you have not monitored DMARC before, and review the aggregate reports.',
      'When legitimate senders pass, change the policy to p=quarantine (optionally increasing pct= in steps), then to p=reject.',
      'Ensure only one _dmarc record exists per domain and that pct= is removed or set to 100 when you finish.',
      'For domains that never send email, publish v=DMARC1; p=reject;.',
    ],
    scriptExample:
      '# Check the published DMARC record (read-only)\nResolve-DnsName -Type TXT _dmarc.contoso.com | Select-Object -ExpandProperty Strings',
    effort: 'medium',
  },
  implementationConsiderations: [
    'Moving to quarantine or reject before all legitimate senders are aligned with SPF or DKIM can cause their mail to be junked or rejected by recipients.',
    'Subdomains inherit the parent domain policy (sp=, or p=) unless they publish their own record.',
    'A DMARC reporting service makes aggregate (rua) reports much easier to interpret.',
  ],
  impact:
    'Receiving systems quarantine or reject mail that spoofs your domain and fails authentication. Misconfigured legitimate senders are affected in the same way.',
  rollback: ['Change the DMARC record back to p=none (monitoring) at your DNS hosting provider.'],
  validation: [
    'Re-run the AdminSecOps collector (mail DNS) and confirm M365-MAIL-003 is PASS.',
    'Run Resolve-DnsName -Type TXT _dmarc.<domain> and confirm a single v=DMARC1 record with p=quarantine or p=reject.',
  ],
  references: [
    M365_REF.dmarc,
    M365_REF.spf,
    M365_REF.dkim,
    M365_REF.attackPhishing,
    REF.scubaGearBaselines,
  ],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SI-8' },
    { framework: 'CISA-SCuBA', id: 'MS.EXO.4.1v1' },
    {
      framework: 'CISA-SCuBA',
      id: 'MS.EXO.4.2v1',
      note: 'partial: SCuBA requires p=reject; this control also accepts p=quarantine',
    },
    { framework: 'MITRE-ATTACK', id: 'T1566' },
  ],
  tags: ['email-authentication', 'dmarc', 'anti-spoofing', 'dns'],
  applies: (ctx) =>
    customDnsEntries(ctx.data('exchange.mailDnsRecords')).length > 0
      ? { applicable: true }
      : { applicable: false, reason: NO_CUSTOM_DOMAINS },
  evaluate: (ctx) => {
    const minimumPercentage = ctx.num('minimumPercentage');
    const entries = customDnsEntries(ctx.data('exchange.mailDnsRecords'));
    const noReporting: string[] = [];
    const verdicts: DomainVerdict[] = entries.map((entry) => {
      const domain = normalizeDomain(entry.domain);
      const effective = effectiveDmarc(entry, entries);
      if (effective === 'error')
        return { domain, verdict: 'error', detail: 'DMARC TXT lookup failed' };
      if (effective === null)
        return {
          domain,
          verdict: 'fail',
          detail: 'No DMARC record is published for the domain or a listed parent domain',
        };
      const { analysis, inheritedFrom } = effective;
      const source = inheritedFrom === null ? '' : ` (inherited from ${inheritedFrom})`;
      if (analysis.recordState === 'multiple') {
        return {
          domain,
          verdict: 'fail',
          detail: 'More than one DMARC record is published; receivers ignore DMARC for the domain',
        };
      }
      if (analysis.policy === null)
        return {
          domain,
          verdict: 'fail',
          detail: `DMARC record has a missing or invalid p= policy${source}`,
        };
      if (!analysis.hasAggregateReporting && inheritedFrom === null) noReporting.push(domain);
      if (analysis.policy === 'none') {
        return {
          domain,
          verdict: 'review',
          detail: `DMARC policy is p=none (monitoring only)${source}; confirm a rollout to quarantine or reject is planned`,
        };
      }
      if (analysis.percentage < minimumPercentage) {
        return {
          domain,
          verdict: 'review',
          detail: `DMARC policy p=${analysis.policy} applies to only ${analysis.percentage}% of failing messages (pct=${analysis.percentage})${source}`,
        };
      }
      return { domain, verdict: 'pass', detail: `DMARC policy p=${analysis.policy}${source}` };
    });
    const facts = [
      fact('Custom domains checked', entries.length),
      fact(
        'Domains with an enforcing DMARC policy',
        verdicts.filter((v) => v.verdict === 'pass').length,
      ),
      fact('Minimum pct required', minimumPercentage),
    ];
    const notes =
      noReporting.length > 0
        ? [
            `${noReporting.sort().join(', ')} have no aggregate reporting address (rua=). Add one so you can see who sends mail as the domain.`,
          ]
        : [];
    return aggregate(
      verdicts,
      facts,
      {
        what: 'DMARC',
        failReason: (n) => `${plural(n, 'domain')} have no valid DMARC record.`,
        reviewReason: (n) =>
          `${plural(n, 'domain')} publish DMARC in monitoring mode (p=none) or apply enforcement to only part of the mail (pct below ${minimumPercentage}). This is normal during a staged rollout, which only an administrator can confirm.`,
        passReason: (n) =>
          `All ${plural(n, 'custom domain')} have a DMARC policy of quarantine or reject.`,
      },
      notes,
    );
  },
});
