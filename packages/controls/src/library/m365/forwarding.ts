import type { AffectedObject, DatasetData } from '@adminsecops/schemas';
import { defineControl, type ControlContext } from '../../define.js';
import { affected, fact, fail, notAssessed, pass, plural, review } from '../../helpers.js';
import { REF } from '../../references.js';
import { isAcceptedDomain, normalizeDomain, parseSmtpAddress } from './domains.js';
import { M365_REF } from './references.js';

type OutboundPolicy = DatasetData<'exchange.outboundSpamPolicies'>[number];
type ForwardingMode = 'on' | 'off' | 'automatic' | 'unknown';

/** Normalized AutoForwardingMode of an outbound spam policy (Automatic | On | Off). */
export function forwardingMode(policy: OutboundPolicy): ForwardingMode {
  const mode = policy.autoForwardingMode.trim().toLowerCase();
  return mode === 'on' || mode === 'off' || mode === 'automatic' ? mode : 'unknown';
}

function policyObject(policy: OutboundPolicy, detail: string): AffectedObject {
  return affected('outboundSpamPolicy', policy.name, policy.name, detail);
}

/**
 * Whether every outbound spam policy explicitly blocks external automatic forwarding
 * (optional evidence; null when the policies were not collected).
 */
function outboundPoliciesAllOff(ctx: ControlContext): boolean | null {
  const policies = ctx.fact('exchange.outboundSpamPolicies');
  if (!policies.available || policies.data.length === 0) return null;
  return policies.data.every((p) => forwardingMode(p) === 'off');
}

const AUTOMATIC_NOTE =
  'Microsoft changed "Automatic - System-controlled" to behave like Off in 2021 for new organizations and for organizations that were not using it, but organizations that were already relying on it may still see it behave like On. Microsoft recommends choosing On or Off explicitly instead of Automatic.';

export const m365OutboundSpamForwarding = defineControl({
  id: 'M365-EXO-003',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Automatic external forwarding is blocked by outbound spam policies',
  technology: 'm365',
  category: 'Data protection',
  subcategory: 'Email forwarding',
  description:
    'Checks the automatic forwarding setting (AutoForwardingMode) of every outbound spam filter policy. Outbound spam policies are the primary Microsoft 365 control over automatic forwarding of mail to external recipients, whether it is configured by users (Inbox rules, Outlook on the web forwarding) or by administrators (mailbox forwarding).',
  rationale:
    'Attackers who compromise a mailbox commonly create forwarding rules that silently copy every incoming message to an external address, which continues to leak data after the password is reset. Blocking automatic external forwarding by default removes this exfiltration and persistence path; legitimate business needs can be allowed for specific users through a custom policy.',
  severity: 'high',
  confidence: 'high',
  applicability: {
    description: 'All Microsoft 365 tenants with Exchange Online (Exchange Online Protection).',
  },
  requiredEvidence: ['exchange.outboundSpamPolicies'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'Reads AutoForwardingMode (Automatic | On | Off, case-insensitive) for every outbound spam policy. NOT_ASSESSED when the default policy is missing from the evidence. FAIL when the default policy is On (external forwarding allowed for everyone not covered by a custom policy). REVIEW when the default policy is not On but a custom policy is On (forwarding is allowed for the users that policy is scoped to, which may be an approved exception; the collected evidence does not include policy scope), or when any policy uses Automatic or an unrecognized value (its effective behaviour differs between organizations). PASS only when every policy is explicitly Off.',
    parameters: {},
  },
  expectedState:
    'The default outbound spam policy, and every custom outbound spam policy, has "Automatic forwarding rules" set to "Off - Forwarding is disabled". Any approved exception is a custom policy scoped to named users.',
  remediation: {
    summary:
      'Set automatic forwarding to Off in the default outbound spam policy and review custom policies that allow it.',
    steps: [
      'Before changing the setting, review Exchange admin center > Reports > Mail flow > Auto forwarded messages report to find users who forward externally and confirm which forwarding is legitimate.',
      'In the Microsoft Defender portal go to Email & collaboration > Policies & rules > Threat policies > Anti-spam (or go directly to https://security.microsoft.com/antispam).',
      'Select "Anti-spam outbound policy (Default)", select Edit in the Protection settings section, and under Forwarding rules set Automatic forwarding rules to "Off - Forwarding is disabled". Save.',
      'For each custom outbound policy listed in the finding, either set it to Off or confirm it is scoped only to users with an approved business need.',
      'If specific users need to forward externally, create a custom outbound spam policy set to On that applies only to those users (and optionally restrict destinations with remote domains).',
    ],
    scriptExample:
      'Connect-ExchangeOnline\nGet-HostedOutboundSpamFilterPolicy | Format-Table Name, IsDefault, AutoForwardingMode\nSet-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode Off',
    effort: 'low',
  },
  implementationConsiderations: [
    'Blocking automatic forwarding also stops administrator-configured mailbox forwarding to external addresses; senders receive a non-delivery report with code 5.7.520.',
    'Forwarding between internal recipients is not affected.',
    'The evidence does not include which senders a custom policy applies to or whether its rule is turned on, so custom policies are evaluated as if they were in effect.',
    'Remote domains (M365-EXO-004) and mail flow rules are additional controls; when any of them blocks forwarding, the block generally wins.',
    AUTOMATIC_NOTE,
  ],
  impact:
    'Users and mailboxes that automatically forward to external addresses stop forwarding; the forwarded copies bounce with an NDR.',
  rollback: [
    'Set the default policy back to its previous value with Set-HostedOutboundSpamFilterPolicy -Identity Default -AutoForwardingMode <Automatic|On>.',
    'Prefer adding a scoped custom policy for users who genuinely need forwarding instead of re-enabling it for everyone.',
  ],
  validation: [
    'Re-run the AdminSecOps Exchange collector and confirm M365-EXO-003 is PASS.',
    'Run Get-HostedOutboundSpamFilterPolicy | Format-Table Name, AutoForwardingMode and confirm every policy shows Off.',
    'Test with a pilot mailbox: an Inbox rule forwarding to an external address should produce an NDR with 5.7.520.',
  ],
  references: [
    M365_REF.externalForwarding,
    M365_REF.outboundSpamConfigure,
    M365_REF.setOutboundSpamPolicy,
    M365_REF.autoForwardedReport,
    M365_REF.attackEmailForwardingRule,
  ],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-4' },
    {
      framework: 'CISA-SCuBA',
      id: 'MS.EXO.1.1v2',
      note: 'partial: the SCuBA policy is assessed through remote domains; this control covers the outbound spam policy setting',
    },
    { framework: 'MITRE-ATTACK', id: 'T1114.003' },
  ],
  tags: ['data-exfiltration', 'email-forwarding', 'exchange-online'],
  evaluate: (ctx) => {
    const policies = ctx.data('exchange.outboundSpamPolicies');
    const defaults = policies.filter((p) => p.isDefault);
    const on = policies.filter((p) => forwardingMode(p) === 'on');
    const ambiguous = policies.filter(
      (p) => forwardingMode(p) === 'automatic' || forwardingMode(p) === 'unknown',
    );
    const facts = [
      fact('Outbound spam policies', policies.length),
      fact('Default policy forwarding mode', defaults[0]?.autoForwardingMode ?? null),
      fact('Policies allowing forwarding (On)', on.length),
      fact('Policies using Automatic or an unrecognized value', ambiguous.length),
    ];
    if (defaults.length === 0) {
      return notAssessed({
        reason:
          'The default outbound spam policy was not present in the collected evidence, so the organization-wide forwarding setting could not be determined.',
        summary: 'Default outbound spam policy not found.',
        facts,
      });
    }
    const detailFor = (p: OutboundPolicy): string => {
      const scope = p.isDefault
        ? 'default policy (applies to all senders not covered by a custom policy)'
        : 'custom policy (applies to its scoped senders)';
      return `AutoForwardingMode=${p.autoForwardingMode}; ${scope}`;
    };
    const defaultOn = defaults.some((p) => forwardingMode(p) === 'on');
    if (defaultOn) {
      return fail({
        reason:
          'The default outbound spam policy allows automatic forwarding to external recipients (AutoForwardingMode On).',
        summary: 'Automatic external forwarding is allowed for the organization.',
        facts,
        affectedObjects: [...on, ...ambiguous].map((p) => policyObject(p, detailFor(p))),
      });
    }
    if (on.length > 0 || ambiguous.length > 0) {
      const reasons: string[] = [];
      if (on.length > 0) {
        reasons.push(
          `${plural(on.length, 'custom policy', 'custom policies')} allow external forwarding (On); confirm each is scoped only to users with an approved business need (policy scope is not part of the collected evidence)`,
        );
      }
      if (ambiguous.length > 0) {
        reasons.push(
          `${plural(ambiguous.length, 'policy', 'policies')} use Automatic (or an unrecognized value), whose effective behaviour differs between organizations and cannot be determined from configuration`,
        );
      }
      return review({
        reason: `${reasons.join('; ')}.`,
        summary:
          'Automatic external forwarding is not explicitly blocked by every outbound spam policy.',
        facts,
        affectedObjects: [...on, ...ambiguous].map((p) => policyObject(p, detailFor(p))),
        notes:
          ambiguous.length > 0
            ? [
                AUTOMATIC_NOTE,
                'Check the Auto forwarded messages report to see whether forwarding is currently occurring, and set the policy to Off explicitly.',
              ]
            : [],
      });
    }
    return pass({
      reason: `All ${plural(policies.length, 'outbound spam policy', 'outbound spam policies')} explicitly block automatic external forwarding (Off).`,
      summary: 'Automatic forwarding to external recipients is blocked.',
      facts,
    });
  },
});

export const m365RemoteDomainForwarding = defineControl({
  id: 'M365-EXO-004',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Default remote domain does not allow automatic forwarding',
  technology: 'm365',
  category: 'Data protection',
  subcategory: 'Email forwarding',
  description:
    'Checks that the Default remote domain (which applies to all external domains, "*") does not allow automatically forwarded messages to be sent outside the organization.',
  rationale:
    'The remote domain setting is a second, independent block on user-configured automatic forwarding (Inbox rules and Outlook on the web forwarding) to external recipients. Microsoft allows it by default. Blocking it on the Default remote domain keeps forwarding blocked even if an outbound spam policy is later changed to allow forwarding, and lets you allow forwarding only to specific partner domains by adding named remote domains. It does not affect forwarding configured by administrators on a mailbox or by mail flow rules, which is why the outbound spam policy (M365-EXO-003) remains the primary control and this control is rated medium.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'All Microsoft 365 tenants with Exchange Online.' },
  requiredEvidence: ['exchange.remoteDomains'],
  optionalEvidence: ['exchange.outboundSpamPolicies'],
  evaluation: {
    logic:
      'Finds the Default remote domain (DomainName "*"). NOT_ASSESSED when it is not present in the evidence. PASS when AutoForwardEnabled is false on it. FAIL when AutoForwardEnabled is true, even if outbound spam policies currently block forwarding (a note then explains that the finding is defence in depth). Named remote domains that allow forwarding are listed as notes: they are explicit destination allow-list entries rather than a default.',
    parameters: {},
  },
  expectedState:
    'The Default remote domain (*) has "Allow automatic forwarding" turned off; forwarding is only allowed for specific, approved remote domains if at all.',
  remediation: {
    summary: 'Turn off automatic forwarding on the Default remote domain.',
    steps: [
      'Review the Auto forwarded messages report (Exchange admin center > Reports > Mail flow) to identify users forwarding externally and confirm which destinations are legitimate.',
      'In the Exchange admin center go to Mail flow > Remote domains, select Default (*) > Edit reply types, and clear "Allow automatic forwarding". Save.',
      'If specific partner domains must receive forwarded mail, add a remote domain for each (Mail flow > Remote domains > Add a remote domain) and allow automatic forwarding only there.',
    ],
    scriptExample:
      'Connect-ExchangeOnline\nGet-RemoteDomain | Format-Table Name, DomainName, AutoForwardEnabled\nSet-RemoteDomain -Identity Default -AutoForwardEnabled $false',
    effort: 'low',
  },
  implementationConsiderations: [
    'When the remote domain blocks automatic forwarding, forwarded messages are silently dropped (no NDR is sent), unlike the outbound spam policy block. Communicate the change to users who rely on forwarding.',
    'Mailbox forwarding configured by administrators (ForwardingSmtpAddress) and mail flow rules are not blocked by remote domain settings; use the outbound spam policy (M365-EXO-003) and review M365-EXO-005.',
    'Settings on a named remote domain override the Default remote domain for that destination.',
  ],
  impact:
    'Inbox rules and user-configured forwarding to external domains without a named remote domain stop delivering forwarded copies.',
  rollback: [
    'Run Set-RemoteDomain -Identity Default -AutoForwardEnabled $true, or re-enable the option in the Exchange admin center.',
  ],
  validation: [
    'Re-run the AdminSecOps Exchange collector and confirm M365-EXO-004 is PASS.',
    'Run Get-RemoteDomain Default | Format-List AutoForwardEnabled and confirm the value is False.',
  ],
  references: [
    M365_REF.remoteDomains,
    M365_REF.manageRemoteDomains,
    M365_REF.externalForwarding,
    M365_REF.attackEmailForwardingRule,
    REF.scubaGearBaselines,
  ],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-4' },
    { framework: 'CISA-SCuBA', id: 'MS.EXO.1.1v2' },
    { framework: 'MITRE-ATTACK', id: 'T1114.003' },
  ],
  tags: ['data-exfiltration', 'email-forwarding', 'exchange-online'],
  evaluate: (ctx) => {
    const domains = ctx.data('exchange.remoteDomains');
    const defaultDomain = domains.find((d) => normalizeDomain(d.domainName) === '*');
    const namedAllowing = domains
      .filter((d) => normalizeDomain(d.domainName) !== '*' && d.autoForwardEnabled)
      .map((d) => `${d.name} (${d.domainName})`)
      .sort((a, b) => a.localeCompare(b));
    const allOff = outboundPoliciesAllOff(ctx);
    const facts = [
      fact('Remote domains', domains.length),
      fact(
        'Default remote domain allows automatic forwarding',
        defaultDomain?.autoForwardEnabled ?? null,
      ),
      fact('Named remote domains allowing automatic forwarding', namedAllowing.length),
    ];
    if (defaultDomain === undefined) {
      return notAssessed({
        reason: 'The Default remote domain (*) was not present in the collected evidence.',
        summary: 'Default remote domain not found.',
        facts,
      });
    }
    const notes: string[] = [];
    if (namedAllowing.length > 0) {
      notes.push(
        `Automatic forwarding is explicitly allowed to these remote domains: ${namedAllowing.join(', ')}. Confirm each is an approved destination.`,
      );
    }
    if (!defaultDomain.autoForwardEnabled) {
      return pass({
        reason:
          'The Default remote domain does not allow automatic forwarding to external domains.',
        summary:
          'User-configured automatic forwarding to external domains is blocked by the Default remote domain.',
        facts,
        notes,
      });
    }
    if (allOff === true) {
      notes.push(
        'All outbound spam policies currently block automatic external forwarding (Off), so forwarding is blocked today; this finding is defence in depth in case an outbound spam policy is changed.',
      );
    }
    return fail({
      reason:
        'The Default remote domain allows automatic forwarding to all external domains (AutoForwardEnabled is True).',
      summary:
        'Remote domain settings do not block user-configured forwarding to external domains.',
      facts,
      affectedObjects: [
        affected(
          'remoteDomain',
          defaultDomain.name,
          `${defaultDomain.name} (${defaultDomain.domainName})`,
          'AutoForwardEnabled=True',
        ),
      ],
      notes,
    });
  },
});

type ForwardingEntry = DatasetData<'exchange.mailboxForwarding'>[number];
type Classified =
  | { kind: 'external'; entry: ForwardingEntry; address: string; domain: string }
  | { kind: 'internal'; entry: ForwardingEntry }
  | { kind: 'recipient'; entry: ForwardingEntry; recipient: string; ignoredSmtp: string | null }
  | { kind: 'unparseable'; entry: ForwardingEntry; value: string };

function keepCopy(entry: ForwardingEntry): string {
  if (entry.deliverToMailboxAndForward === null) return 'copy kept in mailbox: unknown';
  return entry.deliverToMailboxAndForward ? 'copy kept in mailbox' : 'no copy kept in mailbox';
}

function nonEmpty(value: string | null): string | null {
  const v = value?.trim() ?? '';
  return v.length > 0 ? v : null;
}

export const m365MailboxExternalForwarding = defineControl({
  id: 'M365-EXO-005',
  version: '1.1.0',
  lifecycle: 'stable',
  title: 'No mailboxes forward to external recipients',
  technology: 'm365',
  category: 'Data protection',
  subcategory: 'Email forwarding',
  description:
    "Identifies mailboxes with administrator-level (SMTP) forwarding configured to an address outside the organization's accepted domains, and mailboxes forwarding to a recipient object that should be verified.",
  rationale:
    'Mailbox forwarding (ForwardingSmtpAddress) sends a copy of every message a mailbox receives to another address. Forwarding to an external address is a common persistence and data-theft technique after a mailbox compromise, and it can also be a leftover from an employee departure or a policy violation. Every external forwarding should be known and approved.',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'All Microsoft 365 tenants with Exchange Online.' },
  requiredEvidence: ['exchange.mailboxForwarding', 'exchange.acceptedDomains'],
  optionalEvidence: ['exchange.outboundSpamPolicies'],
  evaluation: {
    logic:
      'For each mailbox with forwarding: ForwardingAddress takes precedence. A resolved mail contact or mail user uses its external address; a resolved mailbox uses its primary SMTP address. Groups, unsupported types and unresolved recipients require REVIEW. Otherwise ForwardingSmtpAddress is parsed (an "smtp:" prefix is removed, case-insensitive); forwarding is external when its domain is not an accepted domain (exact match, or a subdomain of a "*.domain" accepted domain entry). FAIL when any mailbox forwards externally; REVIEW when there are only recipient-object forwards or addresses that cannot be parsed; PASS when no mailbox forwards or all forward to accepted domains. NOT_ASSESSED when SMTP forwarding exists but no accepted domains were collected. Inbox rules are assessed separately by M365-EXO-007.',
    parameters: {},
  },
  expectedState:
    'No mailbox forwards to an external address, or each external forwarding is documented and approved.',
  remediation: {
    summary:
      'Confirm each external forwarding with the mailbox owner, remove unapproved forwarding and investigate unexpected ones as a possible compromise.',
    steps: [
      'For each listed mailbox, contact the owner (or manager for a shared mailbox) and confirm whether the forwarding is approved.',
      "If the forwarding is not expected, treat the mailbox as potentially compromised: reset the password, revoke sessions, review sign-in logs and Inbox rules, and follow Microsoft's compromised account guidance.",
      'Remove forwarding in the Exchange admin center: Recipients > Mailboxes > select the mailbox > Mailbox > Email forwarding > Manage email forwarding, and turn off "Forward all emails sent to this mailbox". Or use the script example.',
      'Block automatic external forwarding by default with the outbound spam policy (M365-EXO-003) so that new forwarding cannot be set up silently.',
    ],
    scriptExample:
      'Connect-ExchangeOnline\n# List mailboxes with forwarding\nGet-EXOMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward |\n  Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } |\n  Format-Table UserPrincipalName, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward\n# Remove forwarding from one mailbox after confirming it is not approved\nSet-Mailbox -Identity user@contoso.com -ForwardingSmtpAddress $null -ForwardingAddress $null',
    effort: 'low',
  },
  implementationConsiderations: [
    'Removing forwarding may break an approved business process; confirm with the owner first unless you suspect compromise.',
    'When the outbound spam policy blocks automatic external forwarding, external mailbox forwarding bounces with an NDR, but the configuration remains and becomes active again if the policy changes.',
    'Remote domain settings do not block forwarding configured by administrators on a mailbox.',
    'Forwarding created through Inbox rules is not part of this evidence; use the Auto forwarded messages report to find it.',
  ],
  impact: 'Messages to the affected mailboxes are no longer copied to the external address.',
  rollback: [
    'Re-apply approved forwarding with Set-Mailbox -Identity <mailbox> -ForwardingSmtpAddress smtp:<address> -DeliverToMailboxAndForward $true.',
  ],
  validation: [
    'Re-run the AdminSecOps Exchange collector and confirm M365-EXO-005 is PASS or lists only approved forwarding.',
    'Run Get-EXOMailbox with the ForwardingSmtpAddress property as in the script example and confirm the results.',
  ],
  references: [
    M365_REF.mailboxForwarding,
    M365_REF.externalForwarding,
    M365_REF.compromisedAccount,
    M365_REF.autoForwardedReport,
    M365_REF.attackEmailForwardingRule,
  ],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-4' },
    { framework: 'MITRE-ATTACK', id: 'T1114.003' },
  ],
  tags: ['data-exfiltration', 'email-forwarding', 'exchange-online'],
  evaluate: (ctx) => {
    const entries = ctx.data('exchange.mailboxForwarding');
    const accepted = ctx.data('exchange.acceptedDomains');
    const classified: Classified[] = [];
    for (const entry of entries) {
      const recipient = nonEmpty(entry.forwardingAddress);
      let smtp = nonEmpty(entry.forwardingSmtpAddress);
      if (recipient !== null) {
        const resolved = nonEmpty(entry.resolvedForwardingSmtpAddress ?? null);
        const supported = ['MailContact', 'MailUser', 'UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox'].includes(entry.resolvedForwardingRecipientType ?? '');
        if (resolved !== null && supported) smtp = resolved;
        else {
          classified.push({ kind: 'recipient', entry, recipient, ignoredSmtp: smtp });
          continue;
        }
      }
      if (smtp === null) continue;
      const parsed = parseSmtpAddress(smtp);
      if (parsed === null) {
        classified.push({ kind: 'unparseable', entry, value: smtp });
        continue;
      }
      if (accepted.length > 0 && isAcceptedDomain(parsed.domain, accepted))
        classified.push({ kind: 'internal', entry });
      else
        classified.push({
          kind: 'external',
          entry,
          address: parsed.address,
          domain: parsed.domain,
        });
    }
    const external = classified.filter((c) => c.kind === 'external');
    const toReview = classified.filter((c) => c.kind === 'recipient' || c.kind === 'unparseable');
    const internal = classified.filter((c) => c.kind === 'internal');
    const facts = [
      fact('Mailboxes with forwarding configured', entries.length),
      fact('Forwarding to external addresses', external.length),
      fact('Forwarding to accepted domains', internal.length),
      fact('Forwarding to recipient objects or unrecognized values', toReview.length),
      fact('Accepted domains', accepted.length),
    ];
    if (
      accepted.length === 0 &&
      (external.length > 0 || internal.length > 0)
    ) {
      return notAssessed({
        reason:
          'Mailboxes forward to SMTP addresses but no accepted domains were collected, so internal and external destinations cannot be distinguished.',
        summary: 'Forwarding destinations could not be classified.',
        facts,
      });
    }
    const toObject = (c: Classified): AffectedObject => {
      const upn = c.entry.userPrincipalName;
      const type = c.entry.recipientTypeDetails ? `${c.entry.recipientTypeDetails}; ` : '';
      switch (c.kind) {
        case 'external':
          return affected(
            'mailbox',
            upn,
            upn,
            `${type}Forwards to ${c.address} (domain ${c.domain} is not an accepted domain); ${keepCopy(c.entry)}`,
          );
        case 'recipient':
          return affected(
            'mailbox',
            upn,
            upn,
            `${type}Forwards to recipient object "${c.recipient}" (verify whether it is a mail contact or mail user with an external address); ${keepCopy(c.entry)}${c.ignoredSmtp === null ? '' : `; ForwardingSmtpAddress ${c.ignoredSmtp} is also set but is ignored while ForwardingAddress is set`}`,
          );
        case 'unparseable':
          return affected(
            'mailbox',
            upn,
            upn,
            `${type}ForwardingSmtpAddress "${c.value}" is not a recognizable SMTP address`,
          );
        case 'internal':
          return affected('mailbox', upn, upn, `${type}Forwards to an accepted domain`);
      }
    };
    const sortByUpn = (a: Classified, b: Classified) =>
      a.entry.userPrincipalName.localeCompare(b.entry.userPrincipalName);
    const notes: string[] = [];
    notes.push('Recipient lookups cover the immediate destination only. Group membership, chained forwarding and final delivery are not inferred from an accepted-domain address.');
    const allOff = outboundPoliciesAllOff(ctx);
    if (allOff === true && external.length > 0) {
      notes.push(
        "All outbound spam policies block automatic external forwarding (Off), so these forwards currently bounce with an NDR. The configuration is still a finding: it shows intent (possibly an attacker's) and becomes active if the policy changes.",
      );
    } else if (allOff === false && external.length > 0) {
      notes.push(
        'At least one outbound spam policy does not explicitly block automatic external forwarding (see M365-EXO-003), so these forwards may be delivering mail externally now.',
      );
    }
    notes.push(
      'Inbox-rule forwarding is assessed separately by M365-EXO-007 and mail-flow recipient actions by M365-EXO-008; their collection coverage must also be reviewed.',
    );
    if (external.length > 0) {
      return fail({
        reason: `${plural(external.length, 'mailbox', 'mailboxes')} forward mail to external addresses.`,
        summary: `${plural(external.length, 'mailbox', 'mailboxes')} forward to addresses outside the organization's accepted domains.`,
        facts,
        affectedObjects: [...external.sort(sortByUpn), ...toReview.sort(sortByUpn)].map(toObject),
        notes,
      });
    }
    if (toReview.length > 0) {
      return review({
        reason: `${plural(toReview.length, 'mailbox', 'mailboxes')} forward to a recipient object or an unrecognized address; whether the destination is outside the organization cannot be determined from the evidence.`,
        summary: 'Some forwarding destinations need to be verified.',
        facts,
        affectedObjects: toReview.sort(sortByUpn).map(toObject),
        notes,
      });
    }
    return pass({
      reason:
        entries.length === 0
          ? 'No mailbox has mailbox-level forwarding configured.'
          : `All ${plural(internal.length, 'mailbox', 'mailboxes')} with forwarding forward to accepted domains.`,
      summary: 'No mailbox forwards to an external address.',
      facts,
      notes,
    });
  },
});


