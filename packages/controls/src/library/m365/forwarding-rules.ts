import { defineControl } from '../../define.js';
import { affected, fact, notAssessed, pass, review } from '../../helpers.js';

const common = {
  version: '1.0.0', lifecycle: 'preview' as const, technology: 'm365' as const,
  category: 'Data protection', subcategory: 'Email forwarding', severity: 'medium' as const,
  confidence: 'medium' as const, optionalEvidence: [], frameworkMappings: [], tags: ['exchange', 'forwarding'],
  rationale: 'Forwarding and recipient-copy actions can disclose email. Their business purpose and effective scope need administrator review.',
  expectedState: 'Each forwarding or recipient-copy action has a documented owner, purpose and approved destination.',
  remediation: { summary: 'Review flagged rules before changing them.', steps: ['Record the rule, owner and business purpose.', 'Review destinations, conditions, exceptions and rule ordering in Exchange.', 'Remove or disable only unapproved rules after impact review.'], effort: 'medium' as const },
  implementationConsiderations: ['No message content is collected. A configured action does not prove external delivery or compromise.', 'Disabled rules are excluded; unknown state requires review.'],
  impact: 'Changing forwarding rules may interrupt approved mail routing or business workflows.',
  rollback: ['Restore the recorded rule configuration if an approved workflow is affected.'],
  validation: ['Run a new assessment and verify the collection scope.', 'Confirm remaining forwarding actions have documented approval.'],
};

export const m365InboxForwardingRules = defineControl({
  ...common, id: 'M365-EXO-007', title: 'Inbox forwarding rules have been reviewed',
  description: 'Finds enabled or unknown-state Inbox rules with forwarding, redirect or forward-as-attachment actions in the scanned user/shared mailboxes, including hidden rules.',
  applicability: { description: 'User and shared Exchange Online mailboxes visible to the collector, within its reported scan limits.' },
  requiredEvidence: ['exchange.inboxRules'],
  evaluation: { logic: 'Review enabled or unknown-state forwarding rules. No scanned mailboxes with incomplete collection: not assessed. Partial coverage: review. Complete scope with no enabled forwarding rules: pass for this scope only.', parameters: {} },
  references: [{ title: 'Get-InboxRule', publisher: 'Microsoft', url: 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboxrule?view=exchange-ps' }],
  evaluate: ctx => {
    const data = ctx.data('exchange.inboxRules');
    const rules = data.rules.filter(r => r.enabled !== false);
    const facts = [fact('Mailboxes scanned', data.scannedMailboxes), fact('Mailboxes known to be unscanned (lower bound)', data.unscannedMailboxes), fact('Complete visible scope', data.complete), fact('Forwarding rules requiring review', rules.length)];
    const notes = ['Global Reader and View-Only Organization Management cannot read Inbox rules. Do not elevate permissions automatically.', 'The scan is limited to 25 visible user/shared mailboxes and 200 rules per mailbox. Destinations and message content are not stored.'];
    if (rules.length) return review({ reason: 'Forwarding rules require owner and destination approval; this is not proof of external delivery.', summary: 'Review Inbox forwarding rules.', facts, notes, affectedObjects: rules.map((r,i) => affected('inboxRule', `${r.mailbox}/${r.id ?? i}`, `${r.mailbox}: ${r.name ?? 'Unnamed rule'}`, `Enabled: ${r.enabled ?? 'unknown'}`)) });
    if (!data.complete && data.scannedMailboxes === 0) return notAssessed({ reason: 'No mailbox could be fully scanned. Check the Exchange role and reported collection errors.', summary: 'Inbox-rule coverage unavailable.', facts, notes });
    if (!data.complete || data.unscannedMailboxes > 0) return review({ reason: 'The scan was incomplete; no tenant-wide conclusion can be drawn.', summary: 'Inbox-rule coverage incomplete.', facts, notes });
    return pass({ reason: 'No enabled forwarding rules were found in the complete visible user/shared mailbox scope.', summary: 'No Inbox forwarding rules found in the assessed scope.', facts, notes });
  },
});

export const m365TransportForwardingRules = defineControl({
  ...common, id: 'M365-EXO-008', title: 'Mail-flow recipient actions have been reviewed',
  description: 'Reviews non-disabled mail-flow rules that redirect, copy, blind-copy or add recipients. Conditions, exceptions, activation dates and destination approval are not evaluated.',
  applicability: { description: 'Exchange Online mail-flow rules visible to the signed-in administrator.' },
  requiredEvidence: ['exchange.transportRules'],
  evaluation: { logic: 'Review non-disabled rules with recipient actions or unknown action properties. Partial collection is review, never pass. Pass only when complete evidence contains no such non-disabled actions.', parameters: {} },
  references: [{ title: 'Get-TransportRule', publisher: 'Microsoft', url: 'https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-transportrule?view=exchange-ps' }],
  evaluate: ctx => {
    const data = ctx.data('exchange.transportRules');
    const rules = data.rules.filter(r => r.state?.toLowerCase() !== 'disabled' && [r.hasRedirect, r.hasCopy, r.hasBlindCopy, r.hasAddedRecipients].some(v => v !== false));
    const facts = [fact('Mail-flow rules read', data.rules.length), fact('Rules requiring review', rules.length), fact('Complete visible scope', data.complete)];
    const notes = ['Audit-mode rules are included for review but are not described as active forwarding. Conditions, exceptions, dates and final delivery need manual validation.'];
    if (rules.length) return review({ reason: 'Recipient-changing actions or unknown action settings need business approval and scope review.', summary: 'Review mail-flow recipient actions.', facts, notes, affectedObjects: rules.map((r,i) => affected('transportRule', r.id ?? String(i), r.name ?? 'Unnamed rule', `State: ${r.state ?? 'unknown'}; mode: ${r.mode ?? 'unknown'}; priority: ${r.priority ?? 'unknown'}`)) });
    if (!data.complete) return review({ reason: 'Mail-flow rule collection was incomplete.', summary: 'Mail-flow coverage incomplete.', facts, notes });
    return pass({ reason: 'No non-disabled recipient-changing actions were found in the complete visible rule scope.', summary: 'No mail-flow recipient actions found in the assessed scope.', facts, notes });
  },
});
