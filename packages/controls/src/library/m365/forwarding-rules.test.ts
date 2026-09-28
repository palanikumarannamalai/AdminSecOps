import { describe, expect, it } from 'vitest';
import { run } from '../../../test/run.js';
import { m365InboxForwardingRules as inbox, m365TransportForwardingRules as transport } from './forwarding-rules.js';

describe('M365-EXO-007 and M365-EXO-008 forwarding-rule review controls', () => {
  it('does not pass missing evidence', () => {
    expect(run(inbox, {}).status).toBe('NOT_ASSESSED');
    expect(run(transport, {}).status).toBe('NOT_ASSESSED');
  });
  it.each([[true,0,'PASS'],[false,0,'REVIEW'],[true,1,'REVIEW']])('honours Inbox coverage completeness %s and unread count %s', (complete, unscannedMailboxes, expected) => {
    expect(run(inbox, { 'exchange.inboxRules': { complete, scannedMailboxes: 2, unscannedMailboxes, rules: [] } }).status).toBe(expected);
  });
  it('keeps entirely unread mailboxes unassessed', () => {
    expect(run(inbox, { 'exchange.inboxRules': { complete: false, scannedMailboxes: 0, unscannedMailboxes: 5, rules: [] } }).status).toBe('NOT_ASSESSED');
  });
  it.each([[true,'REVIEW'],[null,'REVIEW'],[false,'PASS']])('handles Inbox rule enabled=%s', (enabled, expected) => {
    expect(run(inbox, { 'exchange.inboxRules': { complete: true, scannedMailboxes: 1, unscannedMailboxes: 0, rules: [{ mailbox: 'test@contoso.example', id: 'rule1', name: 'Forward', enabled }] } }).status).toBe(expected);
  });
  const rule = { id: 'rule1', name: 'Copy', state: 'Enabled', mode: 'Enforce', priority: 0, hasRedirect: false, hasCopy: false, hasBlindCopy: false, hasAddedRecipients: false };
  it.each(['hasRedirect','hasCopy','hasBlindCopy','hasAddedRecipients'])('reviews each mail-flow action %s', key => {
    expect(run(transport, { 'exchange.transportRules': { complete: true, rules: [{ ...rule, [key]: true }] } }).status).toBe('REVIEW');
  });
  it('does not pass unknown properties, partial evidence or audit-mode forwarding', () => {
    for (const data of [{ complete: false, rules: [] }, { complete: true, rules: [{ ...rule, hasCopy: null }] }, { complete: true, rules: [{ ...rule, mode: 'Audit', hasCopy: true }] }])
      expect(run(transport, { 'exchange.transportRules': data }).status).toBe('REVIEW');
  });
  it('excludes explicitly disabled mail-flow actions', () => {
    expect(run(transport, { 'exchange.transportRules': { complete: true, rules: [{ ...rule, state: 'Disabled', hasCopy: true }] } }).status).toBe('PASS');
  });
});
