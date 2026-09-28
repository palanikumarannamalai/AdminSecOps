import { describe, expect, it } from 'vitest';
import {
  acceptedDomain,
  mailboxForwarding,
  outboundPolicy,
  remoteDomain,
} from '../../../test/builders/m365.js';
import { run } from '../../../test/run.js';
import {
  m365MailboxExternalForwarding,
  m365OutboundSpamForwarding,
  m365RemoteDomainForwarding,
} from './forwarding.js';

const defaultOff = outboundPolicy('Default', 'Off', true);

describe('M365-EXO-003 outbound spam policies block automatic external forwarding', () => {
  it('passes when every policy is Off', () => {
    const result = run(m365OutboundSpamForwarding, {
      'exchange.outboundSpamPolicies': [defaultOff, outboundPolicy('Executives', 'Off')],
    });
    expect(result.status).toBe('PASS');
  });

  it('treats the mode case-insensitively', () => {
    const result = run(m365OutboundSpamForwarding, {
      'exchange.outboundSpamPolicies': [outboundPolicy('Default', 'OFF', true)],
    });
    expect(result.status).toBe('PASS');
  });

  it('fails when the default policy allows forwarding', () => {
    const result = run(m365OutboundSpamForwarding, {
      'exchange.outboundSpamPolicies': [outboundPolicy('Default', 'On', true)],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]).toMatchObject({ type: 'outboundSpamPolicy', id: 'Default' });
    expect(result.affectedObjects[0]?.detail).toContain('default policy');
  });

  it('requires review when only a custom policy allows forwarding (scope is not collected)', () => {
    const result = run(m365OutboundSpamForwarding, {
      'exchange.outboundSpamPolicies': [defaultOff, outboundPolicy('Partner forwarding', 'On')],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.statusReason).toContain('scoped');
    expect(result.affectedObjects.map((o) => o.name)).toEqual(['Partner forwarding']);
  });

  it('requires review when the default policy is Automatic, because its behaviour differs by organization', () => {
    const result = run(m365OutboundSpamForwarding, {
      'exchange.outboundSpamPolicies': [outboundPolicy('Default', 'Automatic', true)],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.notes.join(' ')).toContain('2021');
  });

  it('requires review for an unrecognized mode value', () => {
    const result = run(m365OutboundSpamForwarding, {
      'exchange.outboundSpamPolicies': [outboundPolicy('Default', 'Sometimes', true)],
    });
    expect(result.status).toBe('REVIEW');
  });

  it('is NOT_ASSESSED when the default policy is missing from the evidence', () => {
    const result = run(m365OutboundSpamForwarding, {
      'exchange.outboundSpamPolicies': [outboundPolicy('Custom', 'Off')],
    });
    expect(result.status).toBe('NOT_ASSESSED');
  });

  it('is NOT_ASSESSED for an empty policy list (never PASS)', () => {
    expect(run(m365OutboundSpamForwarding, { 'exchange.outboundSpamPolicies': [] }).status).toBe(
      'NOT_ASSESSED',
    );
  });

  it('downgrades PASS to REVIEW on partial evidence', () => {
    const result = run(
      m365OutboundSpamForwarding,
      { 'exchange.outboundSpamPolicies': [defaultOff] },
      { partial: ['exchange.outboundSpamPolicies'] },
    );
    expect(result.status).toBe('REVIEW');
  });
});

describe('M365-EXO-004 default remote domain blocks automatic forwarding', () => {
  it('passes when the Default remote domain blocks forwarding', () => {
    const result = run(m365RemoteDomainForwarding, {
      'exchange.remoteDomains': [remoteDomain('Default', '*', false)],
    });
    expect(result.status).toBe('PASS');
  });

  it('notes named remote domains that allow forwarding as an allow list', () => {
    const result = run(m365RemoteDomainForwarding, {
      'exchange.remoteDomains': [
        remoteDomain('Default', '*', false),
        remoteDomain('Partner', 'partner.example', true),
      ],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('Partner (partner.example)');
  });

  it('fails when the Default remote domain allows forwarding', () => {
    const result = run(m365RemoteDomainForwarding, {
      'exchange.remoteDomains': [remoteDomain('Default', '*', true)],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]).toMatchObject({
      type: 'remoteDomain',
      detail: 'AutoForwardEnabled=True',
    });
  });

  it('still fails but explains defence in depth when outbound spam policies block forwarding', () => {
    const result = run(m365RemoteDomainForwarding, {
      'exchange.remoteDomains': [remoteDomain('Default', '*', true)],
      'exchange.outboundSpamPolicies': [defaultOff],
    });
    expect(result.status).toBe('FAIL');
    expect(result.notes.join(' ')).toContain('defence in depth');
  });

  it('does not add the defence-in-depth note when a policy allows forwarding', () => {
    const result = run(m365RemoteDomainForwarding, {
      'exchange.remoteDomains': [remoteDomain('Default', '*', true)],
      'exchange.outboundSpamPolicies': [outboundPolicy('Default', 'Automatic', true)],
    });
    expect(result.status).toBe('FAIL');
    expect(result.notes.join(' ')).not.toContain('defence in depth');
  });

  it('is NOT_ASSESSED when the Default remote domain is missing', () => {
    const result = run(m365RemoteDomainForwarding, {
      'exchange.remoteDomains': [remoteDomain('Partner', 'partner.example', false)],
    });
    expect(result.status).toBe('NOT_ASSESSED');
  });
});

describe('M365-EXO-005 mailboxes forwarding to external recipients', () => {
  it.each([
    ['MailContact', 'smtp:user@outside.example', 'FAIL'],
    ['MailUser', 'smtp:user@outside.example', 'FAIL'],
    ['UserMailbox', 'user@contoso.example', 'PASS'],
    ['MailUniversalDistributionGroup', 'group@contoso.example', 'REVIEW'],
    [null, 'user@contoso.example', 'REVIEW'],
  ])('uses resolved destination only for supported recipient type %s', (resolvedForwardingRecipientType, resolvedForwardingSmtpAddress, expected) => {
    const entry = { ...mailboxForwarding('source@contoso.example', { forwardingAddress: 'recipient-object', forwardingSmtpAddress: 'smtp:ignored@outside.example' }), resolvedForwardingRecipientType, resolvedForwardingSmtpAddress };
    expect(run(m365MailboxExternalForwarding, { 'exchange.mailboxForwarding': [entry], 'exchange.acceptedDomains': [acceptedDomain('contoso.example')] }).status).toBe(expected);
    if (expected !== 'REVIEW') expect(run(m365MailboxExternalForwarding, { 'exchange.mailboxForwarding': [entry], 'exchange.acceptedDomains': [] }).status).toBe('NOT_ASSESSED');
  });
  const domains = [
    acceptedDomain('contoso.example', { default: true }),
    acceptedDomain('contoso.onmicrosoft.com'),
    acceptedDomain('*.fabrikam.example'),
  ];

  it('passes when no mailbox forwards', () => {
    const result = run(m365MailboxExternalForwarding, {
      'exchange.mailboxForwarding': [],
      'exchange.acceptedDomains': domains,
    });
    expect(result.status).toBe('PASS');
    expect(result.statusReason).toContain('No mailbox');
  });

  it('passes when forwarding targets accepted domains, including smtp: prefixes, case and wildcard subdomains', () => {
    const result = run(m365MailboxExternalForwarding, {
      'exchange.mailboxForwarding': [
        mailboxForwarding('a@contoso.example', {
          forwardingSmtpAddress: 'smtp:Team@CONTOSO.example',
        }),
        mailboxForwarding('b@contoso.example', {
          forwardingSmtpAddress: 'SMTP:b@contoso.onmicrosoft.com',
        }),
        mailboxForwarding('c@contoso.example', { forwardingSmtpAddress: 'c@eu.fabrikam.example' }),
      ],
      'exchange.acceptedDomains': domains,
    });
    expect(result.status).toBe('PASS');
  });

  it('fails for forwarding to an external domain and identifies the mailbox and destination', () => {
    const result = run(m365MailboxExternalForwarding, {
      'exchange.mailboxForwarding': [
        mailboxForwarding('ceo@contoso.example', {
          forwardingSmtpAddress: 'smtp:ceo.private@gmail.example',
          deliverToMailboxAndForward: false,
        }),
        mailboxForwarding('ok@contoso.example', {
          forwardingSmtpAddress: 'smtp:team@contoso.example',
        }),
      ],
      'exchange.acceptedDomains': domains,
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(1);
    expect(result.affectedObjects[0]?.id).toBe('ceo@contoso.example');
    expect(result.affectedObjects[0]?.detail).toContain('ceo.private@gmail.example');
    expect(result.affectedObjects[0]?.detail).toContain('no copy kept in mailbox');
  });

  it('treats a lookalike or parent domain as external', () => {
    const result = run(m365MailboxExternalForwarding, {
      'exchange.mailboxForwarding': [
        mailboxForwarding('a@contoso.example', {
          forwardingSmtpAddress: 'x@contoso.example.attacker.example',
        }),
        mailboxForwarding('b@contoso.example', { forwardingSmtpAddress: 'x@fabrikam.example' }),
      ],
      'exchange.acceptedDomains': domains,
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(2);
  });

  it('requires review when forwarding goes to a recipient object', () => {
    const result = run(m365MailboxExternalForwarding, {
      'exchange.mailboxForwarding': [
        mailboxForwarding('shared@contoso.example', {
          forwardingAddress: 'Partner Contact',
          recipientTypeDetails: 'SharedMailbox',
        }),
      ],
      'exchange.acceptedDomains': domains,
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.detail).toContain('mail contact');
    expect(result.affectedObjects[0]?.detail).toContain('SharedMailbox');
  });

  it('uses ForwardingAddress over ForwardingSmtpAddress when both are set', () => {
    const result = run(m365MailboxExternalForwarding, {
      'exchange.mailboxForwarding': [
        mailboxForwarding('a@contoso.example', {
          forwardingAddress: 'Internal User',
          forwardingSmtpAddress: 'smtp:x@outside.example',
        }),
      ],
      'exchange.acceptedDomains': domains,
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.detail).toContain('ignored while ForwardingAddress is set');
  });

  it('requires review for an unparseable forwarding address', () => {
    const result = run(m365MailboxExternalForwarding, {
      'exchange.mailboxForwarding': [
        mailboxForwarding('a@contoso.example', { forwardingSmtpAddress: 'smtp:not-an-address' }),
      ],
      'exchange.acceptedDomains': domains,
    });
    expect(result.status).toBe('REVIEW');
  });

  it('notes that outbound spam policies currently block the forwarding', () => {
    const result = run(m365MailboxExternalForwarding, {
      'exchange.mailboxForwarding': [
        mailboxForwarding('a@contoso.example', { forwardingSmtpAddress: 'x@outside.example' }),
      ],
      'exchange.acceptedDomains': domains,
      'exchange.outboundSpamPolicies': [defaultOff],
    });
    expect(result.status).toBe('FAIL');
    expect(result.notes.join(' ')).toContain('currently bounce');
  });

  it('notes that forwarding may be active when a policy does not block it', () => {
    const result = run(m365MailboxExternalForwarding, {
      'exchange.mailboxForwarding': [
        mailboxForwarding('a@contoso.example', { forwardingSmtpAddress: 'x@outside.example' }),
      ],
      'exchange.acceptedDomains': domains,
      'exchange.outboundSpamPolicies': [outboundPolicy('Default', 'On', true)],
    });
    expect(result.notes.join(' ')).toContain('may be delivering mail externally');
  });

  it('is NOT_ASSESSED when SMTP forwarding exists but no accepted domains were collected', () => {
    const result = run(m365MailboxExternalForwarding, {
      'exchange.mailboxForwarding': [
        mailboxForwarding('a@contoso.example', { forwardingSmtpAddress: 'x@contoso.example' }),
      ],
      'exchange.acceptedDomains': [],
    });
    expect(result.status).toBe('NOT_ASSESSED');
  });

  it('is NOT_ASSESSED when accepted domains are unavailable', () => {
    const result = run(
      m365MailboxExternalForwarding,
      { 'exchange.mailboxForwarding': [] },
      { unavailable: { 'exchange.acceptedDomains': 'Unauthorized' } },
    );
    expect(result.status).toBe('NOT_ASSESSED');
  });

  it('downgrades PASS to REVIEW when the forwarding list was partially collected', () => {
    const result = run(
      m365MailboxExternalForwarding,
      { 'exchange.mailboxForwarding': [], 'exchange.acceptedDomains': domains },
      { partial: ['exchange.mailboxForwarding'] },
    );
    expect(result.status).toBe('REVIEW');
  });
});
