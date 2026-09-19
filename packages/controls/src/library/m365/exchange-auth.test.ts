import { describe, expect, it } from 'vitest';
import { organizationConfig, smtpAuthMailbox } from '../../../test/builders/m365.js';
import { run } from '../../../test/run.js';
import {
  m365ModernAuthExchange,
  m365SmtpAuthDisabled,
  m365SmtpAuthMailboxes,
} from './exchange-auth.js';

describe('M365-EXO-001 SMTP AUTH disabled organization-wide', () => {
  it('passes when SMTP AUTH is disabled', () => {
    const result = run(m365SmtpAuthDisabled, {
      'exchange.transportConfig': { smtpClientAuthenticationDisabled: true },
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('M365-EXO-002');
  });

  it('fails when SMTP AUTH is enabled', () => {
    expect(
      run(m365SmtpAuthDisabled, {
        'exchange.transportConfig': { smtpClientAuthenticationDisabled: false },
      }).status,
    ).toBe('FAIL');
  });

  it('is NOT_ASSESSED when the transport configuration failed to collect', () => {
    expect(
      run(m365SmtpAuthDisabled, {}, { unavailable: { 'exchange.transportConfig': 'Failed' } })
        .status,
    ).toBe('NOT_ASSESSED');
  });
});

describe('M365-EXO-002 mailboxes with SMTP AUTH explicitly enabled', () => {
  it('passes when there are no overrides', () => {
    expect(run(m365SmtpAuthMailboxes, { 'exchange.smtpAuthMailboxes': [] }).status).toBe('PASS');
  });

  it('passes when overrides only disable SMTP AUTH', () => {
    const result = run(m365SmtpAuthMailboxes, {
      'exchange.smtpAuthMailboxes': [smtpAuthMailbox('a@contoso.example', true)],
    });
    expect(result.status).toBe('PASS');
  });

  it('requires review and lists each mailbox that enables SMTP AUTH, sorted', () => {
    const result = run(m365SmtpAuthMailboxes, {
      'exchange.smtpAuthMailboxes': [
        smtpAuthMailbox('scanner@contoso.example', false),
        smtpAuthMailbox('blocked@contoso.example', true),
        smtpAuthMailbox('app@contoso.example', false),
      ],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.statusReason).toContain('business owner');
    expect(result.affectedObjects.map((o) => o.id)).toEqual([
      'app@contoso.example',
      'scanner@contoso.example',
    ]);
    expect(result.affectedObjects[0]?.detail).toContain('SmtpClientAuthenticationDisabled=False');
  });

  it('adds context when SMTP AUTH is also enabled organization-wide', () => {
    const result = run(m365SmtpAuthMailboxes, {
      'exchange.smtpAuthMailboxes': [smtpAuthMailbox('app@contoso.example', false)],
      'exchange.transportConfig': { smtpClientAuthenticationDisabled: false },
    });
    expect(result.status).toBe('REVIEW');
    expect(result.notes.join(' ')).toContain('enabled for the whole organization');
  });

  it('does not require the optional transport configuration', () => {
    const result = run(
      m365SmtpAuthMailboxes,
      { 'exchange.smtpAuthMailboxes': [smtpAuthMailbox('app@contoso.example', false)] },
      { unavailable: { 'exchange.transportConfig': 'Failed' } },
    );
    expect(result.status).toBe('REVIEW');
  });

  it('downgrades PASS to REVIEW when the mailbox list is partial', () => {
    const result = run(
      m365SmtpAuthMailboxes,
      { 'exchange.smtpAuthMailboxes': [] },
      { partial: ['exchange.smtpAuthMailboxes'] },
    );
    expect(result.status).toBe('REVIEW');
  });
});

describe('M365-EXO-006 modern authentication for Exchange Online', () => {
  it('passes when OAuth2ClientProfileEnabled is true', () => {
    expect(
      run(m365ModernAuthExchange, { 'exchange.organizationConfig': organizationConfig() }).status,
    ).toBe('PASS');
  });

  it('fails when modern authentication is disabled', () => {
    const result = run(m365ModernAuthExchange, {
      'exchange.organizationConfig': organizationConfig({ oAuth2ClientProfileEnabled: false }),
    });
    expect(result.status).toBe('FAIL');
  });
});
