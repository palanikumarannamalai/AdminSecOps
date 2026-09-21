import { describe, expect, it } from 'vitest';
import { acceptedDomain, dkimConfig, dnsRecord } from '../../../test/builders/m365.js';
import { run } from '../../../test/run.js';
import { m365DkimEnabled, m365DmarcPolicy, m365SpfPublished } from './mail-authentication.js';

const onmicrosoft = acceptedDomain('contoso.onmicrosoft.com');

describe('M365-MAIL-001 DKIM signing for custom domains', () => {
  it('does not claim valid signing when status is missing', () => {
    const result = run(m365DkimEnabled, {
      'exchange.acceptedDomains': [acceptedDomain('contoso.example')],
      'exchange.dkimSigningConfigs': [dkimConfig('contoso.example', true, null)],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.detail).toContain('not reported');
  });
  it('passes when every custom authoritative domain signs with a Valid status', () => {
    const result = run(m365DkimEnabled, {
      'exchange.acceptedDomains': [
        onmicrosoft,
        acceptedDomain('contoso.example'),
        acceptedDomain('fabrikam.example'),
      ],
      'exchange.dkimSigningConfigs': [
        dkimConfig('CONTOSO.example', true),
        dkimConfig('fabrikam.example', true, 'Valid'),
        dkimConfig('contoso.onmicrosoft.com', false),
      ],
    });
    expect(result.status).toBe('PASS');
  });

  it('fails when a domain has no DKIM configuration, and ignores onmicrosoft and non-authoritative domains', () => {
    const result = run(m365DkimEnabled, {
      'exchange.acceptedDomains': [
        onmicrosoft,
        acceptedDomain('contoso.mail.onmicrosoft.com'),
        acceptedDomain('contoso.example'),
        acceptedDomain('relay.example', { domainType: 'InternalRelay' }),
      ],
      'exchange.dkimSigningConfigs': [],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.id)).toEqual(['contoso.example']);
    expect(result.affectedObjects[0]?.detail).toContain('No DKIM signing configuration');
  });

  it('fails when signing is disabled', () => {
    const result = run(m365DkimEnabled, {
      'exchange.acceptedDomains': [acceptedDomain('contoso.example')],
      'exchange.dkimSigningConfigs': [dkimConfig('contoso.example', false)],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('disabled');
  });

  it('requires review when signing is enabled but the status is not Valid', () => {
    const result = run(m365DkimEnabled, {
      'exchange.acceptedDomains': [acceptedDomain('contoso.example')],
      'exchange.dkimSigningConfigs': [dkimConfig('contoso.example', true, 'CnameMissing')],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.detail).toContain('CnameMissing');
  });

  it('excludes parked domains that publish "v=spf1 -all"', () => {
    const result = run(m365DkimEnabled, {
      'exchange.acceptedDomains': [
        acceptedDomain('contoso.example'),
        acceptedDomain('parked.example'),
      ],
      'exchange.dkimSigningConfigs': [dkimConfig('contoso.example', true)],
      'exchange.mailDnsRecords': [
        dnsRecord('contoso.example'),
        dnsRecord('parked.example', { spf: ['v=spf1 -all'] }),
      ],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('parked.example');
  });

  it('passes when the only custom domain is parked', () => {
    const result = run(m365DkimEnabled, {
      'exchange.acceptedDomains': [acceptedDomain('parked.example')],
      'exchange.dkimSigningConfigs': [],
      'exchange.mailDnsRecords': [dnsRecord('parked.example', { spf: ['"v=spf1 -all"'] })],
    });
    expect(result.status).toBe('PASS');
  });

  it('is NOT_APPLICABLE when only onmicrosoft.com domains exist', () => {
    const result = run(m365DkimEnabled, {
      'exchange.acceptedDomains': [onmicrosoft],
      'exchange.dkimSigningConfigs': [],
    });
    expect(result.status).toBe('NOT_APPLICABLE');
  });

  it('is NOT_ASSESSED when DKIM configuration was not collected', () => {
    const result = run(m365DkimEnabled, {
      'exchange.acceptedDomains': [acceptedDomain('contoso.example')],
    });
    expect(result.status).toBe('NOT_ASSESSED');
  });
});

describe('M365-MAIL-002 SPF records', () => {
  it('passes with -all and ~all and recommends -all for soft fail', () => {
    const result = run(m365SpfPublished, {
      'exchange.mailDnsRecords': [
        dnsRecord('contoso.example'),
        dnsRecord('fabrikam.example', {
          spf: ['v=spf1 include:spf.protection.outlook.com ~all', 'MS=ms12345'],
        }),
      ],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('fabrikam.example use ~all');
  });

  it.each([
    ['+all', 'v=spf1 +all'],
    ['?all', 'v=spf1 include:spf.protection.outlook.com ?all'],
    ['bare all', 'v=spf1 a mx all'],
    ['no all mechanism', 'v=spf1 include:spf.protection.outlook.com'],
  ])('fails for %s', (_label, record) => {
    const result = run(m365SpfPublished, {
      'exchange.mailDnsRecords': [dnsRecord('contoso.example', { spf: [record] })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.id).toBe('contoso.example');
  });

  it('fails when no SPF record is published', () => {
    const result = run(m365SpfPublished, {
      'exchange.mailDnsRecords': [
        dnsRecord('a.example', { spf: 'NotFound' }),
        dnsRecord('b.example', { spf: ['google-site-verification=abc'] }),
      ],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(2);
  });

  it('fails when multiple SPF records are published (permerror)', () => {
    const result = run(m365SpfPublished, {
      'exchange.mailDnsRecords': [
        dnsRecord('contoso.example', {
          spf: ['v=spf1 -all', 'V=SPF1 include:spf.protection.outlook.com -all'],
        }),
      ],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('permerror');
  });

  it('requires review when the policy is delegated with redirect=', () => {
    const result = run(m365SpfPublished, {
      'exchange.mailDnsRecords': [
        dnsRecord('contoso.example', { spf: ['v=spf1 redirect=_spf.contoso.example'] }),
      ],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.detail).toContain('_spf.contoso.example');
  });

  it('is NOT_ASSESSED when a lookup failed and nothing else failed (never PASS)', () => {
    const result = run(m365SpfPublished, {
      'exchange.mailDnsRecords': [
        dnsRecord('contoso.example'),
        dnsRecord('fabrikam.example', { spf: 'Error' }),
      ],
    });
    expect(result.status).toBe('NOT_ASSESSED');
    expect(result.statusReason).toContain('fabrikam.example');
  });

  it('still fails when another domain has a lookup error, and notes the error', () => {
    const result = run(m365SpfPublished, {
      'exchange.mailDnsRecords': [
        dnsRecord('a.example', { spf: 'NotFound' }),
        dnsRecord('b.example', { spf: 'Error' }),
      ],
    });
    expect(result.status).toBe('FAIL');
    expect(result.notes.join(' ')).toContain('b.example');
  });

  it('ignores onmicrosoft.com domains and duplicates', () => {
    const result = run(m365SpfPublished, {
      'exchange.mailDnsRecords': [
        dnsRecord('contoso.onmicrosoft.com', { spf: 'NotFound' }),
        dnsRecord('contoso.example'),
        dnsRecord('Contoso.Example.'),
      ],
    });
    expect(result.status).toBe('PASS');
    expect(result.observed.facts).toContainEqual({ label: 'Custom domains checked', value: 1 });
  });

  it('is NOT_APPLICABLE when only onmicrosoft.com domains are listed', () => {
    const result = run(m365SpfPublished, {
      'exchange.mailDnsRecords': [dnsRecord('contoso.onmicrosoft.com')],
    });
    expect(result.status).toBe('NOT_APPLICABLE');
  });

  it('downgrades PASS to REVIEW on partial DNS evidence', () => {
    const result = run(
      m365SpfPublished,
      { 'exchange.mailDnsRecords': [dnsRecord('contoso.example')] },
      { partial: ['exchange.mailDnsRecords'] },
    );
    expect(result.status).toBe('REVIEW');
  });
});

describe('M365-MAIL-003 DMARC policy', () => {
  it('passes with p=reject and p=quarantine', () => {
    const result = run(m365DmarcPolicy, {
      'exchange.mailDnsRecords': [
        dnsRecord('contoso.example'),
        dnsRecord('fabrikam.example', {
          dmarc: ['v=DMARC1; p=quarantine; pct=100; rua=mailto:d@fabrikam.example'],
        }),
      ],
    });
    expect(result.status).toBe('PASS');
  });

  it('requires review for p=none (monitoring) and explains why', () => {
    const result = run(m365DmarcPolicy, {
      'exchange.mailDnsRecords': [
        dnsRecord('contoso.example', { dmarc: ['v=DMARC1; p=none; rua=mailto:d@contoso.example'] }),
      ],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.statusReason).toContain('staged rollout');
    expect(result.affectedObjects[0]?.detail).toContain('p=none');
  });

  it('requires review when pct is below 100', () => {
    const result = run(m365DmarcPolicy, {
      'exchange.mailDnsRecords': [
        dnsRecord('contoso.example', {
          dmarc: ['v=DMARC1; p=reject; pct=25; rua=mailto:d@contoso.example'],
        }),
      ],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.detail).toContain('pct=25');
  });

  it('fails when DMARC is missing, duplicated or has an invalid policy', () => {
    const result = run(m365DmarcPolicy, {
      'exchange.mailDnsRecords': [
        dnsRecord('a.example', { dmarc: 'NotFound' }),
        dnsRecord('b.example', { dmarc: ['v=DMARC1; p=reject', 'v=DMARC1; p=none'] }),
        dnsRecord('c.example', { dmarc: ['v=DMARC1; p=block'] }),
        dnsRecord('d.example'),
      ],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.id)).toEqual([
      'a.example',
      'b.example',
      'c.example',
    ]);
  });

  it('applies the parent domain sp= policy to a subdomain without its own record', () => {
    const result = run(m365DmarcPolicy, {
      'exchange.mailDnsRecords': [
        dnsRecord('contoso.example', {
          dmarc: ['v=DMARC1; p=reject; sp=none; rua=mailto:d@contoso.example'],
        }),
        dnsRecord('sales.contoso.example', { dmarc: 'NotFound' }),
      ],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]).toMatchObject({ id: 'sales.contoso.example' });
    expect(result.affectedObjects[0]?.detail).toContain('inherited from contoso.example');
  });

  it('does not infer a passing policy from a parent without policy-discovery evidence', () => {
    const result = run(m365DmarcPolicy, {
      'exchange.mailDnsRecords': [
        dnsRecord('contoso.example'),
        dnsRecord('sales.contoso.example', { dmarc: 'NotFound' }),
      ],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.detail).toContain('RFC 9989');
  });

  it('notes domains without aggregate reporting', () => {
    const result = run(m365DmarcPolicy, {
      'exchange.mailDnsRecords': [dnsRecord('contoso.example', { dmarc: ['v=DMARC1; p=reject'] })],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('rua=');
  });

  it('is NOT_ASSESSED when only lookups failed', () => {
    const result = run(m365DmarcPolicy, {
      'exchange.mailDnsRecords': [dnsRecord('contoso.example', { dmarc: 'Error' })],
    });
    expect(result.status).toBe('NOT_ASSESSED');
  });

  it('is NOT_APPLICABLE without custom domains', () => {
    expect(run(m365DmarcPolicy, { 'exchange.mailDnsRecords': [] }).status).toBe('NOT_APPLICABLE');
  });
});
