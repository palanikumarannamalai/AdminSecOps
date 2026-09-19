import { describe, expect, it } from 'vitest';
import {
  adDomain,
  adUser,
  adUsers,
  CHILD,
  CHILD_SID,
  CONTOSO,
  CONTOSO_SID,
  daysAgo,
  domainAdmins,
  nextSid,
  privilegedGroup,
} from '../../../test/builders/ad.js';
import { run } from '../../../test/run.js';
import { adKrbPreauthDisabled, adKrbPrivilegedSpn, adKrbtgtPasswordAge, adKrbUserSpn } from './kerberos.js';

describe('AD-KRB-001 KRBTGT password age', () => {
  it('passes when every domain rotated within 180 days', () => {
    const result = run(adKrbtgtPasswordAge, {
      'ad.krbtgt': [
        { domain: CONTOSO, pwdLastSet: daysAgo(30) },
        { domain: CHILD, pwdLastSet: daysAgo(180) },
      ],
    });
    expect(result.status).toBe('PASS');
  });

  it('fails for the domain whose KRBTGT password is older than 180 days', () => {
    const result = run(adKrbtgtPasswordAge, {
      'ad.krbtgt': [
        { domain: CONTOSO, pwdLastSet: daysAgo(30) },
        { domain: CHILD, pwdLastSet: daysAgo(900) },
      ],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(1);
    expect(result.affectedObjects[0]?.name).toBe(`${CHILD}\\krbtgt`);
  });

  it('requires review when pwdLastSet is unknown (never PASS)', () => {
    const result = run(adKrbtgtPasswordAge, { 'ad.krbtgt': [{ domain: CONTOSO, pwdLastSet: null }] });
    expect(result.status).toBe('REVIEW');
  });

  it('requires review when a collected domain has no KRBTGT entry', () => {
    const result = run(adKrbtgtPasswordAge, {
      'ad.krbtgt': [{ domain: CONTOSO, pwdLastSet: daysAgo(10) }],
      'ad.domains': [adDomain(CONTOSO), adDomain(CHILD)],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.id).toBe(CHILD);
  });

  it('matches domains by NetBIOS name case-insensitively', () => {
    const result = run(adKrbtgtPasswordAge, {
      'ad.krbtgt': [{ domain: 'CONTOSO', pwdLastSet: daysAgo(10) }],
      'ad.domains': [adDomain(CONTOSO)],
    });
    expect(result.status).toBe('PASS');
  });

  it('is NOT_ASSESSED for an empty dataset', () => {
    expect(run(adKrbtgtPasswordAge, { 'ad.krbtgt': [] }).status).toBe('NOT_ASSESSED');
  });
});

describe('AD-KRB-002 Kerberos pre-authentication', () => {
  it('passes when no account disables pre-authentication', () => {
    expect(run(adKrbPreauthDisabled, { 'ad.users': adUsers([adUser(), adUser()]) }).status).toBe('PASS');
  });

  it('fails for enabled accounts and highlights privileged ones', () => {
    const admin = adUser({ samAccountName: 'adm1', doesNotRequirePreAuth: true });
    const user = adUser({ samAccountName: 'legacy', domain: CHILD, sid: nextSid(CHILD_SID), doesNotRequirePreAuth: true });
    const result = run(adKrbPreauthDisabled, {
      'ad.users': adUsers([admin, user], [CONTOSO, CHILD]),
      'ad.privilegedGroups': [domainAdmins([admin])],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(2);
    const adminObject = result.affectedObjects.find((o) => o.name === `${CONTOSO}\\adm1`);
    expect(adminObject?.detail).toContain('PRIVILEGED');
    expect(result.affectedObjects.some((o) => o.name === `${CHILD}\\legacy`)).toBe(true);
  });

  it('ignores disabled accounts but notes them', () => {
    const result = run(adKrbPreauthDisabled, { 'ad.users': adUsers([adUser({ enabled: false, doesNotRequirePreAuth: true })]) });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('disabled account');
  });

  it('still evaluates without the optional privileged group evidence', () => {
    const result = run(adKrbPreauthDisabled, { 'ad.users': adUsers([adUser({ doesNotRequirePreAuth: true })]) });
    expect(result.status).toBe('FAIL');
    expect(result.notes.join(' ')).toContain('not highlighted');
  });
});

describe('AD-KRB-003 privileged accounts with SPNs', () => {
  it('passes when privileged accounts have no SPNs', () => {
    const admin = adUser({ adminCount: true });
    const svc = adUser({ servicePrincipalNameCount: 2 });
    expect(run(adKrbPrivilegedSpn, { 'ad.users': adUsers([admin, svc]), 'ad.privilegedGroups': [domainAdmins([admin])] }).status).toBe('PASS');
  });

  it('fails for an enabled privileged account with an SPN', () => {
    const admin = adUser({ samAccountName: 'svc-sql-admin', servicePrincipalNameCount: 1, adminCount: true, passwordNeverExpires: true, pwdLastSet: daysAgo(2000) });
    const result = run(adKrbPrivilegedSpn, { 'ad.users': adUsers([admin]), 'ad.privilegedGroups': [domainAdmins([admin])] });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('Domain Admins');
    expect(result.affectedObjects[0]?.detail).toContain('2000 days');
  });

  it('detects privilege through builtin groups and SIDs of another domain', () => {
    const childAdmin = adUser({ domain: CHILD, sid: nextSid(CHILD_SID), servicePrincipalNameCount: 1 });
    const result = run(adKrbPrivilegedSpn, {
      'ad.users': adUsers([childAdmin], [CHILD]),
      'ad.privilegedGroups': [
        privilegedGroup('Backup Operators', 'S-1-5-32-551', [{ samAccountName: childAdmin.samAccountName as string, sid: (childAdmin.sid as string).toLowerCase() }], CHILD),
      ],
    });
    expect(result.status).toBe('FAIL');
  });

  it('ignores disabled privileged accounts and the KRBTGT account', () => {
    const disabled = adUser({ enabled: false, servicePrincipalNameCount: 1 });
    const krbtgt = adUser({ samAccountName: 'krbtgt', sid: `${CONTOSO_SID}-502`, servicePrincipalNameCount: 1 });
    const result = run(adKrbPrivilegedSpn, {
      'ad.users': adUsers([disabled, krbtgt]),
      'ad.privilegedGroups': [domainAdmins([disabled, krbtgt])],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('disabled');
  });

  it('notes adminCount accounts that are no longer privileged', () => {
    const former = adUser({ adminCount: true, servicePrincipalNameCount: 1 });
    const result = run(adKrbPrivilegedSpn, { 'ad.users': adUsers([former]), 'ad.privilegedGroups': [domainAdmins([])] });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('adminCount=1');
  });

  it('is NOT_ASSESSED when privileged group evidence is missing', () => {
    expect(run(adKrbPrivilegedSpn, { 'ad.users': adUsers([]) }).status).toBe('NOT_ASSESSED');
  });
});

describe('AD-KRB-004 user-based service accounts', () => {
  it('passes when no non-privileged user has an SPN', () => {
    expect(run(adKrbUserSpn, { 'ad.users': adUsers([adUser()]), 'ad.privilegedGroups': [] }).status).toBe('PASS');
  });

  it('requires review for enabled user accounts with SPNs, oldest password first', () => {
    const recent = adUser({ samAccountName: 'svc-new', servicePrincipalNameCount: 1, pwdLastSet: daysAgo(10) });
    const old = adUser({ samAccountName: 'svc-old', servicePrincipalNameCount: 3, pwdLastSet: daysAgo(3000), passwordNeverExpires: true });
    const result = run(adKrbUserSpn, { 'ad.users': adUsers([recent, old]), 'ad.privilegedGroups': [] });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.name).toBe(`${CONTOSO}\\svc-old`);
    expect(result.affectedObjects[0]?.detail).toContain('never expires');
  });

  it('excludes privileged accounts (covered by AD-KRB-003), disabled accounts and KRBTGT', () => {
    const admin = adUser({ servicePrincipalNameCount: 1 });
    const disabled = adUser({ enabled: false, servicePrincipalNameCount: 1 });
    const rodcKrbtgt = adUser({ samAccountName: 'krbtgt_12345', servicePrincipalNameCount: 1 });
    const result = run(adKrbUserSpn, { 'ad.users': adUsers([admin, disabled, rodcKrbtgt]), 'ad.privilegedGroups': [domainAdmins([admin])] });
    expect(result.status).toBe('PASS');
  });
});
