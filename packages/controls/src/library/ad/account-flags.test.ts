import { describe, expect, it } from 'vitest';
import { adUser, adUsers, CHILD, CHILD_SID, CONTOSO, domainAdmins, nextSid } from '../../../test/builders/ad.js';
import { run } from '../../../test/run.js';
import { adAccountReversibleEncryption, adPasswordNotRequired } from './account-flags.js';

describe('AD-ACC-001 PASSWD_NOTREQD', () => {
  it('passes when no enabled account has the flag', () => {
    expect(run(adPasswordNotRequired, { 'ad.users': adUsers([adUser()]) }).status).toBe('PASS');
  });

  it('fails for enabled accounts across domains and highlights privileged ones', () => {
    const admin = adUser({ samAccountName: 'adm', passwordNotRequired: true });
    const child = adUser({ domain: CHILD, sid: nextSid(CHILD_SID), passwordNotRequired: true });
    const result = run(adPasswordNotRequired, { 'ad.users': adUsers([admin, child], [CONTOSO, CHILD]), 'ad.privilegedGroups': [domainAdmins([admin])] });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(2);
    expect(result.affectedObjects.find((o) => o.name === `${CONTOSO}\\adm`)?.detail).toContain('PRIVILEGED');
  });

  it('ignores disabled accounts', () => {
    const result = run(adPasswordNotRequired, { 'ad.users': adUsers([adUser({ enabled: false, passwordNotRequired: true })]) });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('PASSWD_NOTREQD');
  });

  it('is NOT_ASSESSED without user evidence', () => {
    expect(run(adPasswordNotRequired, {}, { unavailable: { 'ad.users': 'Unauthorized' } }).status).toBe('NOT_ASSESSED');
  });
});

describe('AD-ACC-002 per-account reversible encryption', () => {
  it('passes when no account stores a reversible password', () => {
    expect(run(adAccountReversibleEncryption, { 'ad.users': adUsers([adUser()]) }).status).toBe('PASS');
  });

  it('fails for enabled and disabled accounts', () => {
    const result = run(adAccountReversibleEncryption, {
      'ad.users': adUsers([adUser({ allowReversiblePasswordEncryption: true }), adUser({ enabled: false, allowReversiblePasswordEncryption: true })]),
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(2);
    expect(result.affectedObjects.map((o) => o.detail).join(' ')).toContain('Disabled account');
  });

  it('keeps FAIL even with partial evidence', () => {
    const result = run(adAccountReversibleEncryption, { 'ad.users': adUsers([adUser({ allowReversiblePasswordEncryption: true })]) }, { partial: ['ad.users'] });
    expect(result.status).toBe('FAIL');
  });
});
