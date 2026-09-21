import { describe, expect, it } from 'vitest';
import { adUser, adUsers, CHILD_SID, CONTOSO, CONTOSO_SID, daysAgo, domainAdmins, nextSid, privilegedGroup } from '../../../test/builders/ad.js';
import { run } from '../../../test/run.js';
import { adForestAdminGroupsEmpty, adStalePrivilegedAccounts } from './privileged-accounts.js';

describe('AD-PRIV-002 stale privileged accounts', () => {
  it('passes when privileged accounts signed in recently', () => {
    const a = adUser({ lastLogonTimestamp: daysAgo(5) });
    expect(run(adStalePrivilegedAccounts, { 'ad.users': adUsers([a]), 'ad.privilegedGroups': [domainAdmins([a])] }).status).toBe('PASS');
  });

  it('fails for an admin without sign-in for more than 90 days', () => {
    const stale = adUser({ samAccountName: 'old-admin', lastLogonTimestamp: daysAgo(200) });
    const result = run(adStalePrivilegedAccounts, { 'ad.users': adUsers([stale]), 'ad.privilegedGroups': [domainAdmins([stale])] });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('200 days');
  });

  it('fails for an admin that never signed in and was created long ago, but not for a new one', () => {
    const never = adUser({ lastLogonTimestamp: null, whenCreated: daysAgo(365) });
    const fresh = adUser({ lastLogonTimestamp: null, whenCreated: daysAgo(10) });
    expect(run(adStalePrivilegedAccounts, { 'ad.users': adUsers([never]), 'ad.privilegedGroups': [domainAdmins([never])] }).status).toBe('FAIL');
    expect(run(adStalePrivilegedAccounts, { 'ad.users': adUsers([fresh]), 'ad.privilegedGroups': [domainAdmins([fresh])] }).status).toBe('PASS');
  });

  it('flags the built-in Administrator with an exception hint', () => {
    const builtIn = adUser({ samAccountName: 'Administrator', sid: `${CONTOSO_SID}-500`, lastLogonTimestamp: daysAgo(400) });
    const result = run(adStalePrivilegedAccounts, { 'ad.users': adUsers([builtIn]), 'ad.privilegedGroups': [domainAdmins([builtIn])] });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('emergency account');
  });

  it('ignores disabled accounts', () => {
    const disabled = adUser({ enabled: false, lastLogonTimestamp: daysAgo(999) });
    expect(run(adStalePrivilegedAccounts, { 'ad.users': adUsers([disabled]), 'ad.privilegedGroups': [domainAdmins([disabled])] }).status).toBe('PASS');
  });

  it('requires review when activity is unknown', () => {
    const unknown = adUser({ lastLogonTimestamp: null, whenCreated: null });
    expect(run(adStalePrivilegedAccounts, { 'ad.users': adUsers([unknown]), 'ad.privilegedGroups': [domainAdmins([unknown])] }).status).toBe('REVIEW');
  });
});

const EA = `${CONTOSO_SID}-519`;
const SA = `${CONTOSO_SID}-518`;
const ROOT_ADMIN = { samAccountName: 'Administrator', sid: `${CONTOSO_SID}-500` };

describe('AD-PRIV-003 Enterprise Admins and Schema Admins', () => {
  it('does not exempt the forest root Administrator from Schema Admins cleanup', () => {
    const result = run(adForestAdminGroupsEmpty, {
      'ad.privilegedGroups': [privilegedGroup('Enterprise Admins', EA, [ROOT_ADMIN]), privilegedGroup('Schema Admins', SA, [ROOT_ADMIN])],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(1);
    expect(result.affectedObjects[0]?.detail).toContain('Schema Admins');
    expect(result.affectedObjects[0]?.detail).not.toContain('different domain');
  });
  it('passes when both groups are empty or contain only the forest root Administrator', () => {
    const result = run(adForestAdminGroupsEmpty, {
      'ad.privilegedGroups': [privilegedGroup('Enterprise Admins', EA, [ROOT_ADMIN]), privilegedGroup('Schema Admins', SA, [])],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('built-in Administrator');
  });

  it('fails for standing members, including nested members', () => {
    const result = run(adForestAdminGroupsEmpty, {
      'ad.privilegedGroups': [
        privilegedGroup('Enterprise Admins', EA, [ROOT_ADMIN, { samAccountName: 'jsmith-admin', sid: nextSid() }]),
        privilegedGroup('Schema Admins', SA, [{ samAccountName: 'exchange-setup', sid: nextSid() }]),
      ],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(2);
  });

  it('treats the Administrator of a child domain as a standing member', () => {
    const result = run(adForestAdminGroupsEmpty, {
      'ad.privilegedGroups': [
        privilegedGroup('Enterprise Admins', EA, [{ samAccountName: 'Administrator', sid: `${CHILD_SID}-500` }]),
        privilegedGroup('Schema Admins', SA, []),
      ],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('different domain');
  });

  it('finds renamed groups by SID', () => {
    const result = run(adForestAdminGroupsEmpty, {
      'ad.privilegedGroups': [privilegedGroup('Unternehmens-Admins', EA, [{ samAccountName: 'x', sid: nextSid() }]), privilegedGroup('Schema-Admins', SA, [])],
    });
    expect(result.status).toBe('FAIL');
  });

  it('requires review when only one forest group was collected', () => {
    expect(run(adForestAdminGroupsEmpty, { 'ad.privilegedGroups': [privilegedGroup('Enterprise Admins', EA, [])] }).status).toBe('REVIEW');
  });

  it('is NOT_ASSESSED when neither group is present (child domain only)', () => {
    const result = run(adForestAdminGroupsEmpty, { 'ad.privilegedGroups': [domainAdmins([], CHILD_SID, CONTOSO)] });
    expect(result.status).toBe('NOT_ASSESSED');
  });
});
