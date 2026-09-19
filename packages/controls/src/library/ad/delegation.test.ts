import { describe, expect, it } from 'vitest';
import { adComputer, adUser, adUsers, CHILD, CHILD_SID, CONTOSO, domainAdmins, nextSid, privilegedGroup } from '../../../test/builders/ad.js';
import { run } from '../../../test/run.js';
import { adPrivilegedNotDelegated, adUnconstrainedDelegation } from './delegation.js';

describe('AD-DEL-001 unconstrained delegation', () => {
  it('passes when only domain controllers are trusted for delegation', () => {
    const result = run(adUnconstrainedDelegation, {
      'ad.computers': [adComputer({ name: 'DC01', isDomainController: true, trustedForDelegation: true }), adComputer()],
      'ad.users': adUsers([adUser()]),
    });
    expect(result.status).toBe('PASS');
  });

  it('fails for a member server and a user account with unconstrained delegation', () => {
    const result = run(adUnconstrainedDelegation, {
      'ad.computers': [adComputer({ name: 'APP01', domain: CHILD, trustedForDelegation: true, operatingSystem: 'Windows Server 2019 Standard' })],
      'ad.users': adUsers([adUser({ samAccountName: 'svc-web', trustedForDelegation: true })]),
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(2);
    expect(result.affectedObjects.map((o) => o.id)).toContain(`${CHILD}\\APP01`);
  });

  it('ignores disabled accounts but notes them', () => {
    const result = run(adUnconstrainedDelegation, {
      'ad.computers': [adComputer({ enabled: false, trustedForDelegation: true })],
      'ad.users': adUsers([adUser({ enabled: false, trustedForDelegation: true })]),
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('disabled computer');
    expect(result.notes.join(' ')).toContain('disabled account');
  });

  it('notes protocol transition without failing', () => {
    const result = run(adUnconstrainedDelegation, {
      'ad.computers': [adComputer({ trustedToAuthForDelegation: true })],
      'ad.users': adUsers([]),
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('protocol transition');
  });

  it('is NOT_ASSESSED when user evidence is missing', () => {
    expect(run(adUnconstrainedDelegation, { 'ad.computers': [] }).status).toBe('NOT_ASSESSED');
  });
});

describe('AD-PRIV-001 privileged accounts protected from delegation', () => {
  it('passes when admins are sensitive or in Protected Users', () => {
    const a = adUser({ accountNotDelegated: true });
    const b = adUser({ memberOfProtectedUsers: true });
    const result = run(adPrivilegedNotDelegated, { 'ad.users': adUsers([a, b]), 'ad.privilegedGroups': [domainAdmins([a, b])] });
    expect(result.status).toBe('PASS');
  });

  it('fails for an unprotected enabled admin in a child domain', () => {
    const childAdmin = adUser({ domain: CHILD, sid: nextSid(CHILD_SID), samAccountName: 'adm-emea' });
    const result = run(adPrivilegedNotDelegated, {
      'ad.users': adUsers([childAdmin], [CHILD]),
      'ad.privilegedGroups': [domainAdmins([childAdmin], CHILD_SID, CHILD)],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.name).toBe(`${CHILD}\\adm-emea`);
  });

  it('skips disabled admins and non-user members', () => {
    const disabled = adUser({ enabled: false });
    const result = run(adPrivilegedNotDelegated, {
      'ad.users': adUsers([disabled]),
      'ad.privilegedGroups': [
        domainAdmins([disabled]),
        privilegedGroup('Administrators', 'S-1-5-32-544', [{ samAccountName: 'SRV01$', sid: nextSid(), objectClass: 'computer' }]),
      ],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('computers or managed service accounts');
  });

  it('requires review when a privileged member is missing from user evidence', () => {
    const result = run(adPrivilegedNotDelegated, {
      'ad.users': adUsers([]),
      'ad.privilegedGroups': [privilegedGroup('Domain Admins', 'S-1-5-21-1111111111-2222222222-3333333333-512', [{ samAccountName: 'ghost', sid: nextSid() }])],
    });
    expect(result.status).toBe('REVIEW');
  });

  it('downgrades PASS on partial privileged group evidence', () => {
    const a = adUser({ accountNotDelegated: true });
    const result = run(
      adPrivilegedNotDelegated,
      { 'ad.users': adUsers([a]), 'ad.privilegedGroups': [domainAdmins([a])] },
      { partial: ['ad.privilegedGroups'] },
    );
    expect(result.status).toBe('REVIEW');
    expect(result.notes.join(' ')).toContain('partial');
  });

  it('matches member SIDs case-insensitively', () => {
    const a = adUser({ accountNotDelegated: false });
    const result = run(adPrivilegedNotDelegated, {
      'ad.users': adUsers([a]),
      'ad.privilegedGroups': [privilegedGroup('Domain Admins', 'S-1-5-21-1111111111-2222222222-3333333333-512', [{ samAccountName: 'x', sid: (a.sid as string).toLowerCase() }], CONTOSO)],
    });
    expect(result.status).toBe('FAIL');
  });
});
