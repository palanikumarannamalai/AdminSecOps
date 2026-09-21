import { describe, expect, it } from 'vitest';
import { CHILD, CONTOSO, passwordPolicy } from '../../../test/builders/ad.js';
import { run } from '../../../test/run.js';
import { adPwdLockoutThreshold, adPwdMinimumLength, adPwdReversibleEncryption } from './password-policy.js';

describe('AD-PWD-001 minimum password length', () => {
  it('passes when every domain requires at least 15 characters', () => {
    const result = run(adPwdMinimumLength, { 'ad.passwordPolicies': [passwordPolicy(CONTOSO), passwordPolicy(CHILD, { minPasswordLength: 16 })] });
    expect(result.status).toBe('PASS');
  });

  it('fails and identifies the domain with a short default policy', () => {
    const result = run(adPwdMinimumLength, {
      'ad.passwordPolicies': [passwordPolicy(CONTOSO), passwordPolicy(CHILD, { minPasswordLength: 7 })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(1);
    expect(result.affectedObjects[0]?.name).toContain(CHILD);
    expect(result.affectedObjects[0]?.detail).toContain('7');
  });

  it('requires review when an applied PSO allows shorter passwords', () => {
    const result = run(adPwdMinimumLength, {
      'ad.passwordPolicies': [passwordPolicy(CONTOSO, {}, [{ name: 'ServiceAccounts', minPasswordLength: 8, appliesToCount: 3 }])],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.id).toBe(`${CONTOSO}\\ServiceAccounts`);
  });

  it('ignores PSOs that are not applied to anyone but notes them', () => {
    const result = run(adPwdMinimumLength, {
      'ad.passwordPolicies': [passwordPolicy(CONTOSO, {}, [{ name: 'Unused', minPasswordLength: 4, appliesToCount: 0 }])],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('Unused');
  });

  it('treats exactly the parameter value as compliant', () => {
    expect(run(adPwdMinimumLength, { 'ad.passwordPolicies': [passwordPolicy(CONTOSO, { minPasswordLength: 15 })] }).status).toBe('PASS');
    expect(run(adPwdMinimumLength, { 'ad.passwordPolicies': [passwordPolicy(CONTOSO, { minPasswordLength: 14 })] }).status).toBe('FAIL');
  });

  it('is NOT_ASSESSED when the dataset is empty', () => {
    expect(run(adPwdMinimumLength, { 'ad.passwordPolicies': [] }).status).toBe('NOT_ASSESSED');
  });

  it('is NOT_ASSESSED without evidence and NOT_APPLICABLE when AD was not in scope', () => {
    expect(run(adPwdMinimumLength, {}).status).toBe('NOT_ASSESSED');
    expect(run(adPwdMinimumLength, {}, { unavailable: { 'ad.passwordPolicies': 'NotApplicable' } }).status).toBe('NOT_APPLICABLE');
  });

  it('downgrades PASS to REVIEW on partial evidence', () => {
    const result = run(adPwdMinimumLength, { 'ad.passwordPolicies': [passwordPolicy(CONTOSO)] }, { partial: ['ad.passwordPolicies'] });
    expect(result.status).toBe('REVIEW');
  });
});

describe('AD-PWD-002 reversible encryption in password policies', () => {
  it('passes when disabled everywhere', () => {
    expect(run(adPwdReversibleEncryption, { 'ad.passwordPolicies': [passwordPolicy(CONTOSO), passwordPolicy(CHILD)] }).status).toBe('PASS');
  });

  it('fails when a default domain policy enables it', () => {
    const result = run(adPwdReversibleEncryption, {
      'ad.passwordPolicies': [passwordPolicy(CONTOSO), passwordPolicy(CHILD, { reversibleEncryptionEnabled: true })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.name).join()).toContain(CHILD);
  });

  it('fails when an applied PSO enables it', () => {
    const result = run(adPwdReversibleEncryption, {
      'ad.passwordPolicies': [passwordPolicy(CONTOSO, {}, [{ name: 'Radius', reversibleEncryptionEnabled: true, appliesToCount: 2 }])],
    });
    expect(result.status).toBe('FAIL');
  });

  it('requires review when only an unapplied PSO enables it', () => {
    const result = run(adPwdReversibleEncryption, {
      'ad.passwordPolicies': [passwordPolicy(CONTOSO, {}, [{ name: 'Old', reversibleEncryptionEnabled: true, appliesToCount: 0 }])],
    });
    expect(result.status).toBe('REVIEW');
  });

  it('is NOT_ASSESSED when collection failed', () => {
    expect(run(adPwdReversibleEncryption, {}, { unavailable: { 'ad.passwordPolicies': 'Failed' } }).status).toBe('NOT_ASSESSED');
  });
});

describe('AD-PWD-003 account lockout threshold', () => {
  it('passes with the baseline threshold of 10', () => {
    expect(run(adPwdLockoutThreshold, { 'ad.passwordPolicies': [passwordPolicy(CONTOSO, { lockoutThreshold: 10 })] }).status).toBe('PASS');
  });

  it('fails when lockout is disabled (0)', () => {
    const result = run(adPwdLockoutThreshold, { 'ad.passwordPolicies': [passwordPolicy(CONTOSO, { lockoutThreshold: 0 })] });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('lockout disabled');
  });

  it('requires review above 10 but at most 100', () => {
    expect(run(adPwdLockoutThreshold, { 'ad.passwordPolicies': [passwordPolicy(CONTOSO, { lockoutThreshold: 50 })] }).status).toBe('REVIEW');
    expect(run(adPwdLockoutThreshold, { 'ad.passwordPolicies': [passwordPolicy(CONTOSO, { lockoutThreshold: 100 })] }).status).toBe('REVIEW');
  });

  it('fails above the NIST ceiling of 100', () => {
    expect(run(adPwdLockoutThreshold, { 'ad.passwordPolicies': [passwordPolicy(CONTOSO, { lockoutThreshold: 101 })] }).status).toBe('FAIL');
  });

  it('evaluates every domain and fails on the worst', () => {
    const result = run(adPwdLockoutThreshold, {
      'ad.passwordPolicies': [passwordPolicy(CONTOSO, { lockoutThreshold: 20 }), passwordPolicy(CHILD, { lockoutThreshold: 0 })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(2);
  });

  it('requires review when an applied PSO disables lockout', () => {
    const result = run(adPwdLockoutThreshold, {
      'ad.passwordPolicies': [passwordPolicy(CONTOSO, {}, [{ name: 'NoLockout', lockoutThreshold: 0, appliesToCount: 1 }])],
    });
    expect(result.status).toBe('REVIEW');
  });

  it('ignores an unapplied PSO without lockout', () => {
    const result = run(adPwdLockoutThreshold, {
      'ad.passwordPolicies': [passwordPolicy(CONTOSO, {}, [{ name: 'NoLockout', lockoutThreshold: 0, appliesToCount: 0 }])],
    });
    expect(result.status).toBe('PASS');
  });
});
