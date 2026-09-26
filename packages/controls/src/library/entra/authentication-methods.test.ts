import { describe, expect, it } from 'vitest';
import { run } from '../../../test/run.js';
import { entraMembersRegisteredForMfa, entraWeakMethodsDisabled } from './authentication-methods.js';

const user = (id: string, registered: boolean, userType = 'member') => ({ id, userPrincipalName: `${id}@contoso.example`, userType, isMfaRegistered: registered, methodsRegistered: [] });

describe('ENTRA-AUTH-001 member MFA registration', () => {
  it('passes when all members are registered (guests ignored)', () => {
    const result = run(entraMembersRegisteredForMfa, { 'entra.userRegistrationDetails': [user('a', true), user('g', false, 'guest')] });
    expect(result.status).toBe('PASS');
  });

  it('fails and lists unregistered members', () => {
    const result = run(entraMembersRegisteredForMfa, { 'entra.userRegistrationDetails': [user('a', true), user('b', false, 'Member')] });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.id)).toEqual(['b']);
    expect(result.observed.facts.find((f) => f.label === 'Unregistered (%)')?.value).toBe(50);
  });

  it('reviews an empty report rather than claiming member coverage', () => {
    expect(run(entraMembersRegisteredForMfa, { 'entra.userRegistrationDetails': [] }).status).toBe('REVIEW');
  });
});

describe('ENTRA-AUTH-002 SMS and voice', () => {
  const policy = (sms: string, voice: string) => ({
    'entra.authenticationMethodsPolicy': {
      policyMigrationState: 'migrationComplete',
      authenticationMethodConfigurations: [
        { id: 'Sms', state: sms, includeTargets: [{ targetType: 'group', id: 'all_users' }] },
        { id: 'Voice', state: voice, includeTargets: [] },
        { id: 'Fido2', state: 'enabled', includeTargets: [] },
      ],
    },
  });

  it('passes when both are disabled', () => {
    expect(run(entraWeakMethodsDisabled, policy('disabled', 'disabled')).status).toBe('PASS');
  });

  it('requires review when SMS is enabled', () => {
    const result = run(entraWeakMethodsDisabled, policy('enabled', 'disabled'));
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.detail).toContain('all users');
  });

  it('reviews when method settings and migration status are absent', () => {
    const result = run(entraWeakMethodsDisabled, { 'entra.authenticationMethodsPolicy': { authenticationMethodConfigurations: [] } });
    expect(result.status).toBe('REVIEW');
  });
});
