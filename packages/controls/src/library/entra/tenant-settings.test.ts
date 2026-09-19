import { describe, expect, it } from 'vitest';
import { authorizationPolicy } from '../../../test/builders/entra.js';
import { run } from '../../../test/run.js';
import {
  GUEST_ROLE,
  entraGuestAccessRestricted,
  entraGuestInvitesRestricted,
  entraStaleGuests,
  entraUserConsentRestricted,
  entraUsersCannotCreateTenants,
  entraUsersCannotRegisterApps,
} from './tenant-settings.js';

const auth = (overrides: Record<string, unknown> = {}) => ({ 'entra.authorizationPolicy': authorizationPolicy(overrides) });

describe('ENTRA-APP-001 app registration', () => {
  it('passes when users cannot register apps and fails otherwise', () => {
    expect(run(entraUsersCannotRegisterApps, auth()).status).toBe('PASS');
    expect(run(entraUsersCannotRegisterApps, auth({ defaultUserRolePermissions: { allowedToCreateApps: true } })).status).toBe('FAIL');
  });
});

describe('ENTRA-APP-002 user consent', () => {
  const consent = (ids: string[]) => auth({ permissionGrantPolicyIdsAssignedToDefaultUserRole: ids });
  it('fails for the legacy policy', () => {
    expect(run(entraUserConsentRestricted, consent(['ManagePermissionGrantsForSelf.microsoft-user-default-legacy'])).status).toBe('FAIL');
  });
  it('passes for low-impact verified publisher consent and for no consent', () => {
    expect(run(entraUserConsentRestricted, consent(['ManagePermissionGrantsForSelf.microsoft-user-default-low'])).status).toBe('PASS');
    expect(run(entraUserConsentRestricted, consent([])).status).toBe('PASS');
    expect(run(entraUserConsentRestricted, consent(['ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team'])).status).toBe('PASS');
  });
  it('requires review for custom policies', () => {
    expect(run(entraUserConsentRestricted, consent(['ManagePermissionGrantsForSelf.contoso-custom'])).status).toBe('REVIEW');
  });
});

describe('ENTRA-EXT-001 guest access', () => {
  it('evaluates each documented guest role', () => {
    expect(run(entraGuestAccessRestricted, auth({ guestUserRoleId: GUEST_ROLE.sameAsMembers })).status).toBe('FAIL');
    expect(run(entraGuestAccessRestricted, auth({ guestUserRoleId: GUEST_ROLE.limited })).status).toBe('PASS');
    expect(run(entraGuestAccessRestricted, auth({ guestUserRoleId: GUEST_ROLE.restricted.toUpperCase() })).status).toBe('PASS');
    expect(run(entraGuestAccessRestricted, auth({ guestUserRoleId: '99999999-9999-4999-8999-999999999999' })).status).toBe('REVIEW');
  });
});

describe('ENTRA-EXT-002 guest invitations', () => {
  it('evaluates allowInvitesFrom values', () => {
    expect(run(entraGuestInvitesRestricted, auth({ allowInvitesFrom: 'everyone' })).status).toBe('FAIL');
    expect(run(entraGuestInvitesRestricted, auth({ allowInvitesFrom: 'adminsAndGuestInviters' })).status).toBe('PASS');
    expect(run(entraGuestInvitesRestricted, auth({ allowInvitesFrom: 'none' })).status).toBe('PASS');
    const members = run(entraGuestInvitesRestricted, auth({ allowInvitesFrom: 'adminsGuestInvitersAndAllMembers' }));
    expect(members.status).toBe('PASS');
    expect(members.notes.length).toBe(1);
    expect(run(entraGuestInvitesRestricted, auth({ allowInvitesFrom: 'somethingNew' })).status).toBe('REVIEW');
  });
});

describe('ENTRA-EXT-003 inactive guests', () => {
  const guest = (id: string, overrides: Record<string, unknown>) => ({ id, userPrincipalName: `${id}#EXT#@contoso.onmicrosoft.com`, accountEnabled: true, ...overrides });
  const assessedAt = '2026-09-01T00:00:00Z';

  it('fails for guests inactive beyond the threshold or never signed in', () => {
    const result = run(
      entraStaleGuests,
      {
        'entra.guestUsers': [
          guest('old', { lastSignInDateTime: '2026-01-01T00:00:00Z', createdDateTime: '2025-01-01T00:00:00Z' }),
          guest('never', { createdDateTime: '2026-01-01T00:00:00Z' }),
          guest('recent', { lastSignInDateTime: '2026-08-20T00:00:00Z' }),
          guest('noninteractive', { lastSignInDateTime: '2025-01-01T00:00:00Z', lastNonInteractiveSignInDateTime: '2026-08-30T00:00:00Z' }),
          guest('new', { createdDateTime: '2026-08-15T00:00:00Z' }),
          guest('disabled', { accountEnabled: false, createdDateTime: '2020-01-01T00:00:00Z' }),
        ],
      },
      { assessedAt },
    );
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.id).sort()).toEqual(['never', 'old']);
  });

  it('passes with only active guests', () => {
    expect(run(entraStaleGuests, { 'entra.guestUsers': [guest('a', { lastSignInDateTime: '2026-08-31T00:00:00Z' })] }, { assessedAt }).status).toBe('PASS');
  });

  it('downgrades PASS to REVIEW when sign-in activity was only partially collected', () => {
    expect(run(entraStaleGuests, { 'entra.guestUsers': [] }, { assessedAt, partial: ['entra.guestUsers'] }).status).toBe('REVIEW');
  });
});

describe('ENTRA-TEN-001 tenant creation', () => {
  it('evaluates true, false and missing values', () => {
    expect(run(entraUsersCannotCreateTenants, auth({ defaultUserRolePermissions: { allowedToCreateTenants: true } })).status).toBe('FAIL');
    expect(run(entraUsersCannotCreateTenants, auth()).status).toBe('PASS');
    expect(run(entraUsersCannotCreateTenants, auth({ defaultUserRolePermissions: { allowedToCreateTenants: null } })).status).toBe('REVIEW');
  });
});
