import { describe, expect, it } from 'vitest';
import { sharePointSettings } from '../../../test/builders/m365.js';
import { run } from '../../../test/run.js';
import {
  m365SharePointAnyoneLinks,
  m365SharePointGuestResharing,
  m365SharePointIdleSignOut,
  m365SharePointLegacyAuth,
} from './sharepoint.js';

describe('M365-SPO-003 guest resharing', () => {
  it('passes when guests cannot reshare', () => {
    expect(run(m365SharePointGuestResharing, { 'm365.sharePointSettings': sharePointSettings() }).status).toBe('PASS');
  });

  it('asks for review (not failure) when guests can reshare', () => {
    const result = run(m365SharePointGuestResharing, {
      'm365.sharePointSettings': sharePointSettings({ isResharingByExternalUsersEnabled: true }),
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.id).toBe('sharepoint.isResharingByExternalUsersEnabled');
  });

  it('does not apply when external sharing is off', () => {
    expect(
      run(m365SharePointGuestResharing, {
        'm365.sharePointSettings': sharePointSettings({ sharingCapability: 'Disabled', isResharingByExternalUsersEnabled: true }),
      }).status,
    ).toBe('NOT_APPLICABLE');
  });

  it('is NOT_ASSESSED when the value is missing (null is never off)', () => {
    expect(
      run(m365SharePointGuestResharing, {
        'm365.sharePointSettings': sharePointSettings({ isResharingByExternalUsersEnabled: null }),
      }).status,
    ).toBe('NOT_ASSESSED');
  });
});

describe('M365-SPO-004 idle session sign-out', () => {
  it('passes when idle sign-out is enabled and reports the times', () => {
    const result = run(m365SharePointIdleSignOut, {
      'm365.sharePointSettings': sharePointSettings({
        idleSessionSignOut: { isEnabled: true, warnAfterInSeconds: 2700, signOutAfterInSeconds: 3600 },
      }),
    });
    expect(result.status).toBe('PASS');
    expect(result.observed.facts).toContainEqual({ label: 'Sign out after (seconds)', value: 3600 });
  });

  it('asks for review when idle sign-out is off', () => {
    expect(
      run(m365SharePointIdleSignOut, {
        'm365.sharePointSettings': sharePointSettings({ idleSessionSignOut: { isEnabled: false } }),
      }).status,
    ).toBe('REVIEW');
  });

  it.each([undefined, null, { warnAfterInSeconds: 60 }])('is NOT_ASSESSED when the setting is %o', (idleSessionSignOut) => {
    expect(
      run(m365SharePointIdleSignOut, { 'm365.sharePointSettings': sharePointSettings({ idleSessionSignOut }) }).status,
    ).toBe('NOT_ASSESSED');
  });

  it('never passes on partial evidence', () => {
    const result = run(
      m365SharePointIdleSignOut,
      { 'm365.sharePointSettings': sharePointSettings({ idleSessionSignOut: { isEnabled: true } }) },
      { partial: ['m365.sharePointSettings'] },
    );
    expect(result.status).toBe('REVIEW');
  });
});

describe('M365-SPO-001 no Anyone links', () => {
  it.each(['disabled', 'existingExternalUserSharingOnly', 'externalUserSharingOnly'])(
    'passes for %s',
    (sharingCapability) => {
      expect(
        run(m365SharePointAnyoneLinks, {
          'm365.sharePointSettings': sharePointSettings({ sharingCapability }),
        }).status,
      ).toBe('PASS');
    },
  );

  it('fails when Anyone links are allowed (case-insensitive)', () => {
    const result = run(m365SharePointAnyoneLinks, {
      'm365.sharePointSettings': sharePointSettings({
        sharingCapability: 'ExternalUserAndGuestSharing',
      }),
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('Anyone');
  });

  it('notes the stricter SCuBA level and missing domain restrictions for new-guest sharing', () => {
    const result = run(m365SharePointAnyoneLinks, {
      'm365.sharePointSettings': sharePointSettings({
        sharingCapability: 'externalUserSharingOnly',
      }),
    });
    expect(result.notes.join(' ')).toContain('existing guests');
    expect(result.notes.join(' ')).toContain('not limited to allowed domains');
  });

  it('notes guest resharing when external sharing is on, but not when it is disabled', () => {
    const on = run(m365SharePointAnyoneLinks, {
      'm365.sharePointSettings': sharePointSettings({
        sharingCapability: 'existingExternalUserSharingOnly',
        isResharingByExternalUsersEnabled: true,
      }),
    });
    expect(on.status).toBe('PASS');
    expect(on.notes.join(' ')).toContain('Guests can share items they do not own');
    const off = run(m365SharePointAnyoneLinks, {
      'm365.sharePointSettings': sharePointSettings({
        sharingCapability: 'disabled',
        isResharingByExternalUsersEnabled: true,
      }),
    });
    expect(off.notes).toEqual([]);
  });

  it('requires review for an unrecognized value', () => {
    const result = run(m365SharePointAnyoneLinks, {
      'm365.sharePointSettings': sharePointSettings({ sharingCapability: 'unknownFutureValue' }),
    });
    expect(result.status).toBe('REVIEW');
  });
});

describe('M365-SPO-002 SharePoint legacy authentication', () => {
  it('passes when legacy protocols are disabled', () => {
    expect(
      run(m365SharePointLegacyAuth, { 'm365.sharePointSettings': sharePointSettings() }).status,
    ).toBe('PASS');
  });

  it('fails when legacy protocols are enabled', () => {
    expect(
      run(m365SharePointLegacyAuth, {
        'm365.sharePointSettings': sharePointSettings({ isLegacyAuthProtocolsEnabled: true }),
      }).status,
    ).toBe('FAIL');
  });

  it('is NOT_ASSESSED when Graph did not return the value (null is never PASS)', () => {
    const result = run(m365SharePointLegacyAuth, {
      'm365.sharePointSettings': sharePointSettings({ isLegacyAuthProtocolsEnabled: null }),
    });
    expect(result.status).toBe('NOT_ASSESSED');
  });
});
