import { describe, expect, it } from 'vitest';
import { sharePointSettings } from '../../../test/builders/m365.js';
import { run } from '../../../test/run.js';
import { m365SharePointAnyoneLinks, m365SharePointLegacyAuth } from './sharepoint.js';

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
