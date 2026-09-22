import { describe, expect, it } from 'vitest';
import { run } from '../../../test/run.js';
import { m365TeamsGuestChannelManagement, m365TeamsPersonalScopeRsc } from './teams.js';

function team(id: string, guestSettings: Record<string, unknown> | null) {
  return {
    id,
    displayName: `Team ${id}`,
    visibility: 'private',
    isArchived: false,
    memberSettings: null,
    guestSettings,
  };
}

describe('M365-TMS-001 personal-scope resource-specific consent', () => {
  it('passes when personal-scope RSC apps are blocked', () => {
    const result = run(m365TeamsPersonalScopeRsc, {
      'm365.teamsAppSettings': { allowUserRequestsForAppAccess: false, isUserPersonalScopeResourceSpecificConsentEnabled: false },
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('not readable');
  });

  it('asks for review when users can grant RSC in the personal scope', () => {
    const result = run(m365TeamsPersonalScopeRsc, {
      'm365.teamsAppSettings': { allowUserRequestsForAppAccess: true, isUserPersonalScopeResourceSpecificConsentEnabled: true },
    });
    expect(result.status).toBe('REVIEW');
    expect(result.severity).toBe('low');
  });

  it('is NOT_ASSESSED when the value is missing', () => {
    expect(run(m365TeamsPersonalScopeRsc, { 'm365.teamsAppSettings': {} }).status).toBe('NOT_ASSESSED');
  });
});

describe('M365-TMS-002 guest channel management', () => {
  const off = { allowCreateUpdateChannels: false, allowDeleteChannels: false };

  it('passes when no team read lets guests manage channels', () => {
    expect(
      run(m365TeamsGuestChannelManagement, { 'm365.teamsTeamSettings': [team('a', off), team('b', off)] }).status,
    ).toBe('PASS');
  });

  it('lists teams where guests can manage channels for review', () => {
    const result = run(m365TeamsGuestChannelManagement, {
      'm365.teamsTeamSettings': [team('a', off), team('b', { allowCreateUpdateChannels: true, allowDeleteChannels: false })],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects.map((o) => o.id)).toEqual(['b']);
  });

  it('treats unknown guest settings as unknown, never as restricted', () => {
    const result = run(m365TeamsGuestChannelManagement, {
      'm365.teamsTeamSettings': [team('a', off), team('c', null), team('d', { allowCreateUpdateChannels: false })],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects.map((o) => o.id)).toEqual(['c', 'd']);
  });

  it('downgrades PASS to REVIEW when not every team could be read', () => {
    const result = run(
      m365TeamsGuestChannelManagement,
      { 'm365.teamsTeamSettings': [team('a', off)] },
      { partial: ['m365.teamsTeamSettings'] },
    );
    expect(result.status).toBe('REVIEW');
  });

  it('does not apply when the tenant has no teams', () => {
    expect(run(m365TeamsGuestChannelManagement, { 'm365.teamsTeamSettings': [] }).status).toBe('NOT_APPLICABLE');
  });
});
