import { describe, expect, it } from 'vitest';
import { sharePointSettings } from '../../../test/builders/m365.js';
import { run } from '../../../test/run.js';
import { m365SharePointDomainRestrictions as domains, m365SharePointInvitationIdentity as identity } from './sharepoint-governance.js';

const data = (overrides: Record<string, unknown> = {}) => ({ 'm365.sharePointSettings': sharePointSettings(overrides) });
describe('M365-SPO-005 and M365-SPO-006 governance checks', () => {
  it.each([identity, domains])('keeps missing or partial evidence honest for $metadata.id', control => {
    expect(run(control, {}).status).toBe('NOT_ASSESSED');
    const complete = data({ isRequireAcceptingUserToMatchInvitedUserEnabled: true, sharingDomainRestrictionMode: 'allowList', sharingAllowedDomainList: ['partner.example'] });
    expect(run(control, complete, { partial: ['m365.sharePointSettings'] }).status).toBe('REVIEW');
    expect(run(control, data({ sharingCapability: 'Disabled' })).status).toBe('NOT_APPLICABLE');
    expect(run(control, { ...complete, 'm365.sharePointSettings': sharePointSettings({ sharingCapability: 'unknownFutureValue', isRequireAcceptingUserToMatchInvitedUserEnabled: true, sharingDomainRestrictionMode: 'allowList', sharingAllowedDomainList: ['partner.example'] }) }).status).toBe('REVIEW');
  });
  it.each([[true, 'PASS'], [false, 'REVIEW'], [null, 'NOT_ASSESSED'], [undefined, 'NOT_ASSESSED']])('handles invitation flag %s without assuming B2B behavior', (value, status) => {
    const r = run(identity, data({ isRequireAcceptingUserToMatchInvitedUserEnabled: value }));
    expect(r.status).toBe(status);
    if (value === null || value === undefined) expect(r.statusReason).toContain('did not return');
    if (value === false) expect(r.statusReason).toContain('B2B');
  });
  it.each(['allowList', 'blockList'])('checks the corresponding %s list', mode => {
    const key = mode === 'allowList' ? 'sharingAllowedDomainList' : 'sharingBlockedDomainList';
    expect(run(domains, data({ sharingDomainRestrictionMode: mode, [key]: ['Partner.Example'] })).status).toBe('PASS');
    expect(run(domains, data({ sharingDomainRestrictionMode: mode, [key]: null })).status).toBe('NOT_ASSESSED');
    expect(run(domains, data({ sharingDomainRestrictionMode: mode, [key]: [] })).status).toBe('REVIEW');
  });
  it.each(['*.example.com', 'https://partner.example', 'partner..example', '-partner.example'])('rejects invalid domain entry %s', domain => {
    expect(run(domains, data({ sharingDomainRestrictionMode: 'allowList', sharingAllowedDomainList: [domain] })).status).toBe('REVIEW');
  });
  it('does not infer restrictions from stale lists or treat unknown as none', () => {
    expect(run(domains, data({ sharingDomainRestrictionMode: 'none', sharingAllowedDomainList: ['partner.example'] })).status).toBe('REVIEW');
    expect(run(domains, data({ sharingDomainRestrictionMode: 'unknownFutureValue' })).status).toBe('REVIEW');
    expect(run(domains, data({ sharingDomainRestrictionMode: null })).status).toBe('NOT_ASSESSED');
  });
});
