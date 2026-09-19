import { describe, expect, it } from 'vitest';
import {
  ALL_OBJECTS_GUID,
  daysSince,
  hostNamesMatch,
  normalizeAdRights,
  normalizeObjectType,
  publishedTemplateIndex,
  sidDomainPart,
  sidRid,
} from './ad-parsing.js';

describe('AD parsing helpers', () => {
  it('splits SIDs into domain part and RID', () => {
    expect(sidRid('S-1-5-21-1-2-3-500')).toBe('500');
    expect(sidDomainPart('s-1-5-21-1-2-3-500')).toBe('S-1-5-21-1-2-3');
    expect(sidDomainPart('S-1-5-32-544')).toBeNull();
  });

  it('matches short and fully qualified host names but not different FQDNs', () => {
    expect(hostNamesMatch('DC01', 'dc01.contoso.com')).toBe(true);
    expect(hostNamesMatch('dc01.contoso.com.', 'DC01.CONTOSO.COM')).toBe(true);
    expect(hostNamesMatch('dc01.contoso.com', 'dc01.fabrikam.com')).toBe(false);
  });

  it('computes whole days relative to a reference date', () => {
    const at = new Date('2026-09-01T12:00:00Z');
    expect(daysSince('2026-08-01T12:00:00Z', at)).toBe(31);
    expect(daysSince(null, at)).toBeNull();
    expect(daysSince('2026-09-10T12:00:00Z', at)).toBe(-9);
  });

  it('normalises rights and object types', () => {
    expect(normalizeAdRights(['ReadProperty, WriteProperty', 'GenericAll'])).toEqual(['readproperty', 'writeproperty', 'genericall']);
    expect(normalizeObjectType(null)).toBe(ALL_OBJECTS_GUID);
    expect(normalizeObjectType('{0E10C968-78FB-11D2-90D4-00C04F79DC55}')).toBe('0e10c968-78fb-11d2-90d4-00c04f79dc55');
  });

  it('indexes published templates case-insensitively', () => {
    const index = publishedTemplateIndex([
      { name: 'CA1', certificateTemplates: ['User', 'WebServer'] },
      { name: 'CA2', certificateTemplates: ['user'] },
    ]);
    expect(index.get('user')).toEqual(['CA1', 'CA2']);
    expect(index.get('webserver')).toEqual(['CA1']);
  });
});
