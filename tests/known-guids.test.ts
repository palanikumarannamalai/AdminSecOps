import { describe, expect, it } from 'vitest';
import {
  FICTIONAL_TEST_GUIDS,
  MICROSOFT_PUBLISHED_GUIDS,
  PROJECT_GUIDS,
  isListedGuid,
  isObviouslyFictionalGuid,
} from '../scripts/known-guids.js';

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

describe('secret-scan GUID allowlist', () => {
  it('accepts obviously fictional shapes', () => {
    for (const guid of [
      'aaaaaaaa-0000-4000-8000-000000000001',
      'AAAAAAAA-0000-4000-8000-000000000002',
      '11111111-2222-4333-8444-555555555555',
      'a1a1a1a1-0000-4000-8000-000000000001',
      'ffff0001-0000-4000-8000-000000000001',
    ]) {
      expect(isObviouslyFictionalGuid(guid), guid).toBe(true);
    }
  });

  it('rejects a GUID that looks random and is not listed', () => {
    // Made up for this test and assembled at runtime, so the literal never reaches the scan.
    const randomLooking = ['3b9e61d4', '72c8', '4f05', 'a1d3', '9c4e87b2f016'].join('-');
    expect(isObviouslyFictionalGuid(randomLooking)).toBe(false);
    expect(isListedGuid(randomLooking)).toBe(false);
  });

  it('lists only lowercase GUIDs, each with a label, and no duplicates across lists', () => {
    const lists = [
      Object.keys(MICROSOFT_PUBLISHED_GUIDS),
      Object.keys(PROJECT_GUIDS),
      Object.keys(FICTIONAL_TEST_GUIDS),
    ];
    const all = lists.flat();
    expect(all.every((guid) => GUID.test(guid))).toBe(true);
    expect(new Set(all).size).toBe(all.length);
    for (const entry of Object.values(MICROSOFT_PUBLISHED_GUIDS)) {
      expect(entry.name).not.toBe('');
      expect(entry.source).toMatch(/^https:\/\/learn\.microsoft\.com\//);
    }
  });
});
