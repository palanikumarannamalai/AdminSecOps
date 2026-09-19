import { describe, expect, it } from 'vitest';
import { sampleResult, sampleResults, summarize } from '../test/sample-result';
import { buildModuleCards, moduleForTechnology } from './modules';

describe('moduleForTechnology', () => {
  it('maps technologies to dashboard modules', () => {
    expect(moduleForTechnology('entra')).toBe('entra');
    expect(moduleForTechnology('hybrid')).toBe('entra');
    expect(moduleForTechnology('m365')).toBe('m365');
    expect(moduleForTechnology('azure')).toBe('azure');
    expect(moduleForTechnology('intune')).toBe('intune');
    expect(moduleForTechnology('ad')).toBe('ad');
    expect(moduleForTechnology('adcs')).toBe('ad');
    expect(moduleForTechnology('windows')).toBe('windows');
    expect(moduleForTechnology('gpo')).toBe('windows');
  });
});

describe('buildModuleCards', () => {
  const cards = buildModuleCards(sampleResult.summary);
  const card = (id: string) => {
    const found = cards.find((c) => c.id === id);
    if (found === undefined) throw new Error(id);
    return found;
  };

  it('returns the six modules in display order', () => {
    expect(cards.map((c) => c.label)).toEqual([
      'Microsoft 365',
      'Entra ID',
      'Azure',
      'Intune',
      'Active Directory',
      'Windows',
    ]);
  });

  it('adds hybrid results to Entra ID', () => {
    expect(card('entra').counts).toMatchObject({ PASS: 2, FAIL: 1, REVIEW: 1 });
    expect(card('entra').assessed).toBe(4);
    expect(card('entra').notCollected).toBe(false);
  });

  it('adds AD CS results to Active Directory', () => {
    expect(card('ad').counts.FAIL).toBe(2);
  });

  it('marks modules with nothing assessed as not collected', () => {
    expect(card('azure').notCollected).toBe(true);
    expect(card('azure').counts.NOT_ASSESSED).toBe(1);
    expect(card('intune').notCollected).toBe(true);
    // Windows only has a GPO control in ERROR: nothing assessed.
    expect(card('windows').notCollected).toBe(true);
    expect(card('windows').counts.ERROR).toBe(1);
  });

  it('treats an empty summary as not collected everywhere', () => {
    const empty = buildModuleCards(summarize([], []));
    expect(empty.every((c) => c.notCollected && c.total === 0)).toBe(true);
  });

  it('totals match the results', () => {
    expect(cards.reduce((sum, c) => sum + c.total, 0)).toBe(sampleResults.length);
  });
});
