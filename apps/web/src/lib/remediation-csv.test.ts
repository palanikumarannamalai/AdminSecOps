import { describe, expect, it } from 'vitest';
import { sampleResult } from '../test/sample-result';
import { remediationCsv } from './remediation-csv';

describe('remediation tracker export', () => {
  it('includes evidence gaps and review tasks but excludes passes and inapplicable checks', () => {
    const csv = remediationCsv(sampleResult);
    for (const row of sampleResult.results) {
      expect(csv.includes(`"${row.controlId}"`)).toBe(row.status !== 'PASS' && row.status !== 'NOT_APPLICABLE');
    }
    expect(csv).toContain('"Owner","Target date","Tracking status","Exception expiry","Verification evidence"');
  });
  it('neutralises spreadsheet formulas and quotes embedded commas, quotes and newlines', () => {
    const row = sampleResult.results[0]!;
    const csv = remediationCsv({ ...sampleResult, results: [{ ...row, status: 'REVIEW', title: ' \t=HYPERLINK("evil")', statusReason: 'one, "two"\nthree' }] });
    expect(csv).toContain("\"' \t=HYPERLINK(\"\"evil\"\")\"");
    expect(csv).toContain('"one, ""two""\nthree"');
    expect(csv).toContain('Validate evidence and document decision');
  });
});
