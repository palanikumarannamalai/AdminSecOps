import { describe, expect, it } from 'vitest';
import { atpPolicy } from '../../../test/builders/m365.js';
import { run } from '../../../test/run.js';
import { m365SafeAttachmentsSpo } from './defender.js';

describe('M365-MDO-001 Safe Attachments for SharePoint, OneDrive and Teams', () => {
  it('passes when enabled', () => {
    expect(run(m365SafeAttachmentsSpo, { 'exchange.atpPolicy': atpPolicy() }).status).toBe('PASS');
  });

  it('fails when disabled', () => {
    expect(
      run(m365SafeAttachmentsSpo, {
        'exchange.atpPolicy': atpPolicy({ enableATPForSPOTeamsODB: false }),
      }).status,
    ).toBe('FAIL');
  });

  it('notes Safe Documents click-through', () => {
    const result = run(m365SafeAttachmentsSpo, {
      'exchange.atpPolicy': atpPolicy({ enableSafeDocs: true, allowSafeDocsOpen: true }),
    });
    expect(result.notes.join(' ')).toContain('Protected View');
  });

  it('is NOT_APPLICABLE without Defender for Office 365', () => {
    const result = run(
      m365SafeAttachmentsSpo,
      {},
      { unavailable: { 'exchange.atpPolicy': 'NotApplicable' } },
    );
    expect(result.status).toBe('NOT_APPLICABLE');
  });

  it('is NOT_ASSESSED when collection failed', () => {
    expect(
      run(m365SafeAttachmentsSpo, {}, { unavailable: { 'exchange.atpPolicy': 'Failed' } }).status,
    ).toBe('NOT_ASSESSED');
  });
});
