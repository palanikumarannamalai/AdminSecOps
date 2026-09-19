import { describe, expect, it } from 'vitest';
import { organizationConfig } from '../../../test/builders/m365.js';
import { run } from '../../../test/run.js';
import { m365MailboxAuditing, m365UnifiedAuditLog } from './audit.js';

describe('M365-AUD-001 unified audit log ingestion', () => {
  it('passes when ingestion is enabled', () => {
    const result = run(m365UnifiedAuditLog, {
      'exchange.adminAuditLogConfig': { unifiedAuditLogIngestionEnabled: true },
    });
    expect(result.status).toBe('PASS');
    expect(result.evidence.map((e) => e.datasetId)).toEqual(['exchange.adminAuditLogConfig']);
  });

  it('fails when ingestion is disabled and explains the PowerShell caveat', () => {
    const result = run(m365UnifiedAuditLog, {
      'exchange.adminAuditLogConfig': { unifiedAuditLogIngestionEnabled: false },
    });
    expect(result.status).toBe('FAIL');
    expect(result.notes.join(' ')).toContain('Security & Compliance PowerShell');
  });

  it('is NOT_ASSESSED when the audit configuration was not collected', () => {
    expect(
      run(
        m365UnifiedAuditLog,
        {},
        { unavailable: { 'exchange.adminAuditLogConfig': 'Unauthorized' } },
      ).status,
    ).toBe('NOT_ASSESSED');
  });

  it('downgrades PASS to REVIEW on partial evidence', () => {
    const result = run(
      m365UnifiedAuditLog,
      { 'exchange.adminAuditLogConfig': { unifiedAuditLogIngestionEnabled: true } },
      { partial: ['exchange.adminAuditLogConfig'] },
    );
    expect(result.status).toBe('REVIEW');
  });
});

describe('M365-AUD-002 mailbox auditing on by default', () => {
  it('passes when AuditDisabled is false', () => {
    expect(
      run(m365MailboxAuditing, { 'exchange.organizationConfig': organizationConfig() }).status,
    ).toBe('PASS');
  });

  it('fails when AuditDisabled is true', () => {
    const result = run(m365MailboxAuditing, {
      'exchange.organizationConfig': organizationConfig({ auditDisabled: true }),
    });
    expect(result.status).toBe('FAIL');
    expect(result.observed.facts).toContainEqual({ label: 'AuditDisabled', value: true });
  });

  it('is NOT_ASSESSED without the organization configuration', () => {
    expect(run(m365MailboxAuditing, {}).status).toBe('NOT_ASSESSED');
  });
});
