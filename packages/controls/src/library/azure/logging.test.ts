import { describe, expect, it } from 'vitest';
import { diagnosticSetting, SUB_A, SUB_B, subscription } from '../../../test/builders/azure.js';
import { run } from '../../../test/run.js';
import { azActivityLogExport } from './logging.js';

const entry = (subscriptionId: string, settings: Record<string, unknown>[]) => ({ subscriptionId, settings });

describe('AZ-LOG-001 activity log export', () => {
  it('passes when each subscription exports Administrative and Security', () => {
    const result = run(azActivityLogExport, {
      'azure.activityLogDiagnostics': [entry(SUB_A, [diagnosticSetting()]), entry(SUB_B, [diagnosticSetting({ workspaceConfigured: false, storageAccountConfigured: true })])],
    });
    expect(result.status).toBe('PASS');
  });

  it('accepts required categories spread over several settings and matches case-insensitively', () => {
    const result = run(azActivityLogExport, {
      'azure.activityLogDiagnostics': [
        entry(SUB_A, [diagnosticSetting({ name: 'a', enabledCategories: ['administrative'] }), diagnosticSetting({ name: 'b', enabledCategories: ['SECURITY'] })]),
      ],
    });
    expect(result.status).toBe('PASS');
  });

  it('fails when a subscription has no diagnostic setting', () => {
    const result = run(azActivityLogExport, {
      'azure.activityLogDiagnostics': [entry(SUB_A, [diagnosticSetting()]), entry(SUB_B, [])],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.id)).toEqual([`/subscriptions/${SUB_B}`]);
  });

  it('fails when the Security category is not exported', () => {
    const result = run(azActivityLogExport, {
      'azure.activityLogDiagnostics': [entry(SUB_A, [diagnosticSetting({ enabledCategories: ['Administrative', 'Policy'] })])],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('Security');
  });

  it('fails when settings have no destination', () => {
    const result = run(azActivityLogExport, {
      'azure.activityLogDiagnostics': [entry(SUB_A, [diagnosticSetting({ workspaceConfigured: false })])],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('destination');
  });

  it('requires review for subscriptions missing from the evidence', () => {
    const result = run(azActivityLogExport, {
      'azure.activityLogDiagnostics': [entry(SUB_A, [diagnosticSetting()])],
      'azure.subscriptions': [subscription(SUB_A), subscription(SUB_B)],
    });
    expect(result.status).toBe('REVIEW');
  });

  it('is NOT_ASSESSED when diagnostics were not collected', () => {
    expect(run(azActivityLogExport, {}, { unavailable: { 'azure.activityLogDiagnostics': 'Unauthorized' } }).status).toBe('NOT_ASSESSED');
  });
});
