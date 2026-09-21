import { describe, expect, it } from 'vitest';
import { CONTROL_LIBRARY } from '@adminsecops/controls';
import { buildEvidencePackage, loadEvidenceBundle } from '@adminsecops/evidence';
import { runAssessment } from '@adminsecops/engine';
import type { AssessmentResult } from '@adminsecops/schemas';
import { envelope, manifestBase } from '../../evidence/test/sample.js';
import { escapeHtml, html, link, safeUrl } from './html-builder.js';
import { renderHtmlReport } from './html-report.js';
import { buildJsonReport, reportFileName, serializeJsonReport } from './json-report.js';

const XSS = '<script>alert(1)</script><img src=x onerror=alert(2)>';

function sampleResult(): AssessmentResult {
  const { files } = buildEvidencePackage({ ...manifestBase(), environment: { ...manifestBase().environment, label: `Contoso ${XSS}` } }, [
    { path: 'evidence/entra/securityDefaults.json', envelope: envelope('entra.securityDefaults', { isEnabled: false }) },
    {
      path: 'evidence/entra/conditionalAccessPolicies.json',
      envelope: envelope('entra.conditionalAccessPolicies', [
        {
          id: '11111111-1111-4111-8111-111111111111',
          displayName: `Report only ${XSS}`,
          state: 'enabledForReportingButNotEnforced',
          conditions: { users: { includeUsers: ['All'] }, applications: { includeApplications: ['All'] }, clientAppTypes: ['all'] },
          grantControls: { operator: 'OR', builtInControls: ['mfa'] },
        },
      ]),
    },
    {
      path: 'evidence/entra/authorizationPolicy.json',
      envelope: envelope('entra.authorizationPolicy', {
        allowInvitesFrom: 'everyone',
        guestUserRoleId: 'a0b1b346-4d3e-4e8b-98f8-753987be4970',
        permissionGrantPolicyIdsAssignedToDefaultUserRole: ['ManagePermissionGrantsForSelf.microsoft-user-default-legacy'],
        defaultUserRolePermissions: { allowedToCreateApps: true, allowedToCreateSecurityGroups: true, allowedToReadOtherUsers: true, allowedToCreateTenants: true },
      }),
    },
  ]);
  return runAssessment(loadEvidenceBundle(files), CONTROL_LIBRARY, { processedAt: new Date('2026-09-02T00:00:00Z') });
}

describe('html builder', () => {
  it('escapes interpolated values', () => {
    expect(html`<p>${XSS}</p>`.value).not.toContain('<script>');
    expect(escapeHtml(`"'\`&`)).toBe('&quot;&#39;&#96;&amp;');
  });

  it('only links https URLs', () => {
    expect(safeUrl('javascript:alert(1)')).toBeUndefined();
    expect(safeUrl('http://example.com')).toBeUndefined();
    expect(link('javascript:alert(1)', 'x').value).not.toContain('href');
    expect(link('https://learn.microsoft.com/a"b', 'x').value).toContain('href="https://learn.microsoft.com/a%22b"');
  });
});

describe('HTML report', () => {
  const result = sampleResult();
  const report = renderHtmlReport(result, { generatedAt: new Date('2026-09-02T00:00:00Z') });

  it('labels review findings as requiring verification', () => {
    expect(report).toContain('Potential impact if confirmed:');
    expect(report).toContain('This does not establish a confirmed security gap.');
  });

  it('never emits evidence-supplied markup', () => {
    expect(report).not.toContain('<script');
    expect(report).not.toContain('<img src=x');
    expect(report).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('declares a restrictive content security policy without scripts', () => {
    expect(report).toMatch(/Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;sha256-[A-Za-z0-9+/=]+&#39;/);
  });

  it('contains every finding section', () => {
    for (const heading of [
      'What did you find?',
      'Why does it matter?',
      'What did you observe?',
      'What should it be?',
      'What is affected?',
      'What evidence supports this?',
      'What should I check before changing it?',
      'How do I fix it?',
      'How do I roll it back?',
      'How do I verify the fix?',
      'Authoritative references',
    ]) {
      expect(report).toContain(`<h4>${heading}</h4>`);
    }
    expect(report).toContain('What should I fix first?');
    expect(report).toContain('not a security score');
  });

  it('lists not-assessed controls and evidence integrity', () => {
    expect(report).toContain('Controls not assessed');
    expect(report).toContain('All evidence files listed in the manifest were present');
  });

  it('is deterministic for the same input', () => {
    expect(renderHtmlReport(result, { generatedAt: new Date('2026-09-02T00:00:00Z') })).toBe(report);
  });
});

describe('JSON report', () => {
  it('wraps a schema-valid assessment', () => {
    const result = sampleResult();
    const report = buildJsonReport(result, new Date('2026-09-02T00:00:00Z'));
    expect(report.reportType).toBe('adminsecops.assessment');
    const text = serializeJsonReport(report);
    expect(JSON.parse(text)).toEqual(JSON.parse(JSON.stringify(report)));
    expect(report.assessment.findings.length).toBeGreaterThan(0);
  });

  it('builds safe file names', () => {
    expect(reportFileName(sampleResult(), 'html')).toMatch(/^adminsecops-report-Contoso-[A-Za-z0-9.-]+-2026-09-01\.html$/);
  });
});
