/**
 * Realistic, fictional assessment result for web tests (contoso.example). Typed against
 * the result schema so that contract changes break the tests at compile time.
 * No real tenant, domain or person data.
 */
import type { Technology } from '@adminsecops/core';
import type {
  AssessmentComparison,
  AssessmentResult,
  AssessmentSummary,
  ControlResult,
  EvidenceReference,
  Finding,
  StatusCounts,
} from '@adminsecops/schemas';
import type { AssessmentListItem } from '../api/types';

export const ASSESSMENT_ID = '3f2a9c1e-7b4d-4e8a-9c21-5d6e7f8a9b0c';
export const FOLLOWUP_ASSESSMENT_ID = '8c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f';
const TENANT_ID = '00000000-0000-4000-8000-00000000c0de';
const ASSESSED_AT = '2026-09-01T09:30:00.0000000+00:00';
const PROCESSED_AT = '2026-09-01T10:02:11.512Z';

const HASH = (seed: string) => seed.repeat(64).slice(0, 64);

const ev = {
  caPolicies: {
    datasetId: 'entra.conditionalAccessPolicies',
    path: 'entra/conditionalAccessPolicies.json',
    sha256: HASH('a1'),
    collectedAt: '2026-09-01T09:21:04Z',
    status: 'Success',
    source: {
      system: 'MicrosoftGraph',
      operations: ['GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'],
      apiVersion: 'v1.0',
    },
  },
  servicePrincipals: {
    datasetId: 'entra.servicePrincipals',
    path: 'entra/servicePrincipals.json',
    sha256: HASH('b2'),
    collectedAt: '2026-09-01T09:22:40Z',
    status: 'Partial',
    source: {
      system: 'MicrosoftGraph',
      operations: ['GET https://graph.microsoft.com/v1.0/servicePrincipals'],
      apiVersion: 'v1.0',
    },
  },
  forwarding: {
    datasetId: 'exchange.mailboxForwarding',
    path: 'exchange/mailboxForwarding.json',
    sha256: HASH('c3'),
    collectedAt: '2026-09-01T09:25:12Z',
    status: 'Success',
    source: { system: 'ExchangeOnline', operations: ['Get-EXOMailbox -Properties ForwardingSmtpAddress'], apiVersion: null },
  },
  krbtgt: {
    datasetId: 'ad.krbtgt',
    path: 'ad/krbtgt.json',
    sha256: HASH('d4'),
    collectedAt: '2026-09-01T09:27:30Z',
    status: 'Success',
    source: { system: 'ActiveDirectory', operations: ['Get-ADUser -Identity krbtgt -Properties pwdLastSet'], apiVersion: null },
  },
  templates: {
    datasetId: 'adcs.certificateTemplates',
    path: 'adcs/certificateTemplates.json',
    sha256: HASH('e5'),
    collectedAt: '2026-09-01T09:28:02Z',
    status: 'Success',
    source: {
      system: 'ActiveDirectory',
      operations: ['Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration"'],
      apiVersion: null,
    },
  },
} satisfies Record<string, EvidenceReference>;

function result(partial: Partial<ControlResult> & Pick<ControlResult, 'controlId' | 'title' | 'technology' | 'status'>): ControlResult {
  return {
    controlVersion: '1.0.0',
    category: 'General',
    subcategory: 'General',
    severity: 'medium',
    confidence: 'high',
    statusReason: 'Evaluated against the collected evidence.',
    observed: { summary: '', facts: [] },
    expected: 'The control expected state.',
    affectedObjects: [],
    affectedObjectCount: 0,
    evidence: [],
    notes: [],
    ...partial,
  };
}

export const sampleResults: ControlResult[] = [
  result({
    controlId: 'ADCS-TPL-001',
    title: 'Certificate templates allow requesters to supply the subject (ESC1)',
    technology: 'adcs',
    category: 'Certificate services',
    subcategory: 'Templates',
    severity: 'critical',
    status: 'FAIL',
    statusReason: '1 enabled template allows enrollee-supplied subject and client authentication for broad groups.',
    observed: {
      summary: 'Template "ContosoUser-Legacy" is published, allows enrollee-supplied subject and grants enroll to Domain Users.',
      facts: [
        { label: 'Vulnerable templates', value: 1 },
        { label: 'Manager approval required', value: false },
      ],
    },
    expected: 'No published template combines enrollee-supplied subject, client authentication EKU and low-privileged enrollment.',
    affectedObjectCount: 1,
    affectedObjects: [
      {
        type: 'certificateTemplate',
        id: 'CN=ContosoUser-Legacy,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=example',
        name: 'ContosoUser-Legacy',
        detail: 'Enroll: CONTOSO\\Domain Users; EKU: Client Authentication',
      },
    ],
    evidence: [ev.templates],
  }),
  result({
    controlId: 'ENTRA-CA-001',
    title: 'Legacy authentication is not blocked by Conditional Access',
    technology: 'entra',
    category: 'Conditional Access',
    subcategory: 'Legacy authentication',
    severity: 'high',
    status: 'FAIL',
    statusReason: 'No enabled policy blocks legacy authentication client apps for all users.',
    observed: {
      summary: '3 Conditional Access policies are enabled; none blocks Exchange ActiveSync and other legacy clients.',
      facts: [
        { label: 'Enabled policies', value: 3 },
        { label: 'Policies blocking legacy authentication', value: 0 },
        { label: 'Report-only policy present', value: true },
      ],
    },
    expected: 'An enabled policy blocks legacy authentication for all users, with documented exclusions only.',
    affectedObjectCount: 1,
    affectedObjects: [{ type: 'tenant', id: TENANT_ID, name: 'Contoso (Example)' }],
    evidence: [ev.caPolicies],
  }),
  result({
    controlId: 'M365-EXO-004',
    title: 'Mailboxes forward mail to external domains',
    technology: 'm365',
    category: 'Exchange Online',
    subcategory: 'Mail flow',
    severity: 'medium',
    status: 'FAIL',
    statusReason: '3 mailboxes forward to external recipients.',
    affectedObjectCount: 3,
    affectedObjects: [
      { type: 'mailbox', id: 'adele.vance@contoso.example', name: 'Adele Vance', detail: 'Forwards to an external address' },
      { type: 'mailbox', id: 'finance@contoso.example', name: 'Finance', detail: 'Forwards to an external address' },
    ],
    evidence: [ev.forwarding],
  }),
  result({
    controlId: 'AD-KRB-001',
    title: 'KRBTGT account password has not been changed in over 180 days',
    technology: 'ad',
    category: 'Kerberos',
    subcategory: 'KRBTGT',
    severity: 'medium',
    confidence: 'high',
    status: 'FAIL',
    statusReason: 'The KRBTGT password was last set 1,204 days before the assessment.',
    observed: { summary: 'pwdLastSet is 2023-05-16.', facts: [{ label: 'Days since password change', value: 1204 }] },
    affectedObjectCount: 1,
    affectedObjects: [{ type: 'user', id: 'S-1-5-21-1004336348-1177238915-682003330-502', name: 'krbtgt' }],
    evidence: [ev.krbtgt],
  }),
  result({
    controlId: 'ENTRA-APP-002',
    title: 'Applications hold high-privilege Microsoft Graph application permissions',
    technology: 'entra',
    category: 'Applications',
    subcategory: 'Permissions',
    severity: 'high',
    confidence: 'medium',
    status: 'REVIEW',
    statusReason: '2 service principals hold Directory.ReadWrite.All or equivalent application permissions.',
    affectedObjectCount: 2,
    affectedObjects: [
      { type: 'servicePrincipal', id: '11111111-2222-4333-8444-555555555555', name: 'Contoso HR Sync' },
      { type: 'servicePrincipal', id: '66666666-7777-4888-8999-000000000000', name: 'Legacy Reporting Tool' },
    ],
    evidence: [ev.servicePrincipals],
    notes: ['The service principal dataset was collected partially; results may be incomplete.'],
  }),
  result({
    controlId: 'ENTRA-SD-001',
    title: 'Security defaults or Conditional Access protect sign-ins',
    technology: 'entra',
    category: 'Identity protection',
    subcategory: 'Baseline',
    severity: 'high',
    status: 'PASS',
    statusReason: 'Conditional Access is in use, so security defaults are not required.',
    evidence: [ev.caPolicies],
  }),
  result({
    controlId: 'HYB-SYNC-001',
    title: 'Directory synchronization is healthy',
    technology: 'hybrid',
    category: 'Hybrid identity',
    subcategory: 'Synchronization',
    status: 'PASS',
    statusReason: 'Last synchronization completed 18 minutes before collection.',
  }),
  result({
    controlId: 'AZ-DEF-001',
    title: 'Microsoft Defender for Cloud plans are enabled for servers',
    technology: 'azure',
    category: 'Defender for Cloud',
    subcategory: 'Plans',
    status: 'NOT_ASSESSED',
    statusReason: 'Dataset azure.defenderPlans was not collected (module Azure was not selected).',
  }),
  result({
    controlId: 'INT-CMP-001',
    title: 'Devices without a compliance policy are marked not compliant',
    technology: 'intune',
    category: 'Compliance',
    subcategory: 'Settings',
    status: 'NOT_APPLICABLE',
    statusReason: 'The tenant has no Intune licence.',
  }),
  result({
    controlId: 'GPO-PWD-001',
    title: 'Group Policy Preferences do not contain stored passwords',
    technology: 'gpo',
    category: 'Group Policy',
    subcategory: 'Credentials',
    severity: 'critical',
    status: 'ERROR',
    statusReason: 'The SYSVOL scan dataset failed schema validation.',
  }),
];

function finding(
  control: ControlResult,
  rank: number,
  tier: Finding['priority']['tier'],
  extra: Partial<Finding>,
): Finding {
  if (control.status !== 'FAIL' && control.status !== 'REVIEW') throw new Error('Findings need FAIL or REVIEW');
  return {
    findingId: `F-${control.controlId}`,
    findingKey: `${control.controlId}:tenant`,
    assessmentId: ASSESSMENT_ID,
    controlId: control.controlId,
    controlVersion: control.controlVersion,
    status: control.status,
    severity: control.severity,
    confidence: control.confidence,
    technology: control.technology,
    category: control.category,
    title: control.title,
    description: control.statusReason,
    observedState: { summary: control.observed.summary || control.statusReason, facts: control.observed.facts },
    expectedState: control.expected,
    affectedObjects: control.affectedObjects,
    affectedObjectCount: control.affectedObjectCount,
    evidence: control.evidence,
    risk: 'An attacker who obtains a low-privileged foothold can use this configuration to escalate privileges.',
    remediation: {
      summary: 'Change the configuration to the expected state after confirming dependencies.',
      steps: ['Identify owners of the affected objects.', 'Apply the change in a pilot group.', 'Apply the change broadly.'],
      effort: 'medium',
    },
    implementationConsiderations: ['Confirm which applications or users depend on the current configuration.'],
    impact: 'Users or applications that rely on the current configuration may stop working until they are updated.',
    rollback: ['Revert the setting to its previous value recorded before the change.'],
    validation: ['Collect new evidence and confirm the control returns PASS.'],
    references: [
      {
        title: 'Microsoft Learn: security guidance',
        url: 'https://learn.microsoft.com/en-us/security/',
        publisher: 'Microsoft',
      },
    ],
    frameworkMappings: [{ framework: 'NIST-800-53r5', id: 'AC-6' }],
    tags: [],
    effort: 'medium',
    notes: control.notes,
    priority: {
      rank,
      tier,
      sortKey: 50000 - rank,
      factors: [`Severity: ${control.severity}`, `Confidence: ${control.confidence}`],
    },
    ...extra,
  };
}

const byId = (id: string): ControlResult => {
  const found = sampleResults.find((r) => r.controlId === id);
  if (found === undefined) throw new Error(`Missing control ${id}`);
  return found;
};

export const sampleFindings: Finding[] = [
  finding(byId('ADCS-TPL-001'), 1, 'fix-now', {
    risk: 'Any domain user can request a certificate for any identity, including domain administrators, and authenticate as them.',
    remediation: {
      summary: 'Remove the enrollee-supplied subject flag or restrict enrollment to a dedicated group, then require manager approval.',
      steps: [
        'Open the Certificate Templates console (certtmpl.msc) on a management server.',
        'Open the properties of the ContosoUser-Legacy template.',
        'On Subject Name, select "Build from this Active Directory information".',
        'On Security, remove Enroll from Domain Users and grant it to the group that needs the template.',
      ],
      scriptExample:
        '# Review before running. Lists templates that allow enrollee-supplied subject.\nGet-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=contoso,DC=example" -Filter * -Properties msPKI-Certificate-Name-Flag |\n  Where-Object { $_."msPKI-Certificate-Name-Flag" -band 1 }',
      effort: 'low',
    },
    effort: 'low',
    references: [
      {
        title: 'Securing PKI: Certificate template security',
        url: 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/',
        publisher: 'Microsoft',
      },
      { title: 'MITRE ATT&CK T1649 Steal or Forge Authentication Certificates', url: 'https://attack.mitre.org/techniques/T1649/', publisher: 'MITRE' },
    ],
    frameworkMappings: [
      { framework: 'MITRE-ATTACK', id: 'T1649' },
      { framework: 'NIST-800-53r5', id: 'AC-6' },
    ],
    tags: ['privileged-access', 'credential-exposure'],
  }),
  finding(byId('ENTRA-CA-001'), 2, 'fix-now', {
    tags: ['legacy-authentication', 'mfa'],
    effort: 'low',
    frameworkMappings: [
      { framework: 'CISA-SCuBA', id: 'MS.AAD.1.1v1' },
      { framework: 'MCSB', id: 'IM-7' },
    ],
  }),
  finding(byId('M365-EXO-004'), 3, 'fix-next', {
    tags: ['data-exfiltration'],
    frameworkMappings: [{ framework: 'CISA-SCuBA', id: 'MS.EXO.1.1v1' }],
  }),
  finding(byId('AD-KRB-001'), 4, 'fix-next', { effort: 'high' }),
  finding(byId('ENTRA-APP-002'), 5, 'review', { tags: ['privileged-access'] }),
];

function countStatuses(results: readonly ControlResult[]): StatusCounts {
  const counts: StatusCounts = { PASS: 0, FAIL: 0, REVIEW: 0, NOT_APPLICABLE: 0, NOT_ASSESSED: 0, ERROR: 0 };
  for (const r of results) counts[r.status] += 1;
  return counts;
}

const TECHNOLOGY_LIST: Technology[] = ['entra', 'm365', 'azure', 'intune', 'ad', 'adcs', 'windows', 'gpo', 'hybrid'];

export function summarize(results: readonly ControlResult[], findings: readonly Finding[]): AssessmentSummary {
  const byStatus = countStatuses(results);
  const byTechnology = Object.fromEntries(
    TECHNOLOGY_LIST.map((t) => [t, countStatuses(results.filter((r) => r.technology === t))]),
  ) as Record<Technology, StatusCounts>;
  const findingsBySeverity = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const f of findings) findingsBySeverity[f.severity] += 1;
  const assessed = byStatus.PASS + byStatus.FAIL + byStatus.REVIEW;
  return {
    controlsEvaluated: results.length,
    byStatus,
    findingsBySeverity,
    byTechnology,
    assessmentCoverage: { assessed, applicable: results.length - byStatus.NOT_APPLICABLE },
  };
}

export const sampleResult: AssessmentResult = {
  resultSchemaVersion: '1.0',
  engineVersion: '0.1.0',
  controlLibraryVersion: '0.1.0',
  assessmentId: ASSESSMENT_ID,
  assessedAt: ASSESSED_AT,
  processedAt: PROCESSED_AT,
  collection: {
    collector: { name: 'AdminSecOps.Collector', version: '0.1.0', powershellVersion: '7.4.6', platform: 'Win32NT' },
    environment: {
      label: 'Contoso production',
      tenantId: TENANT_ID,
      tenantDisplayName: 'Contoso (Example)',
      primaryDomain: 'contoso.example',
      adForestName: 'contoso.example',
      adDomainName: 'contoso.example',
    },
    options: { modules: ['Entra', 'Exchange', 'AD', 'ADCS', 'GPO'] },
    modules: [
      {
        name: 'Entra',
        version: '0.1.0',
        status: 'CompletedWithErrors',
        startedAt: '2026-09-01T09:20:00Z',
        completedAt: '2026-09-01T09:23:00Z',
        prerequisites: [{ name: 'Microsoft.Graph.Authentication', satisfied: true, detail: null }],
        errors: [],
        warnings: [],
      },
      {
        name: 'AD',
        version: '0.1.0',
        status: 'Completed',
        startedAt: '2026-09-01T09:26:00Z',
        completedAt: '2026-09-01T09:28:30Z',
        prerequisites: [],
        errors: [],
        warnings: [],
      },
    ],
    manifestSha256: HASH('f6'),
  },
  evidence: {
    integrityVerified: true,
    files: [
      {
        path: 'entra/conditionalAccessPolicies.json',
        datasetId: 'entra.conditionalAccessPolicies',
        module: 'Entra',
        integrity: 'verified',
        schema: 'valid',
        sensitiveContent: false,
        collectionStatus: 'Success',
        sha256: HASH('a1'),
        expectedSha256: HASH('a1'),
        sizeBytes: 48213,
        messages: [],
      },
      {
        path: 'entra/servicePrincipals.json',
        datasetId: 'entra.servicePrincipals',
        module: 'Entra',
        integrity: 'verified',
        schema: 'valid',
        sensitiveContent: false,
        collectionStatus: 'Partial',
        sha256: HASH('b2'),
        expectedSha256: HASH('b2'),
        sizeBytes: 1_204_551,
        messages: ['Collection stopped after 2 of 3 pages (throttled).'],
      },
      {
        path: 'gpo/sysvolPasswordArtifacts.json',
        datasetId: 'gpo.sysvolPasswordArtifacts',
        module: 'GPO',
        integrity: 'verified',
        schema: 'invalid',
        sensitiveContent: false,
        collectionStatus: 'Success',
        sha256: HASH('09'),
        expectedSha256: HASH('09'),
        sizeBytes: 912,
        messages: ['data.files[0].path: Expected string, received number'],
      },
    ],
    datasets: [
      {
        datasetId: 'entra.conditionalAccessPolicies',
        title: 'Conditional Access policies',
        technology: 'entra',
        module: 'Entra',
        state: 'available',
        collectionStatus: 'Success',
        reason: 'Collected successfully.',
      },
      {
        datasetId: 'entra.servicePrincipals',
        title: 'Service principals',
        technology: 'entra',
        module: 'Entra',
        state: 'partial',
        collectionStatus: 'Partial',
        reason: 'Some pages could not be collected.',
      },
      {
        datasetId: 'azure.defenderPlans',
        title: 'Defender for Cloud plans',
        technology: 'azure',
        module: 'Azure',
        state: 'unavailable',
        collectionStatus: null,
        reason: 'Module Azure was not collected.',
      },
    ],
    issues: [
      {
        level: 'warning',
        code: 'GraphThrottled',
        message: 'Microsoft Graph throttled the request; collection of servicePrincipals is partial.',
        target: 'servicePrincipals',
        module: 'Entra',
        datasetId: 'entra.servicePrincipals',
        origin: 'collector',
      },
      {
        level: 'error',
        code: 'SchemaValidationFailed',
        message: 'gpo.sysvolPasswordArtifacts did not match the dataset schema.',
        target: null,
        module: 'GPO',
        datasetId: 'gpo.sysvolPasswordArtifacts',
        origin: 'ingestion',
      },
    ],
  },
  inventory: [
    { technology: 'entra', key: 'users', label: 'Users', count: 1342, datasetId: 'entra.users' },
    { technology: 'entra', key: 'guests', label: 'Guest users', count: 87, datasetId: 'entra.guestUsers' },
    { technology: 'entra', key: 'caPolicies', label: 'Conditional Access policies', count: 3, datasetId: 'entra.conditionalAccessPolicies' },
    { technology: 'azure', key: 'subscriptions', label: 'Subscriptions', count: null, datasetId: 'azure.subscriptions' },
    { technology: 'ad', key: 'computers', label: 'Computers', count: 412, datasetId: 'ad.computers' },
  ],
  summary: summarize(sampleResults, sampleFindings),
  results: sampleResults,
  findings: sampleFindings,
};

export const sampleListItem: AssessmentListItem = {
  assessmentId: ASSESSMENT_ID,
  label: 'Contoso production',
  tenantDisplayName: 'Contoso (Example)',
  primaryDomain: 'contoso.example',
  adForestName: 'contoso.example',
  assessedAt: ASSESSED_AT,
  processedAt: PROCESSED_AT,
  integrityVerified: true,
  source: 'sample',
  summary: sampleResult.summary,
};

export const followupListItem: AssessmentListItem = {
  ...sampleListItem,
  assessmentId: FOLLOWUP_ASSESSMENT_ID,
  label: 'Contoso production (follow-up)',
  assessedAt: '2026-09-15T09:30:00Z',
  processedAt: '2026-09-15T09:40:00Z',
};

export const sampleComparison: AssessmentComparison = {
  baseline: { assessmentId: ASSESSMENT_ID, assessedAt: ASSESSED_AT },
  current: { assessmentId: FOLLOWUP_ASSESSMENT_ID, assessedAt: '2026-09-15T09:30:00Z' },
  sameEnvironment: true,
  newFindings: [
    {
      findingKey: 'ENTRA-GST-001:tenant',
      controlId: 'ENTRA-GST-001',
      title: 'Guest users can invite other guests',
      severity: 'medium',
      status: 'FAIL',
    },
  ],
  resolvedFindings: [
    {
      findingKey: 'ADCS-TPL-001:tenant',
      controlId: 'ADCS-TPL-001',
      title: 'Certificate templates allow requesters to supply the subject (ESC1)',
      severity: 'critical',
      status: 'FAIL',
    },
    {
      findingKey: 'ENTRA-CA-001:tenant',
      controlId: 'ENTRA-CA-001',
      title: 'Legacy authentication is not blocked by Conditional Access',
      severity: 'high',
      status: 'FAIL',
    },
  ],
  changedFindings: [
    {
      findingKey: 'M365-EXO-004:tenant',
      controlId: 'M365-EXO-004',
      title: 'Mailboxes forward mail to external domains',
      severity: 'medium',
      changes: [{ field: 'affectedObjectCount', from: 3, to: 1 }],
      addedObjects: [],
      removedObjects: ['adele.vance@contoso.example', 'finance@contoso.example'],
    },
  ],
  unchangedFindingCount: 2,
  controlStatusChanges: [
    { controlId: 'ADCS-TPL-001', title: 'Certificate templates allow requesters to supply the subject (ESC1)', from: 'FAIL', to: 'PASS' },
    { controlId: 'AZ-DEF-001', title: 'Microsoft Defender for Cloud plans are enabled for servers', from: 'NOT_ASSESSED', to: null },
  ],
  direction: 'mixed',
};
