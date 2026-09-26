import { screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { AssessmentResult, ControlResult, DatasetAvailability, ManifestModule } from '@adminsecops/schemas';
import { computeCoverage, gapReason, workloadOfDataset } from '../lib/coverage';
import { createFakeApi, renderApp } from '../test/render';
import { ASSESSMENT_ID, sampleResult } from '../test/sample-result';

function dataset(datasetId: string, state: DatasetAvailability['state'], collectionStatus: DatasetAvailability['collectionStatus'], module: DatasetAvailability['module'], reason: string): DatasetAvailability {
  return { datasetId, title: datasetId, technology: datasetId.startsWith('intune.') ? 'intune' : datasetId.startsWith('entra.') ? 'entra' : 'm365', module, state, collectionStatus, reason };
}

function control(controlId: string, status: ControlResult['status'], datasetId: string): ControlResult {
  return {
    controlId,
    controlVersion: '1.0.0',
    title: controlId,
    technology: 'm365',
    category: 'General',
    subcategory: 'General',
    severity: 'low',
    confidence: 'high',
    status,
    statusReason: 'Synthetic result.',
    observed: { summary: '', facts: [] },
    expected: 'Expected state.',
    affectedObjects: [],
    affectedObjectCount: 0,
    evidence: [{ datasetId, path: null, sha256: null, collectedAt: null, status: null, source: null }],
    notes: [],
  };
}

const module = (name: ManifestModule['name'], status: ManifestModule['status'], warning?: string): ManifestModule => ({
  name,
  version: '0.2.0',
  status,
  startedAt: null,
  completedAt: null,
  prerequisites: [],
  errors: [],
  warnings: warning === undefined ? [] : [{ code: 'NOT_AVAILABLE_ONLINE', message: warning, target: null }],
});

/** An online assessment: SharePoint consent missing, Teams partial, Intune unlicensed, Exchange unsupported. */
const onlineResult: AssessmentResult = {
  ...sampleResult,
  collection: {
    ...sampleResult.collection,
    modules: [
      module('Entra', 'Completed'),
      module('M365', 'CompletedWithErrors'),
      module('Intune', 'Completed'),
      module('Exchange', 'Skipped', 'Exchange Online configuration is not available through delegated Microsoft Graph.'),
    ],
  },
  evidence: {
    ...sampleResult.evidence,
    datasets: [
      dataset('entra.organization', 'available', 'Success', 'Entra', 'Collected.'),
      dataset('entra.applications', 'unavailable', null, 'Entra', 'Not present in the evidence package.'),
      dataset('m365.sharePointSettings', 'unavailable', 'Unauthorized', 'M365', 'HTTP 403. Delegated consent was not granted for: SharePointTenantSettings.Read.All.'),
      dataset('m365.teamsAppSettings', 'available', 'Success', 'M365', 'Collected.'),
      dataset('m365.teamsTeamSettings', 'partial', 'Partial', 'M365', 'Some teams could not be read.'),
      dataset('intune.settings', 'unavailable', 'NotApplicable', 'Intune', 'Microsoft Intune is not licensed.'),
      dataset('exchange.transportConfig', 'unavailable', null, 'Exchange', 'Not present in the evidence package.'),
    ],
  },
  results: [
    control('ENTRA-CA-001', 'PASS', 'entra.securityDefaults'),
    control('M365-SPO-001', 'NOT_ASSESSED', 'm365.sharePointSettings'),
    control('M365-SPO-002', 'NOT_ASSESSED', 'm365.sharePointSettings'),
    control('M365-TMS-001', 'PASS', 'm365.teamsAppSettings'),
    control('M365-TMS-002', 'REVIEW', 'm365.teamsTeamSettings'),
    control('INTUNE-CMP-001', 'NOT_APPLICABLE', 'intune.settings'),
    control('M365-EXO-001', 'NOT_ASSESSED', 'exchange.transportConfig'),
  ],
};

describe('coverage computation', () => {
  it('maps datasets to workloads and statuses to administrator reasons', () => {
    expect(workloadOfDataset('m365.sharePointSettings')).toBe('sharepoint');
    expect(workloadOfDataset('m365.teamsTeamSettings')).toBe('teams');
    expect(workloadOfDataset('exchange.mailDnsRecords')).toBe('exchange');
    expect(workloadOfDataset('gpo.groupPolicyObjects')).toBe('onprem');
    expect(gapReason('Unauthorized', false)).toBe('permission');
    expect(gapReason('NotApplicable', false)).toBe('licence');
    expect(gapReason('Failed', false)).toBe('failed');
    expect(gapReason(null, true)).toBe('unsupported');
    expect(gapReason(null, false)).toBe('not-collected');
  });

  it('never reports a workload without usable evidence as assessed', () => {
    const coverage = new Map(computeCoverage(onlineResult).map((w) => [w.key, w]));
    expect(coverage.get('sharepoint')).toMatchObject({ state: 'not-assessed', catalogueControls: 2, assessed: 0, notAssessed: 2 });
    expect(coverage.get('sharepoint')?.gaps[0]?.reason).toBe('permission');
    expect(coverage.get('teams')).toMatchObject({ state: 'partial', assessed: 2, partial: ['m365.teamsTeamSettings'] });
    expect(coverage.get('intune')).toMatchObject({ state: 'not-assessed', notApplicable: 1 });
    expect(coverage.get('intune')?.gaps[0]?.reason).toBe('licence');
    expect(coverage.get('exchange')).toMatchObject({ state: 'not-assessed', catalogueControls: 1, assessed: 0 });
    expect(coverage.get('exchange')?.gaps[0]?.reason).toBe('unsupported');
    expect(coverage.get('exchange')?.skippedReasons[0]).toContain('not available');
    expect(coverage.get('entra')).toMatchObject({ state: 'partial', assessed: 1 });
  });
});

describe('connector coverage states', () => {
  const issue = (datasetId: string, code: string) => ({ code, message: code, target: null, level: 'error' as const, module: null, datasetId, origin: 'collector' as const });
  const connectorResult: AssessmentResult = {
    ...sampleResult,
    collection: { ...sampleResult.collection, collector: { ...sampleResult.collection.collector, name: 'AdminSecOps.HostedGraphCollector' }, modules: [module('Azure', 'Skipped'), module('Exchange', 'CompletedWithErrors')] },
    evidence: {
      ...sampleResult.evidence,
      datasets: [
        dataset('azure.storageAccounts', 'unavailable', 'NotCollected', 'Azure', 'Not connected.'),
        dataset('exchange.transportConfig', 'unavailable', 'Unauthorized', 'Exchange', 'Consent missing.'),
        dataset('exchange.mailDnsRecords', 'available', 'Success', 'Exchange', 'Collected.'),
        dataset('ad.domains', 'unavailable', null, 'AD', 'Not present in the evidence package.'),
        dataset('intune.compliancePolicies', 'unavailable', 'Failed', 'Intune', 'HTTP 500.'),
      ],
      issues: [issue('azure.storageAccounts', 'CONNECTOR_NOT_CONNECTED'), issue('exchange.transportConfig', 'CONNECTOR_CONSENT_REQUIRED')],
    },
    results: [
      control('AZ-STG-001', 'NOT_ASSESSED', 'azure.storageAccounts'),
      control('M365-EXO-001', 'NOT_ASSESSED', 'exchange.transportConfig'),
      control('M365-MAIL-002', 'PASS', 'exchange.mailDnsRecords'),
      control('AD-PWD-001', 'NOT_ASSESSED', 'ad.domains'),
      control('INTUNE-CMP-002', 'NOT_ASSESSED', 'intune.compliancePolicies'),
    ],
  };

  it('distinguishes not connected, consent required, unsupported and failed collection', () => {
    const coverage = new Map(computeCoverage(connectorResult).map((w) => [w.key, w]));
    expect(coverage.get('azure')).toMatchObject({ state: 'not-assessed', blocker: 'not-connected', assessed: 0 });
    expect(coverage.get('exchange')).toMatchObject({ state: 'partial', assessed: 1, notAssessed: 1 });
    expect(coverage.get('exchange')?.gaps[0]?.reason).toBe('permission');
    expect(coverage.get('onprem')).toMatchObject({ state: 'not-assessed', blocker: 'unsupported' });
    expect(coverage.get('onprem')?.skippedReasons[0]).toContain('private networks');
    expect(coverage.get('intune')).toMatchObject({ state: 'not-assessed', blocker: 'failed' });
    expect(gapReason('NotCollected', false, ['CONNECTOR_EXPIRED'])).toBe('not-connected');
    expect(gapReason('NotCollected', false, ['CONNECTOR_UNAVAILABLE'])).toBe('unsupported');
  });

  it('labels each not-assessed workload with its reason on the page', async () => {
    renderApp(`/assessments/${ASSESSMENT_ID}/coverage`, createFakeApi({ getAssessment: vi.fn(() => Promise.resolve(connectorResult)) }));
    const table = await screen.findByRole('table', { name: 'Coverage per workload' });
    expect(within(within(table).getByRole('row', { name: /Azure subscriptions/ })).getByText('not connected')).toBeTruthy();
    expect(within(within(table).getByRole('row', { name: /On-premises/ })).getByText('unsupported online')).toBeTruthy();
    expect(within(within(table).getByRole('row', { name: /Microsoft Intune/ })).getByText('collection failed')).toBeTruthy();
    expect(screen.getByText(/Connector not connected or connection expired/)).toBeTruthy();
  });
});

describe('CoveragePage', () => {
  it('shows per-workload coverage and the reason each dataset is missing', async () => {
    renderApp(`/assessments/${ASSESSMENT_ID}/coverage`, createFakeApi({ getAssessment: vi.fn(() => Promise.resolve(onlineResult)) }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Assessment coverage by workload' })).toBeTruthy();
    const table = screen.getByRole('table', { name: 'Coverage per workload' });
    const sharePointRow = within(table).getByRole('row', { name: /SharePoint and OneDrive/ });
    expect(within(sharePointRow).getByText('Not assessed')).toBeTruthy();
    const teamsRow = within(table).getByRole('row', { name: /Microsoft Teams/ });
    expect(within(teamsRow).getByText('Partially assessed')).toBeTruthy();
    expect(screen.getByText(/Missing permission or consent/)).toBeTruthy();
    expect(screen.getByText(/Not licensed or not applicable/)).toBeTruthy();
    expect(screen.getByText('Exchange Online configuration is not available through delegated Microsoft Graph.')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Coverage' })).toBeTruthy();
  });
});
