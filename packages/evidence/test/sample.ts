import type { EvidenceEnvelope, EvidenceManifest } from '@adminsecops/schemas';
import { buildEvidencePackage } from '../src/package-writer.js';

export const ASSESSMENT_ID = '6f1c1a52-4b7e-4f8e-9a51-0c6f7d2b9e10';

export function manifestBase(): Omit<EvidenceManifest, 'files'> {
  return {
    manifestVersion: '1.0',
    product: 'AdminSecOps',
    assessmentId: ASSESSMENT_ID,
    createdAt: '2026-09-01T10:00:00.0000000Z',
    collector: { name: 'AdminSecOps.Collector', version: '0.1.0', powershellVersion: '7.4.6', platform: 'Win32NT' },
    environment: {
      label: 'Contoso test',
      tenantId: '11111111-2222-4333-8444-555555555555',
      tenantDisplayName: 'Contoso',
      primaryDomain: 'contoso.example',
      adForestName: null,
      adDomainName: null,
    },
    options: { modules: ['Entra'] },
    modules: [
      {
        name: 'Entra',
        version: '0.1.0',
        status: 'Completed',
        startedAt: '2026-09-01T09:58:00Z',
        completedAt: '2026-09-01T10:00:00Z',
        prerequisites: [],
        errors: [],
        warnings: [],
      },
    ],
  };
}

export function envelope(datasetId: string, data: unknown, overrides: Partial<EvidenceEnvelope> = {}): EvidenceEnvelope {
  return {
    schemaVersion: '1.0',
    datasetId,
    assessmentId: ASSESSMENT_ID,
    collector: { name: 'AdminSecOps.Collector', version: '0.1.0', module: 'Entra', moduleVersion: '0.1.0' },
    collectedAt: '2026-09-01T09:59:00Z',
    source: { system: 'MicrosoftGraph', operations: ['GET https://graph.microsoft.com/v1.0/policies/x'], apiVersion: 'v1.0' },
    status: 'Success',
    errors: [],
    warnings: [],
    data,
    ...overrides,
  };
}

/** A small valid package with two Entra datasets. */
export function samplePackage() {
  return buildEvidencePackage(manifestBase(), [
    { path: 'evidence/entra/securityDefaults.json', envelope: envelope('entra.securityDefaults', { isEnabled: false }) },
    {
      path: 'evidence/entra/authorizationPolicy.json',
      envelope: envelope('entra.authorizationPolicy', {
        allowInvitesFrom: 'everyone',
        guestUserRoleId: '10dae51f-b6af-4016-8d66-8c2a99b929b3',
        permissionGrantPolicyIdsAssignedToDefaultUserRole: [],
        defaultUserRolePermissions: { allowedToCreateApps: true, allowedToCreateSecurityGroups: true, allowedToReadOtherUsers: true },
        unexpectedExtraProperty: 'is stripped',
      }),
    },
  ]);
}
