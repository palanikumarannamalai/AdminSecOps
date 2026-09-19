import { describe, expect, it } from 'vitest';
import { storageAccount, SUB_B } from '../../../test/builders/azure.js';
import { run } from '../../../test/run.js';
import { azStorageMinimumTls, azStorageNoAnonymousBlob, azStorageSecureTransfer } from './storage.js';

describe('AZ-STG-001 anonymous blob access', () => {
  it('passes when every account disallows anonymous access', () => {
    const result = run(azStorageNoAnonymousBlob, { 'azure.storageAccounts': [storageAccount(), storageAccount({ subscriptionId: SUB_B })] });
    expect(result.status).toBe('PASS');
  });

  it('fails when anonymous access is allowed', () => {
    const result = run(azStorageNoAnonymousBlob, {
      'azure.storageAccounts': [storageAccount(), storageAccount({ name: 'publicdata', allowBlobPublicAccess: true })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.name)).toEqual(['publicdata']);
  });

  it('fails when the property is not set (null)', () => {
    const result = run(azStorageNoAnonymousBlob, { 'azure.storageAccounts': [storageAccount({ allowBlobPublicAccess: null })] });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('not set');
  });

  it('mentions disabled public network access as a mitigating factor', () => {
    const result = run(azStorageNoAnonymousBlob, {
      'azure.storageAccounts': [storageAccount({ allowBlobPublicAccess: true, publicNetworkAccess: 'Disabled' })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('Public network access is disabled');
  });

  it('treats FileStorage accounts as not applicable', () => {
    const result = run(azStorageNoAnonymousBlob, {
      'azure.storageAccounts': [storageAccount({ kind: 'FileStorage', allowBlobPublicAccess: null })],
    });
    expect(result.status).toBe('NOT_APPLICABLE');
  });

  it('is NOT_APPLICABLE without storage accounts', () => {
    expect(run(azStorageNoAnonymousBlob, { 'azure.storageAccounts': [] }).status).toBe('NOT_APPLICABLE');
  });

  it('is NOT_APPLICABLE when the collector reported the dataset as not applicable', () => {
    expect(run(azStorageNoAnonymousBlob, {}, { unavailable: { 'azure.storageAccounts': 'NotApplicable' } }).status).toBe('NOT_APPLICABLE');
  });

  it('downgrades PASS to REVIEW on partial evidence', () => {
    const result = run(azStorageNoAnonymousBlob, { 'azure.storageAccounts': [storageAccount()] }, { partial: ['azure.storageAccounts'] });
    expect(result.status).toBe('REVIEW');
  });
});

describe('AZ-STG-002 secure transfer', () => {
  it('passes when HTTPS is required', () => {
    expect(run(azStorageSecureTransfer, { 'azure.storageAccounts': [storageAccount()] }).status).toBe('PASS');
  });

  it('fails when HTTP is accepted', () => {
    const result = run(azStorageSecureTransfer, { 'azure.storageAccounts': [storageAccount({ supportsHttpsTrafficOnly: false })] });
    expect(result.status).toBe('FAIL');
  });

  it('never passes an unknown value', () => {
    expect(run(azStorageSecureTransfer, { 'azure.storageAccounts': [storageAccount({ supportsHttpsTrafficOnly: null })] }).status).toBe('NOT_ASSESSED');
    expect(
      run(azStorageSecureTransfer, { 'azure.storageAccounts': [storageAccount(), storageAccount({ supportsHttpsTrafficOnly: null })] }).status,
    ).toBe('REVIEW');
  });
});

describe('AZ-STG-003 minimum TLS version', () => {
  it.each(['TLS1_2', 'TLS1_3', 'tls1_2'])('passes with %s', (minimumTlsVersion) => {
    expect(run(azStorageMinimumTls, { 'azure.storageAccounts': [storageAccount({ minimumTlsVersion })] }).status).toBe('PASS');
  });

  it.each(['TLS1_0', 'TLS1_1'])('fails with %s', (minimumTlsVersion) => {
    expect(run(azStorageMinimumTls, { 'azure.storageAccounts': [storageAccount({ minimumTlsVersion })] }).status).toBe('FAIL');
  });

  it.each([null, ''])('fails when not set (%s), because TLS 1.0 is then accepted', (minimumTlsVersion) => {
    const result = run(azStorageMinimumTls, { 'azure.storageAccounts': [storageAccount({ minimumTlsVersion })] });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('not set');
  });

  it('does not pass an unrecognized value', () => {
    expect(run(azStorageMinimumTls, { 'azure.storageAccounts': [storageAccount({ minimumTlsVersion: 'TLS9' })] }).status).toBe('NOT_ASSESSED');
  });
});
