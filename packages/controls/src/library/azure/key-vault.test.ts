import { describe, expect, it } from 'vitest';
import { keyVault } from '../../../test/builders/azure.js';
import { run } from '../../../test/run.js';
import { azKeyVaultPurgeProtection, azKeyVaultRbac } from './key-vault.js';

describe('AZ-KV-001 purge protection', () => {
  it('passes when purge protection is enabled', () => {
    expect(run(azKeyVaultPurgeProtection, { 'azure.keyVaults': [keyVault(), keyVault()] }).status).toBe('PASS');
  });

  it('fails when purge protection is not set (null means never enabled)', () => {
    const result = run(azKeyVaultPurgeProtection, { 'azure.keyVaults': [keyVault(), keyVault({ name: 'kv-legacy', enablePurgeProtection: null })] });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.name)).toEqual(['kv-legacy']);
  });

  it('fails when purge protection is false and notes disabled soft delete', () => {
    const result = run(azKeyVaultPurgeProtection, {
      'azure.keyVaults': [keyVault({ enablePurgeProtection: false, enableSoftDelete: false })],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('Soft delete');
  });

  it('is NOT_APPLICABLE without key vaults', () => {
    expect(run(azKeyVaultPurgeProtection, { 'azure.keyVaults': [] }).status).toBe('NOT_APPLICABLE');
  });
});

describe('AZ-KV-002 Azure RBAC permission model', () => {
  it('passes when every vault uses Azure RBAC', () => {
    expect(run(azKeyVaultRbac, { 'azure.keyVaults': [keyVault()] }).status).toBe('PASS');
  });

  it.each([false, null])('fails when enableRbacAuthorization is %s (access policies)', (value) => {
    const result = run(azKeyVaultRbac, { 'azure.keyVaults': [keyVault({ enableRbacAuthorization: value })] });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('access policies');
  });

  it('is NOT_ASSESSED when key vaults were not collected', () => {
    expect(run(azKeyVaultRbac, {}, { unavailable: { 'azure.keyVaults': 'Failed' } }).status).toBe('NOT_ASSESSED');
  });
});
