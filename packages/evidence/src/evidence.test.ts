import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { AdminSecOpsError, sha256Hex } from '@adminsecops/core';
import { MANIFEST_FILE_NAME } from '@adminsecops/schemas';
import { loadEvidenceBundle } from './bundle.js';
import { DEFAULT_PACKAGE_LIMITS } from './limits.js';
import { buildEvidencePackage } from './package-writer.js';
import { normalizePackagePath, readDirectoryPackage, readZipPackage, type PackageFiles } from './package-reader.js';
import { makeZip, patchName } from '../test/zip.js';
import { envelope, manifestBase, samplePackage } from '../test/sample.js';

async function rejectsWith(promise: Promise<unknown>, code: string): Promise<void> {
  await expect(promise).rejects.toSatisfy((error: unknown) => error instanceof AdminSecOpsError && error.code === code);
}

describe('normalizePackagePath', () => {
  it('accepts normal relative paths and converts backslashes', () => {
    expect(normalizePackagePath('evidence\\entra\\x.json')).toBe('evidence/entra/x.json');
    expect(normalizePackagePath('evidence/')).toBeUndefined();
  });

  it.each(['../x.json', '/etc/passwd', 'C:/x.json', 'a/../../b.json', 'a/./b.json', 'a//b.json', 'a/b c.json', '.hidden', 'a/b/c/d/e/f/g.json'])(
    'rejects %s',
    (p) => {
      expect(() => normalizePackagePath(p)).toThrow(AdminSecOpsError);
    },
  );
});

describe('readZipPackage', () => {
  it('reads a valid archive in memory', async () => {
    const zip = await makeZip([
      { name: 'evidence-manifest.json', data: '{}' },
      { name: 'evidence/entra/a.json', data: '{"a":1}' },
    ]);
    const files = await readZipPackage(zip);
    expect([...files.keys()].sort()).toEqual(['evidence-manifest.json', 'evidence/entra/a.json']);
  });

  it('rejects data that is not a ZIP', async () => {
    await rejectsWith(readZipPackage(Buffer.from('not a zip')), 'PACKAGE_NOT_ZIP');
  });

  it('rejects path traversal entries', async () => {
    const zip = patchName(await makeZip([{ name: 'aa/evil.json', data: '{}' }]), 'aa/evil.json', '../evil.json');
    await expect(readZipPackage(zip)).rejects.toBeInstanceOf(AdminSecOpsError);
  });

  it('rejects absolute path entries', async () => {
    const zip = patchName(await makeZip([{ name: 'xetc/passwd', data: 'x' }]), 'xetc/passwd', '/etc/passwd');
    await expect(readZipPackage(zip)).rejects.toBeInstanceOf(AdminSecOpsError);
  });

  it('rejects symbolic links', async () => {
    const zip = await makeZip([{ name: 'evidence/link.json', data: '/etc/passwd', mode: 0o120777 }]);
    await rejectsWith(readZipPackage(zip), 'PACKAGE_SYMLINK');
  });

  it('rejects duplicate entries', async () => {
    const zip = patchName(
      await makeZip([
        { name: 'a1.json', data: '{}' },
        { name: 'a2.json', data: '{}' },
      ]),
      'a2.json',
      'a1.json',
    );
    await rejectsWith(readZipPackage(zip), 'PACKAGE_DUPLICATE_ENTRY');
  });

  it('rejects highly compressed entries (zip bomb heuristic)', async () => {
    const zip = await makeZip([{ name: 'bomb.json', data: Buffer.alloc(8 * 1024 * 1024, 0x20) }]);
    await rejectsWith(readZipPackage(zip), 'PACKAGE_COMPRESSION_RATIO');
  });

  it('enforces entry count, file size, archive size and total size limits', async () => {
    const zip = await makeZip([
      { name: 'a.json', data: 'x'.repeat(100), compress: false },
      { name: 'b.json', data: 'y'.repeat(100), compress: false },
    ]);
    await rejectsWith(readZipPackage(zip, { ...DEFAULT_PACKAGE_LIMITS, maxEntries: 1 }), 'PACKAGE_TOO_MANY_ENTRIES');
    await rejectsWith(readZipPackage(zip, { ...DEFAULT_PACKAGE_LIMITS, maxFileBytes: 50 }), 'PACKAGE_FILE_TOO_LARGE');
    await rejectsWith(readZipPackage(zip, { ...DEFAULT_PACKAGE_LIMITS, maxArchiveBytes: 10 }), 'PACKAGE_TOO_LARGE');
    await rejectsWith(readZipPackage(zip, { ...DEFAULT_PACKAGE_LIMITS, maxTotalBytes: 150 }), 'PACKAGE_TOO_LARGE');
  });
});

describe('readDirectoryPackage', () => {
  let dir: string | undefined;
  afterEach(() => {
    if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
  });

  it('reads files with forward-slash paths', async () => {
    dir = mkdtempSync(path.join(tmpdir(), 'aso-'));
    mkdirSync(path.join(dir, 'evidence', 'entra'), { recursive: true });
    writeFileSync(path.join(dir, 'evidence', 'entra', 'a.json'), '{}');
    const files = await readDirectoryPackage(dir);
    expect([...files.keys()]).toEqual(['evidence/entra/a.json']);
  });

  it('rejects symbolic links', async (context) => {
    dir = mkdtempSync(path.join(tmpdir(), 'aso-'));
    writeFileSync(path.join(dir, 'target.json'), '{}');
    try {
      symlinkSync(path.join(dir, 'target.json'), path.join(dir, 'link.json'));
    } catch {
      context.skip(); // creating symlinks requires privileges on some Windows systems
    }
    await rejectsWith(readDirectoryPackage(dir), 'PACKAGE_SYMLINK');
  });
});

describe('loadEvidenceBundle', () => {
  it('verifies hashes, validates schemas and strips unknown properties', () => {
    const { files } = samplePackage();
    const bundle = loadEvidenceBundle(files);
    expect(bundle.integrityVerified).toBe(true);
    expect(bundle.files.every((f) => f.integrity === 'verified' && f.schema === 'valid')).toBe(true);
    const auth = bundle.datasets.get('entra.authorizationPolicy');
    expect(auth?.state).toBe('available');
    expect(JSON.stringify(auth?.data)).not.toContain('unexpectedExtraProperty');
  });

  it('rejects a package without a manifest', () => {
    expect(() => loadEvidenceBundle(new Map())).toThrow(/evidence-manifest.json/);
  });

  it('rejects an invalid manifest', () => {
    const files: PackageFiles = new Map([[MANIFEST_FILE_NAME, Buffer.from('{"manifestVersion":"9.9"}')]]);
    expect(() => loadEvidenceBundle(files)).toThrow(/does not match the expected schema/);
  });

  it('marks tampered files as hash-mismatch and does not use them', () => {
    const { files } = samplePackage();
    files.set('evidence/entra/securityDefaults.json', Buffer.from(JSON.stringify(envelope('entra.securityDefaults', { isEnabled: true }))));
    const bundle = loadEvidenceBundle(files);
    expect(bundle.integrityVerified).toBe(false);
    expect(bundle.files.find((f) => f.path.endsWith('securityDefaults.json'))?.integrity).toBe('hash-mismatch');
    expect(bundle.datasets.get('entra.securityDefaults')?.state).toBe('unavailable');
    expect(bundle.issues.some((i) => i.code === 'HASH_MISMATCH')).toBe(true);
  });

  it('reports missing and unlisted files', () => {
    const { files } = samplePackage();
    files.delete('evidence/entra/securityDefaults.json');
    files.set('evidence/extra.json', Buffer.from('{}'));
    const bundle = loadEvidenceBundle(files);
    expect(bundle.files.find((f) => f.path.endsWith('securityDefaults.json'))?.integrity).toBe('missing');
    expect(bundle.files.find((f) => f.path === 'evidence/extra.json')?.integrity).toBe('unlisted');
    expect(bundle.datasets.get('entra.securityDefaults')?.state).toBe('unavailable');
  });

  it('rejects evidence files that contain secret material', () => {
    const { files } = buildEvidencePackage(manifestBase(), [
      {
        path: 'evidence/entra/applications.json',
        envelope: envelope('entra.applications', [
          {
            id: 'a',
            appId: '11111111-1111-4111-8111-111111111111',
            displayName: 'App',
            passwordCredentials: [{ keyId: 'k', hint: 'Abc', endDateTime: '2027-01-01T00:00:00Z' }],
            keyCredentials: [],
          },
        ]),
      },
    ]);
    const bundle = loadEvidenceBundle(files);
    const check = bundle.files[0];
    expect(check?.sensitiveContent).toBe(true);
    expect(bundle.datasets.get('entra.applications')?.state).toBe('unavailable');
    expect(JSON.stringify(bundle)).not.toContain('Abc');
  });

  it('rejects envelopes that disagree with the manifest', () => {
    const { files } = buildEvidencePackage(manifestBase(), [
      {
        path: 'evidence/entra/securityDefaults.json',
        envelope: envelope('entra.securityDefaults', { isEnabled: true }, { assessmentId: '99999999-9999-4999-8999-999999999999' }),
      },
    ]);
    const bundle = loadEvidenceBundle(files);
    expect(bundle.datasets.get('entra.securityDefaults')?.state).toBe('unavailable');
    expect(bundle.issues.some((i) => i.code === 'ENVELOPE_MISMATCH')).toBe(true);
  });

  it('marks schema-invalid data as unavailable with path-only messages', () => {
    const { files } = buildEvidencePackage(manifestBase(), [
      { path: 'evidence/entra/securityDefaults.json', envelope: envelope('entra.securityDefaults', { isEnabled: 'SECRET-LOOKING-VALUE' }) },
    ]);
    const bundle = loadEvidenceBundle(files);
    expect(bundle.datasets.get('entra.securityDefaults')?.state).toBe('unavailable');
    expect(bundle.files[0]?.schema).toBe('invalid');
    expect(JSON.stringify(bundle.files)).not.toContain('SECRET-LOOKING-VALUE');
  });

  it('ignores unknown datasets with a warning', () => {
    const { files } = buildEvidencePackage(manifestBase(), [{ path: 'evidence/entra/future.json', envelope: envelope('entra.futureDataset', {}) }]);
    const bundle = loadEvidenceBundle(files);
    expect(bundle.files[0]?.schema).toBe('unknown-dataset');
    expect(bundle.issues.some((i) => i.code === 'DATASET_UNKNOWN' && i.level === 'warning')).toBe(true);
  });

  it('keeps unusable collection statuses unavailable with the collector error', () => {
    const { files } = buildEvidencePackage(manifestBase(), [
      {
        path: 'evidence/entra/securityDefaults.json',
        envelope: envelope('entra.securityDefaults', null, {
          status: 'Unauthorized',
          errors: [{ code: 'Forbidden', message: 'Insufficient privileges (Policy.Read.All required).', target: null }],
        }),
      },
    ]);
    const bundle = loadEvidenceBundle(files);
    const ds = bundle.datasets.get('entra.securityDefaults');
    expect(ds?.state).toBe('unavailable');
    expect(ds?.reason).toContain('Unauthorized');
    expect(bundle.issues.some((i) => i.origin === 'collector' && i.code === 'Forbidden')).toBe(true);
  });

  it('marks Partial datasets as partial', () => {
    const { files } = buildEvidencePackage(manifestBase(), [
      { path: 'evidence/entra/securityDefaults.json', envelope: envelope('entra.securityDefaults', { isEnabled: true }, { status: 'Partial' }) },
    ]);
    expect(loadEvidenceBundle(files).datasets.get('entra.securityDefaults')?.state).toBe('partial');
  });

  it('computes the manifest hash', () => {
    const { files } = samplePackage();
    expect(loadEvidenceBundle(files).manifestSha256).toBe(sha256Hex(files.get(MANIFEST_FILE_NAME) ?? ''));
  });

  it('round-trips through a real ZIP archive', async () => {
    const { files } = samplePackage();
    const zip = await makeZip([...files.entries()].map(([name, data]) => ({ name, data })));
    const bundle = loadEvidenceBundle(await readZipPackage(zip));
    expect(bundle.integrityVerified).toBe(true);
    expect(bundle.datasets.size).toBe(2);
  });
});
