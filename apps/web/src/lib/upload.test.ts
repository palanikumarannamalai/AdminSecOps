import { describe, expect, it } from 'vitest';
import { MAX_UPLOAD_BYTES, validatePackageFile } from './upload';
import { safeHttpsUrl } from './url';

describe('validatePackageFile', () => {
  it('accepts a zip within the size limit', () => {
    expect(validatePackageFile({ name: 'AdminSecOps-Evidence.ZIP', size: 1024 })).toEqual({ ok: true });
    expect(validatePackageFile({ name: 'e.zip', size: MAX_UPLOAD_BYTES })).toEqual({ ok: true });
  });

  it('requires a file', () => {
    expect(validatePackageFile(undefined)).toMatchObject({ ok: false });
  });

  it('rejects other extensions', () => {
    const result = validatePackageFile({ name: 'evidence.json', size: 10 });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.message).toContain('not a .zip file');
    expect(validatePackageFile({ name: 'evidence.zip.exe', size: 10 }).ok).toBe(false);
  });

  it('rejects empty and oversized files', () => {
    expect(validatePackageFile({ name: 'e.zip', size: 0 }).ok).toBe(false);
    const result = validatePackageFile({ name: 'e.zip', size: MAX_UPLOAD_BYTES + 1 });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.message).toContain('100 MB');
  });
});

describe('safeHttpsUrl', () => {
  it('allows https only', () => {
    expect(safeHttpsUrl('https://learn.microsoft.com/en-us/entra/')).toBe('https://learn.microsoft.com/en-us/entra/');
    expect(safeHttpsUrl('http://example.com')).toBeNull();
    expect(safeHttpsUrl('javascript:alert(1)')).toBeNull();
    expect(safeHttpsUrl('data:text/html,<script>alert(1)</script>')).toBeNull();
    expect(safeHttpsUrl('//evil.example')).toBeNull();
    expect(safeHttpsUrl('https://user:pass@example.com')).toBeNull();
    expect(safeHttpsUrl(null)).toBeNull();
  });
});
