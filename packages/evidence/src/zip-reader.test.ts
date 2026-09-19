import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { AdminSecOpsError } from '@adminsecops/core';
import { loadEvidenceBundle } from './bundle.js';
import { DEFAULT_PACKAGE_LIMITS } from './limits.js';
import { readZipPackage } from './package-reader.js';
import { crc32, readZipBytes } from './zip-reader.js';
import { makeZip, patchName } from '../test/zip.js';
import { samplePackage } from '../test/sample.js';

function rejectsWith(fn: () => unknown, code: string): void {
  let error: unknown;
  try {
    fn();
  } catch (e) {
    error = e;
  }
  expect(error, `expected ${code}`).toBeInstanceOf(AdminSecOpsError);
  expect((error as AdminSecOpsError).code).toBe(code);
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

function fixtureEntries(name: string): Array<{ name: string; data: Uint8Array }> {
  const base = path.join(root, 'fixtures', 'assessments', name);
  const out: Array<{ name: string; data: Uint8Array }> = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir)) {
      const full = path.join(dir, e);
      if (statSync(full).isDirectory()) walk(full);
      else out.push({ name: path.relative(base, full).split(path.sep).join('/'), data: readFileSync(full) });
    }
  };
  walk(base);
  return out;
}

describe('readZipBytes (browser-compatible reader)', () => {
  it('computes CRC-32 correctly', () => {
    expect(crc32(new TextEncoder().encode('123456789'))).toBe(0xcbf43926);
  });

  it('reads deflated and stored entries and matches the Node.js reader byte for byte', async () => {
    const zip = await makeZip([
      ...fixtureEntries('contoso'),
      { name: 'logs/stored.json', data: '{"a":1}', compress: false },
    ]);
    const browser = readZipBytes(zip);
    const node = await readZipPackage(zip);
    expect([...browser.keys()].sort()).toEqual([...node.keys()].sort());
    for (const [name, bytes] of node) expect(Buffer.from(browser.get(name)!).equals(Buffer.from(bytes))).toBe(true);
    const bundle = loadEvidenceBundle(browser);
    expect(bundle.integrityVerified).toBe(true);
    expect(bundle.datasets.size).toBeGreaterThan(50);
  });

  it('round-trips a generated evidence package', async () => {
    const { files } = samplePackage();
    const zip = await makeZip([...files.entries()].map(([name, data]) => ({ name, data })));
    expect(loadEvidenceBundle(readZipBytes(zip)).integrityVerified).toBe(true);
  });

  it('rejects non-ZIP, empty and truncated data', async () => {
    rejectsWith(() => readZipBytes(new TextEncoder().encode('not a zip at all, definitely')), 'PACKAGE_NOT_ZIP');
    rejectsWith(() => readZipBytes(new Uint8Array(0)), 'PACKAGE_NOT_ZIP');
    const zip = await makeZip([{ name: 'a.json', data: '{"a":1}' }]);
    expect(() => readZipBytes(zip.subarray(0, zip.length - 30))).toThrow(AdminSecOpsError);
    expect(() => readZipBytes(zip.subarray(40))).toThrow(AdminSecOpsError);
  });

  it('rejects path traversal and absolute paths', async () => {
    const traversal = patchName(await makeZip([{ name: 'aa/evil.json', data: '{}' }]), 'aa/evil.json', '../evil.json');
    rejectsWith(() => readZipBytes(traversal), 'PACKAGE_UNSAFE_PATH');
    const absolute = patchName(await makeZip([{ name: 'xetc/passwd', data: 'x' }]), 'xetc/passwd', '/etc/passwd');
    rejectsWith(() => readZipBytes(absolute), 'PACKAGE_UNSAFE_PATH');
  });

  it('rejects symbolic links and duplicates', async () => {
    rejectsWith(() => readZipBytes(Buffer.from([])), 'PACKAGE_NOT_ZIP');
    const link = await makeZip([{ name: 'evidence/link.json', data: '/etc/passwd', mode: 0o120777 }]);
    rejectsWith(() => readZipBytes(link), 'PACKAGE_SYMLINK');
    const dup = patchName(
      await makeZip([
        { name: 'a1.json', data: '{}' },
        { name: 'a2.json', data: '{}' },
      ]),
      'a2.json',
      'a1.json',
    );
    rejectsWith(() => readZipBytes(dup), 'PACKAGE_DUPLICATE_ENTRY');
  });

  it('rejects encrypted entries', async () => {
    const zip = Buffer.from(await makeZip([{ name: 'a.json', data: '{"a":1}' }]));
    const central = zip.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    zip.writeUInt16LE(zip.readUInt16LE(central + 8) | 0x1, central + 8);
    rejectsWith(() => readZipBytes(zip), 'PACKAGE_ENCRYPTED_ENTRY');
  });

  it('rejects zip bombs by ratio and by actual inflated size', async () => {
    const bomb = await makeZip([{ name: 'bomb.json', data: Buffer.alloc(8 * 1024 * 1024, 0x20) }]);
    rejectsWith(() => readZipBytes(bomb), 'PACKAGE_COMPRESSION_RATIO');
    // Lie about the uncompressed size: the reader must stop on the real inflated size.
    const lie = Buffer.from(await makeZip([{ name: 'b.json', data: Buffer.alloc(200_000, 0x41) }]));
    const central = lie.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
    lie.writeUInt32LE(100, central + 24);
    rejectsWith(() => readZipBytes(lie, { ...DEFAULT_PACKAGE_LIMITS, maxFileBytes: 1000 }), 'PACKAGE_FILE_TOO_LARGE');
    expect(() => readZipBytes(lie)).toThrow(/corrupt or unsupported/);
  });

  it('enforces entry count, file size, archive size and total size limits', async () => {
    const zip = await makeZip([
      { name: 'a.json', data: 'x'.repeat(100), compress: false },
      { name: 'b.json', data: 'y'.repeat(100), compress: false },
    ]);
    rejectsWith(() => readZipBytes(zip, { ...DEFAULT_PACKAGE_LIMITS, maxEntries: 1 }), 'PACKAGE_TOO_MANY_ENTRIES');
    rejectsWith(() => readZipBytes(zip, { ...DEFAULT_PACKAGE_LIMITS, maxFileBytes: 50 }), 'PACKAGE_FILE_TOO_LARGE');
    rejectsWith(() => readZipBytes(zip, { ...DEFAULT_PACKAGE_LIMITS, maxArchiveBytes: 10 }), 'PACKAGE_TOO_LARGE');
    rejectsWith(() => readZipBytes(zip, { ...DEFAULT_PACKAGE_LIMITS, maxTotalBytes: 150 }), 'PACKAGE_TOO_LARGE');
  });

  it('detects corrupted entry data by CRC-32', async () => {
    const zip = Buffer.from(await makeZip([{ name: 'a.json', data: '{"value":"abcdefgh"}', compress: false }]));
    const at = zip.indexOf(Buffer.from('abcdefgh'));
    zip[at] = 0x7a;
    expect(() => readZipBytes(zip)).toThrow(/corrupt or unsupported/);
  });

  it('rejects ZIP64 markers', async () => {
    const zip = Buffer.from(await makeZip([{ name: 'a.json', data: '{}' }]));
    const eocd = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    zip.writeUInt32LE(0xffffffff, eocd + 16);
    expect(() => readZipBytes(zip)).toThrow(/corrupt or unsupported/);
  });
});

describe('browser entry points', () => {
  // Follow relative and workspace imports from the browser entry points and fail on any Node.js
  // built-in or the Node-only ZIP library, so hosted mode can never silently depend on them.
  const packagesDir = path.join(root, 'packages');
  const workspace: Record<string, string> = {
    '@adminsecops/core': 'core/src/index.ts',
    '@adminsecops/schemas': 'schemas/src/index.ts',
    '@adminsecops/inventory': 'inventory/src/index.ts',
    '@adminsecops/controls': 'controls/src/index.ts',
    '@adminsecops/reporting': 'reporting/src/index.ts',
    '@adminsecops/evidence/browser': 'evidence/src/browser.ts',
    '@adminsecops/engine/browser': 'engine/src/browser.ts',
  };
  const forbidden = /^(node:|fs$|path$|crypto$|stream$|zlib$|child_process$|yauzl$|os$)/;

  function importsOf(file: string): string[] {
    const text = readFileSync(file, 'utf8');
    return [...text.matchAll(/(?:import|export)\s[^'"]*?from\s+['"]([^'"]+)['"]/g)].map((m) => m[1]!);
  }

  function walk(entry: string): { visited: Set<string>; violations: string[] } {
    const visited = new Set<string>();
    const violations: string[] = [];
    const stack = [entry];
    while (stack.length > 0) {
      const file = stack.pop()!;
      if (visited.has(file)) continue;
      visited.add(file);
      for (const spec of importsOf(file)) {
        if (forbidden.test(spec)) violations.push(`${path.relative(root, file)} imports ${spec}`);
        else if (spec.startsWith('.')) stack.push(path.resolve(path.dirname(file), spec.replace(/\.js$/, '.ts')));
        else if (spec.startsWith('@adminsecops/')) {
          const target = workspace[spec];
          if (target === undefined) violations.push(`${path.relative(root, file)} imports non-browser entry ${spec}`);
          else stack.push(path.join(packagesDir, target));
        }
      }
    }
    return { visited, violations };
  }

  it.each(['engine/src/browser.ts', 'evidence/src/browser.ts', 'reporting/src/index.ts'])('%s has no Node-only imports', (entry) => {
    const { visited, violations } = walk(path.join(packagesDir, entry));
    expect(visited.size).toBeGreaterThan(3);
    expect(violations).toEqual([]);
  });
});
