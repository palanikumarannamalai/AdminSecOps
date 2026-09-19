import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { makeZip } from '../../../packages/evidence/test/zip.js';
import { samplePackage } from '../../../packages/evidence/test/sample.js';
import { runCli } from './cli.js';

function capture() {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (t: string) => out.push(t), err: (t: string) => err.push(t) }, out, err };
}

describe('CLI', () => {
  let dir: string | undefined;
  afterEach(() => {
    if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
  });

  async function writeZip(): Promise<string> {
    dir = mkdtempSync(path.join(tmpdir(), 'aso-cli-'));
    const { files } = samplePackage();
    const file = path.join(dir, 'package.zip');
    writeFileSync(file, await makeZip([...files.entries()].map(([name, data]) => ({ name, data }))));
    return file;
  }

  it('assesses a package and writes HTML and JSON reports', async () => {
    const zip = await writeZip();
    const c = capture();
    const code = await runCli(['assess', zip, '--out', path.join(dir!, 'out')], c.io);
    expect(code).toBe(0);
    expect(c.out.join('\n')).toContain('What should I fix first?');
    const outputs = readdirSync(path.join(dir!, 'out')).sort();
    expect(outputs).toHaveLength(2);
    expect(outputs[0]).toMatch(/\.html$/);
    const json = JSON.parse(readFileSync(path.join(dir!, 'out', outputs[1]!), 'utf8'));
    expect(json.reportType).toBe('adminsecops.assessment');

    // refuses to overwrite without --force
    const again = capture();
    expect(await runCli(['assess', zip, '--out', path.join(dir!, 'out')], again.io)).toBe(1);
    expect(again.err.join('')).toContain('already exists');

    // compare the report with itself
    const cmp = capture();
    const jsonPath = path.join(dir!, 'out', outputs[1]!);
    expect(await runCli(['compare', jsonPath, jsonPath], cmp.io)).toBe(0);
    expect(cmp.out[0]).toContain('unchanged');
  });

  it('validates packages', async () => {
    const zip = await writeZip();
    const c = capture();
    expect(await runCli(['validate', zip], c.io)).toBe(0);
    expect(c.out.join('\n')).toContain('Integrity: verified');
  });

  it('lists controls and datasets', async () => {
    const c = capture();
    expect(await runCli(['controls'], c.io)).toBe(0);
    expect(c.out.join('\n')).toContain('ENTRA-CA-001');
    const d = capture();
    expect(await runCli(['datasets'], d.io)).toBe(0);
    expect(d.out.join('\n')).toContain('entra.conditionalAccessPolicies');
  });

  it('reports errors without stack traces and uses usage exit codes', async () => {
    const c = capture();
    expect(await runCli(['assess', path.join(tmpdir(), 'does-not-exist.zip')], c.io)).toBe(1);
    expect(c.err[0]).toMatch(/^Error: Input not found/);
    expect(await runCli(['assess'], capture().io)).toBe(64);
    expect(await runCli(['bogus'], capture().io)).toBe(64);
  });
});
