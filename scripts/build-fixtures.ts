/**
 * Regenerate the sanitized sample assessment fixtures under fixtures/assessments.
 *
 *   npx tsx scripts/build-fixtures.ts     (or: npm run fixtures)
 *
 * Output is byte-for-byte deterministic: each fixture directory is deleted and
 * rewritten with the exact bytes produced by buildEvidencePackage, so the SHA-256
 * values in evidence-manifest.json always match the files.
 */
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { FIXTURES_ROOT, buildFixturePackages } from './fixtures/index.js';

const repoRoot = path.resolve(import.meta.dirname, '..');

function main(): void {
  const packages = buildFixturePackages();
  for (const pkg of packages) {
    const target = path.join(repoRoot, FIXTURES_ROOT, pkg.directory);
    rmSync(target, { recursive: true, force: true });
    const paths = [...pkg.files.keys()].sort();
    for (const relative of paths) {
      const bytes = pkg.files.get(relative);
      if (bytes === undefined) continue;
      const destination = path.join(target, ...relative.split('/'));
      mkdirSync(path.dirname(destination), { recursive: true });
      writeFileSync(destination, bytes);
    }
    const datasets = pkg.environment.datasets;
    const byStatus = new Map<string, number>();
    for (const d of datasets) byStatus.set(d.status, (byStatus.get(d.status) ?? 0) + 1);
    const statusText = [...byStatus.entries()].map(([s, n]) => `${s} ${n}`).join(', ');
    console.log(`${FIXTURES_ROOT}/${pkg.directory}: ${paths.length} files, ${datasets.length} datasets (${statusText})`);
  }
}

main();
