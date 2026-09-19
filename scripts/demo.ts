/**
 * Local end-to-end demonstration on sanitized, fictional data (`npm run demo`):
 *   sanitized environment -> collector-format evidence (ZIP) -> integrity and schema
 *   validation -> normalized inventory -> deterministic controls -> findings ->
 *   prioritization -> HTML/JSON reports -> comparison with a follow-up assessment.
 * Reports are written to ./out/demo (git-ignored).
 */
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import yazl from 'yazl';
import { compareAssessments, runAssessment } from '@adminsecops/engine';
import { CONTROL_LIBRARY } from '@adminsecops/controls';
import { loadEvidenceBundle, readZipPackage } from '@adminsecops/evidence';
import { buildJsonReport, renderHtmlReport, serializeJsonReport } from '@adminsecops/reporting';

const root = process.cwd();
const outDir = path.join(root, 'out', 'demo');

function files(dir: string, base = dir): Array<[string, Buffer]> {
  return readdirSync(dir).flatMap((e) => {
    const full = path.join(dir, e);
    return statSync(full).isDirectory() ? files(full, base) : [[path.relative(base, full).split(path.sep).join('/'), readFileSync(full)] as [string, Buffer]];
  });
}

function zip(dir: string): Promise<Buffer> {
  const z = new yazl.ZipFile();
  for (const [name, data] of files(dir)) z.addBuffer(data, name);
  z.end();
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    z.outputStream.on('data', (c: Buffer) => chunks.push(c)).on('end', () => resolve(Buffer.concat(chunks))).on('error', reject);
  });
}

async function assess(name: string) {
  const archive = await zip(path.join(root, 'fixtures', 'assessments', name));
  writeFileSync(path.join(outDir, `${name}.evidence.zip`), archive);
  const bundle = loadEvidenceBundle(await readZipPackage(archive));
  console.log(`\n[${name}] evidence package: ${bundle.files.length} files, integrity ${bundle.integrityVerified ? 'verified' : 'FAILED'}, ${bundle.datasets.size} datasets`);
  const result = runAssessment(bundle, CONTROL_LIBRARY);
  const s = result.summary.byStatus;
  console.log(`[${name}] ${result.results.length} controls: FAIL ${s.FAIL}, REVIEW ${s.REVIEW}, PASS ${s.PASS}, N/A ${s.NOT_APPLICABLE}, NOT ASSESSED ${s.NOT_ASSESSED}, ERROR ${s.ERROR}`);
  writeFileSync(path.join(outDir, `${name}-report.html`), renderHtmlReport(result));
  writeFileSync(path.join(outDir, `${name}-report.json`), serializeJsonReport(buildJsonReport(result)));
  return result;
}

mkdirSync(outDir, { recursive: true });
const before = await assess('contoso');
console.log('\nWhat should I fix first? (contoso)');
for (const f of before.findings.slice(0, 8)) console.log(`  ${f.priority.rank}. [${f.priority.tier}] ${f.severity}/${f.status} ${f.title} (${f.controlId})`);
const after = await assess('contoso-followup');
await assess('fabrikam');
const cmp = compareAssessments(before, after);
console.log(`\nContoso drift: ${cmp.direction}; resolved ${cmp.resolvedFindings.length}, new ${cmp.newFindings.length}, changed ${cmp.changedFindings.length}`);
for (const f of cmp.newFindings) console.log(`  new: ${f.title} (${f.controlId})`);
console.log(`\nReports written to ${outDir}`);
console.log('Start the dashboard with `npm start` and open http://localhost:4310 (use "Load sample" to explore the same data).');
