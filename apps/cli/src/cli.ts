import { existsSync, statSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { CONTROL_LIBRARY, CONTROL_LIBRARY_VERSION } from '@adminsecops/controls';
import {
  AdminSecOpsError,
  ENGINE_VERSION,
  PRODUCT_NAME,
  PRODUCT_TAGLINE,
  TECHNOLOGY_LABELS,
  safeJsonParse,
  toPublicErrorMessage,
} from '@adminsecops/core';
import { compareAssessments, runAssessment } from '@adminsecops/engine';
import { loadEvidenceBundle, readDirectoryPackage, readZipPackage, type EvidenceBundle } from '@adminsecops/evidence';
import { buildJsonReport, renderHtmlReport, reportFileName, serializeJsonReport } from '@adminsecops/reporting';
import { AssessmentResultSchema, listDatasetDefinitions, type AssessmentResult } from '@adminsecops/schemas';

export interface CliIo {
  out: (text: string) => void;
  err: (text: string) => void;
}

const USAGE = `${PRODUCT_NAME} ${ENGINE_VERSION} - ${PRODUCT_TAGLINE}

Usage:
  adminsecops assess <package.zip|evidence-dir> [--out <dir>] [--format html,json] [--force]
  adminsecops validate <package.zip|evidence-dir>
  adminsecops compare <baseline-report.json> <current-report.json>
  adminsecops controls [--json]
  adminsecops datasets
  adminsecops help

All processing is local. Evidence and reports are sensitive: store them securely.
`;

async function loadBundle(input: string): Promise<EvidenceBundle> {
  if (!existsSync(input)) throw new AdminSecOpsError('INPUT_NOT_FOUND', `Input not found: ${input}`);
  const files = statSync(input).isDirectory() ? await readDirectoryPackage(input) : await readZipPackage(await readFile(input));
  return loadEvidenceBundle(files);
}

async function readReport(file: string): Promise<AssessmentResult> {
  const json = safeJsonParse(await readFile(file), { label: path.basename(file), maxBytes: 200 * 1024 * 1024 });
  const candidate = typeof json === 'object' && json !== null && 'assessment' in json ? json.assessment : json;
  const parsed = AssessmentResultSchema.safeParse(candidate);
  if (!parsed.success) throw new AdminSecOpsError('REPORT_INVALID', `${path.basename(file)} is not an AdminSecOps JSON report.`);
  return parsed.data;
}

async function writeOutput(file: string, content: string, force: boolean): Promise<void> {
  if (existsSync(file) && !force) throw new AdminSecOpsError('OUTPUT_EXISTS', `${file} already exists (use --force to overwrite).`);
  await writeFile(file, content, { encoding: 'utf8', mode: 0o600 });
}

function summaryLines(result: AssessmentResult): string[] {
  const s = result.summary;
  const lines = [
    `Assessment ${result.assessmentId} (evidence collected ${result.assessedAt})`,
    `Evidence integrity: ${result.evidence.integrityVerified ? 'verified' : 'FAILED - some evidence was not used'}`,
    `Controls: ${s.controlsEvaluated} | FAIL ${s.byStatus.FAIL} | REVIEW ${s.byStatus.REVIEW} | PASS ${s.byStatus.PASS} | NOT APPLICABLE ${s.byStatus.NOT_APPLICABLE} | NOT ASSESSED ${s.byStatus.NOT_ASSESSED} | ERROR ${s.byStatus.ERROR}`,
    `Coverage (not a score): ${s.assessmentCoverage.assessed}/${s.assessmentCoverage.applicable} applicable controls assessed`,
    '',
    'What should I fix first?',
  ];
  for (const f of result.findings.slice(0, 10)) {
    lines.push(`  ${String(f.priority.rank).padStart(2)}. [${f.severity.toUpperCase()}/${f.status}] ${f.title} (${f.controlId}, ${f.affectedObjectCount} affected)`);
  }
  if (result.findings.length === 0) lines.push('  No findings. Check the not-assessed controls before concluding the environment is secure.');
  return lines;
}

export async function runCli(argv: readonly string[], io: CliIo): Promise<number> {
  const [command, ...rest] = argv;
  try {
    switch (command) {
      case 'assess': {
        const { values, positionals } = parseArgs({
          args: rest,
          allowPositionals: true,
          options: { out: { type: 'string' }, format: { type: 'string' }, force: { type: 'boolean' } },
        });
        const input = positionals[0];
        if (input === undefined) throw new AdminSecOpsError('USAGE', 'assess requires an evidence package path.');
        const formats = (values.format ?? 'html,json').split(',').map((f) => f.trim());
        if (formats.some((f) => f !== 'html' && f !== 'json')) throw new AdminSecOpsError('USAGE', 'format must be html, json or html,json.');
        const bundle = await loadBundle(input);
        const result = runAssessment(bundle, CONTROL_LIBRARY);
        const outDir = path.resolve(values.out ?? '.');
        await mkdir(outDir, { recursive: true });
        for (const line of summaryLines(result)) io.out(line);
        io.out('');
        if (formats.includes('html')) {
          const file = path.join(outDir, reportFileName(result, 'html'));
          await writeOutput(file, renderHtmlReport(result), values.force === true);
          io.out(`HTML report: ${file}`);
        }
        if (formats.includes('json')) {
          const file = path.join(outDir, reportFileName(result, 'json'));
          await writeOutput(file, serializeJsonReport(buildJsonReport(result)), values.force === true);
          io.out(`JSON report: ${file}`);
        }
        return result.evidence.integrityVerified ? 0 : 2;
      }
      case 'validate': {
        const input = rest[0];
        if (input === undefined) throw new AdminSecOpsError('USAGE', 'validate requires an evidence package path.');
        const bundle = await loadBundle(input);
        io.out(`Manifest: assessment ${bundle.manifest.assessmentId}, created ${bundle.manifest.createdAt}, collector ${bundle.manifest.collector.name} ${bundle.manifest.collector.version}`);
        for (const f of bundle.files) {
          io.out(`  ${f.integrity.padEnd(13)} ${f.schema.padEnd(15)} ${(f.collectionStatus ?? '-').padEnd(13)} ${f.path}${f.sensitiveContent ? '  [SECRET-LIKE CONTENT REJECTED]' : ''}`);
        }
        for (const issue of bundle.issues) io.out(`  ${issue.level.toUpperCase()} ${issue.code}: ${issue.message}`);
        io.out(bundle.integrityVerified ? 'Integrity: verified' : 'Integrity: FAILED');
        return bundle.integrityVerified ? 0 : 2;
      }
      case 'compare': {
        const [a, b] = rest;
        if (a === undefined || b === undefined) throw new AdminSecOpsError('USAGE', 'compare requires two JSON report files.');
        const comparison = compareAssessments(await readReport(a), await readReport(b));
        io.out(`Direction: ${comparison.direction}${comparison.sameEnvironment ? '' : ' (WARNING: assessments appear to be from different environments)'}`);
        io.out(`New findings (${comparison.newFindings.length}):`);
        for (const f of comparison.newFindings) io.out(`  + [${f.severity}] ${f.title} (${f.controlId})`);
        io.out(`Resolved findings (${comparison.resolvedFindings.length}):`);
        for (const f of comparison.resolvedFindings) io.out(`  - [${f.severity}] ${f.title} (${f.controlId})`);
        io.out(`Changed findings (${comparison.changedFindings.length}):`);
        for (const f of comparison.changedFindings) io.out(`  ~ ${f.title} (${f.changes.map((c) => `${c.field}: ${c.from} -> ${c.to}`).join(', ')})`);
        return 0;
      }
      case 'controls': {
        const { values } = parseArgs({ args: rest, options: { json: { type: 'boolean' } } });
        if (values.json === true) {
          io.out(JSON.stringify({ libraryVersion: CONTROL_LIBRARY_VERSION, controls: CONTROL_LIBRARY.map((c) => c.metadata) }, null, 2));
          return 0;
        }
        io.out(`Control library ${CONTROL_LIBRARY_VERSION}: ${CONTROL_LIBRARY.length} controls`);
        for (const c of [...CONTROL_LIBRARY].sort((x, y) => x.metadata.id.localeCompare(y.metadata.id))) {
          io.out(`  ${c.metadata.id.padEnd(16)} ${c.metadata.severity.padEnd(9)} ${TECHNOLOGY_LABELS[c.metadata.technology].padEnd(17)} ${c.metadata.title}`);
        }
        return 0;
      }
      case 'datasets': {
        for (const d of listDatasetDefinitions()) {
          io.out(`${d.id} (${d.module}) - ${d.title}`);
          io.out(`    permissions: ${d.permissions.join('; ')}`);
        }
        return 0;
      }
      case undefined:
      case 'help':
      case '--help':
      case '-h':
        io.out(USAGE);
        return 0;
      default:
        io.err(`Unknown command: ${command}\n\n${USAGE}`);
        return 64;
    }
  } catch (error) {
    io.err(`Error: ${toPublicErrorMessage(error)}`);
    return error instanceof AdminSecOpsError && error.code === 'USAGE' ? 64 : 1;
  }
}
