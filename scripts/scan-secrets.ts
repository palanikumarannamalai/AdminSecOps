/**
 * Repository hygiene scan (run in CI and before commits: `npm run scan:secrets`).
 * - Scans every git-tracked file for secret-looking content.
 * - Applies the evidence secret detector to every tracked JSON file.
 * - Fails if assessment output (ZIPs, collector output folders) is tracked.
 * - Checks that sample data uses only reserved/fictional domains.
 * Exits non-zero on any problem. Prints file paths and rule names only, never values.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { findSensitiveContent, safeJsonParse } from '@adminsecops/core';

const TEXT_PATTERNS: Array<{ id: string; pattern: RegExp }> = [
  { id: 'pem-private-key', pattern: /-----BEGIN (?:RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY-----/ },
  { id: 'jwt', pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { id: 'azure-storage-key', pattern: /AccountKey=[A-Za-z0-9+/=]{40,}/ },
  { id: 'entra-client-secret', pattern: /\b[A-Za-z0-9_~.-]{3}8Q~[A-Za-z0-9_~.-]{31,34}\b/ },
  { id: 'aws-access-key', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'github-token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { id: 'gpp-cpassword', pattern: /cpassword="[A-Za-z0-9+/=]{16,}"/i },
  { id: 'sas-signature', pattern: /[?&]sig=[A-Za-z0-9%+/=]{30,}/ },
];

/** Files allowed to contain detector test patterns (the detectors and their tests). */
const PATTERN_ALLOWLIST = [
  /^packages\/core\/src\/sensitive\.ts$/,
  /^packages\/core\/src\/core\.test\.ts$/,
  /^packages\/evidence\/src\/evidence\.test\.ts$/,
  /^scripts\/scan-secrets\.ts$/,
  /^collectors\/powershell\/tests\//,
  /^collectors\/powershell\/core\/.*Sensitive.*\.ps1$/i,
];

const FORBIDDEN_PATHS = [/\.zip$/i, /(^|\/)AdminSecOps-Assessment[^/]*\//i, /(^|\/)\.env$/, /\.(pfx|p12|pem|key)$/i];
const FIXTURE_DOMAIN = /\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(com|net|org|io|gov|edu)\b/gi;
const ALLOWED_REAL_DOMAINS = [
  /\.onmicrosoft\.com$/i,
  /^(graph|login|management|learn|www)\.microsoft\.com$/i,
  /^management\.azure\.com$/i,
  /^microsoft\.com$/i,
  /^(outlook|protection\.outlook)\.com$/i,
  /\.protection\.outlook\.com$/i,
  /^spf\.protection\.outlook\.com$/i,
];

const files = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
const problems: string[] = [];

for (const file of files) {
  if (FORBIDDEN_PATHS.some((p) => p.test(file)) && !file.endsWith('.fixture.zip')) {
    problems.push(`${file}: assessment output or key material must not be committed`);
    continue;
  }
  let size: number;
  try {
    size = statSync(file).size;
  } catch {
    continue; // deleted in the working tree
  }
  if (size > 20 * 1024 * 1024) continue;
  const buffer = readFileSync(file);
  if (buffer.includes(0)) continue; // binary
  const text = buffer.toString('utf8');

  if (!PATTERN_ALLOWLIST.some((p) => p.test(file))) {
    for (const { id, pattern } of TEXT_PATTERNS) {
      if (pattern.test(text)) problems.push(`${file}: matches secret pattern '${id}'`);
    }
  }

  if (file.endsWith('.json') && (file.startsWith('fixtures/') || file.startsWith('collectors/'))) {
    try {
      const findings = findSensitiveContent(safeJsonParse(buffer, { label: file }));
      for (const f of findings) problems.push(`${file}: ${f.path} (${f.rule})`);
    } catch {
      problems.push(`${file}: invalid JSON`);
    }
    for (const match of text.matchAll(FIXTURE_DOMAIN)) {
      const domain = match[0].toLowerCase();
      if (!ALLOWED_REAL_DOMAINS.some((p) => p.test(domain))) problems.push(`${file}: non-fictional domain '${domain}' in sample data`);
    }
  }
}

if (problems.length > 0) {
  process.stderr.write(`Secret / hygiene scan found ${problems.length} problem(s):\n${[...new Set(problems)].map((p) => `  - ${p}`).join('\n')}\n`);
  process.exit(1);
}
process.stdout.write(`Secret / hygiene scan passed (${files.length} tracked files).\n`);
