/**
 * Sanitized sample assessment fixtures. `buildFixturePackages` produces the exact
 * bytes of every fixture evidence package in memory (used by scripts/build-fixtures.ts
 * to write them and by tests/fixtures.test.ts to check the committed files are
 * current). Every payload is validated with the real dataset schema and scanned for
 * secret-like content; any problem throws.
 */
import { findSensitiveContent, isUsableCollectionStatus } from '@adminsecops/core';
import { buildEvidencePackage, summarizeZodIssues, type PackageFiles } from '@adminsecops/evidence';
import { EvidenceEnvelopeSchema, EvidenceManifestSchema, listDatasetDefinitions, exchangeInboxRules, exchangeTransportRules } from '@adminsecops/schemas';
import { type EnvironmentFixture, envelopeFor, evidencePath, manifestBase, uncollected, message } from './common.js';
import { contosoFollowupEnvironment } from './contoso-followup.js';
import { contosoInitialEnvironment } from './contoso-initial.js';
import { fabrikamEnvironment } from './fabrikam.js';

export { CONTOSO_ASSESSMENT_ID } from './contoso-initial.js';
export { CONTOSO_FOLLOWUP_ASSESSMENT_ID } from './contoso-followup.js';
export { FABRIKAM_ASSESSMENT_ID } from './fabrikam.js';

/** Location of the fixtures relative to the repository root. */
export const FIXTURES_ROOT = 'fixtures/assessments';

export function fixtureEnvironments(): EnvironmentFixture[] {
  return [contosoInitialEnvironment(), contosoFollowupEnvironment(), fabrikamEnvironment()].map((env) =>
    env.modules.some((module) => module.module === 'Exchange') ? {
      ...env,
      datasets: [...env.datasets, ...[exchangeInboxRules, exchangeTransportRules].map((definition) =>
        uncollected(definition, 'NotCollected', { warnings: [message('HOSTED_RULE_COLLECTION', 'This local sample does not collect rules; use the hosted Exchange connector.')] }))],
    } : env);

}

export interface FixturePackage {
  directory: string;
  environment: EnvironmentFixture;
  files: PackageFiles;
}

function fail(env: EnvironmentFixture, detail: string): never {
  throw new Error(`Fixture "${env.directory}": ${detail}`);
}

function validate(env: EnvironmentFixture): void {
  const seen = new Set<string>();
  const moduleNames = new Set(env.modules.map((m) => m.module));
  for (const fixture of env.datasets) {
    const { definition } = fixture;
    if (seen.has(definition.id)) fail(env, `dataset ${definition.id} is defined twice`);
    seen.add(definition.id);
    if (!moduleNames.has(definition.module)) fail(env, `dataset ${definition.id} belongs to module ${definition.module}, which was not run`);
    if (isUsableCollectionStatus(fixture.status)) {
      const result = definition.schema.safeParse(fixture.data);
      if (!result.success) {
        fail(env, `dataset ${definition.id} does not match its schema: ${summarizeZodIssues(result.error).join('; ')}`);
      }
      if (fixture.status === 'Partial' && fixture.errors.length === 0) fail(env, `dataset ${definition.id} is Partial without errors`);
    } else {
      if (fixture.data !== null) fail(env, `dataset ${definition.id} has status ${fixture.status} but data is not null`);
      if (fixture.errors.length === 0 && fixture.warnings.length === 0) {
        fail(env, `dataset ${definition.id} has status ${fixture.status} but no explanatory message`);
      }
    }
  }
}

/** Build one environment's evidence package, failing loudly on any contract violation. */
export function buildFixturePackage(env: EnvironmentFixture): FixturePackage {
  validate(env);
  const inputs = env.datasets.map((fixture) => {
    const envelope = envelopeFor(env, fixture);
    const parsed = EvidenceEnvelopeSchema.safeParse(envelope);
    if (!parsed.success) fail(env, `envelope for ${fixture.definition.id} is invalid: ${summarizeZodIssues(parsed.error).join('; ')}`);
    const sensitive = findSensitiveContent(envelope);
    if (sensitive.length > 0) {
      fail(env, `envelope for ${fixture.definition.id} contains secret-like content at ${sensitive.map((s) => s.path).join(', ')}`);
    }
    return { path: evidencePath(fixture.definition), envelope };
  });
  const { files, manifest } = buildEvidencePackage(manifestBase(env), inputs);
  const manifestCheck = EvidenceManifestSchema.safeParse(manifest);
  if (!manifestCheck.success) fail(env, `manifest is invalid: ${summarizeZodIssues(manifestCheck.error).join('; ')}`);
  return { directory: env.directory, environment: env, files };
}

/** Build every fixture package. Contoso must cover every dataset known to the engine. */
export function buildFixturePackages(): FixturePackage[] {
  const packages = fixtureEnvironments().map(buildFixturePackage);
  const contoso = packages.find((p) => p.directory === 'contoso');
  const covered = new Set(contoso?.environment.datasets.map((d) => d.definition.id));
  const missing = listDatasetDefinitions().filter((d) => !covered.has(d.id));
  if (missing.length > 0) {
    throw new Error(`Fixture "contoso" must include every dataset; missing: ${missing.map((d) => d.id).join(', ')}`);
  }
  return packages;
}
