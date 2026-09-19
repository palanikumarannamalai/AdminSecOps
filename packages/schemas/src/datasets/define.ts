import type { z } from 'zod';
import type { CollectorModule, Technology } from '@adminsecops/core';
import type { EvidenceSource } from '../evidence.js';

/**
 * Classification of personal data present in a dataset (see docs/PRIVACY.md).
 * - none: configuration only.
 * - identifiers: names / UPNs / account names of users, groups or devices.
 * - identifiers-and-activity: identifiers plus activity metadata such as last sign-in time.
 */
export type PersonalDataClass = 'none' | 'identifiers' | 'identifiers-and-activity';

/**
 * A dataset is the unit of evidence: one collector output file with one schema.
 * The schema is the contract between the PowerShell collectors and the engine.
 * Unknown properties are stripped during validation, so data a collector sends
 * that is not declared here never reaches controls, storage or reports.
 */
export interface DatasetDefinition<S extends z.ZodType = z.ZodType, Id extends string = string> {
  readonly id: Id;
  readonly module: CollectorModule;
  readonly technology: Technology;
  readonly title: string;
  readonly description: string;
  readonly source: EvidenceSource['system'];
  /** Read operations the collector performs to produce this dataset. */
  readonly operations: readonly string[];
  /** Least-privilege permissions or roles needed to collect this dataset. */
  readonly permissions: readonly string[];
  /** Licence or feature prerequisites; absence normally yields status NotApplicable. */
  readonly prerequisites?: readonly string[];
  readonly personalData: PersonalDataClass;
  readonly schema: S;
}

export function defineDataset<const Id extends string, S extends z.ZodType>(
  definition: DatasetDefinition<S, Id>,
): DatasetDefinition<S, Id> {
  return definition;
}
