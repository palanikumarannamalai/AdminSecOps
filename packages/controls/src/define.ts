import type { Confidence } from '@adminsecops/core';
import type { Fact, Inventory } from '@adminsecops/inventory';
import {
  ControlMetadataSchema,
  isKnownDatasetId,
  type AffectedObject,
  type ControlMetadata,
  type ControlMetadataInput,
  type DatasetData,
  type DatasetId,
  type ObservedFact,
} from '@adminsecops/schemas';

/** Thrown by ControlContext when a control reads a dataset that is not available. */
export class EvidenceUnavailableError extends Error {
  readonly datasetId: string;
  readonly reason: string;
  constructor(datasetId: string, reason: string) {
    super(`Evidence ${datasetId} is not available: ${reason}`);
    this.name = 'EvidenceUnavailableError';
    this.datasetId = datasetId;
    this.reason = reason;
  }
}

/** Read-only evaluation context handed to a control. */
export class ControlContext {
  readonly inventory: Inventory;
  private readonly parameters: Readonly<Record<string, number | string | boolean>>;
  private readonly used = new Set<string>();

  constructor(inventory: Inventory, parameters: Readonly<Record<string, number | string | boolean>>) {
    this.inventory = inventory;
    this.parameters = parameters;
  }

  /** The point in time the evidence describes. Controls must use this instead of the wall clock. */
  get assessedAt(): Date {
    return this.inventory.assessedAt;
  }

  /**
   * Validated payload of a dataset. Throws EvidenceUnavailableError when the dataset
   * is missing or unusable, which the engine converts to NOT_ASSESSED (never PASS).
   */
  data<K extends DatasetId>(id: K): DatasetData<K> {
    const fact = this.inventory.get(id);
    this.used.add(id);
    if (!fact.available) throw new EvidenceUnavailableError(id, fact.reason);
    return fact.data;
  }

  /** Fact access for optional evidence where the control handles absence itself. */
  fact<K extends DatasetId>(id: K): Fact<DatasetData<K>> {
    this.used.add(id);
    return this.inventory.get(id);
  }

  /** Numeric control parameter (declared in metadata.evaluation.parameters). */
  num(name: string): number {
    const value = this.parameters[name];
    if (typeof value !== 'number') throw new Error(`Control parameter ${name} is not a number`);
    return value;
  }

  str(name: string): string {
    const value = this.parameters[name];
    if (typeof value !== 'string') throw new Error(`Control parameter ${name} is not a string`);
    return value;
  }

  /** Datasets read during evaluation (used for evidence references). */
  usedDatasets(): readonly string[] {
    return [...this.used];
  }
}

export type OutcomeStatus = 'PASS' | 'FAIL' | 'REVIEW' | 'NOT_APPLICABLE' | 'NOT_ASSESSED';

export interface EvaluationOutcome {
  status: OutcomeStatus;
  /** Plain-language reason for the status. Never include secrets. */
  reason: string;
  observed: { summary: string; facts?: ObservedFact[] };
  affectedObjects?: AffectedObject[];
  notes?: string[];
  /** Optional per-result confidence; the engine never raises confidence above the control's. */
  confidence?: Confidence;
}

export type Applicability = { applicable: true } | { applicable: false; reason: string };

export interface ControlImplementation {
  /**
   * Decide whether the control applies to this environment (e.g. licence present,
   * hybrid identity in use). Reading unavailable evidence here yields NOT_ASSESSED.
   */
  applies?: (ctx: ControlContext) => Applicability;
  evaluate: (ctx: ControlContext) => EvaluationOutcome;
}

export interface ControlDefinition extends ControlImplementation {
  readonly metadata: ControlMetadata;
}

/**
 * Define a control. Metadata is validated when the library loads, so an invalid
 * control (missing rollback, unknown dataset, bad reference URL...) fails the build
 * and the test suite rather than producing an incomplete finding at runtime.
 */
export function defineControl(input: ControlMetadataInput & ControlImplementation): ControlDefinition {
  const { applies, evaluate, ...metadataInput } = input;
  const parsed = ControlMetadataSchema.safeParse(metadataInput);
  if (!parsed.success) {
    const detail = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid control metadata for ${String(metadataInput.id)}: ${detail}`);
  }
  const metadata = parsed.data;
  for (const id of [...metadata.requiredEvidence, ...metadata.optionalEvidence]) {
    if (!isKnownDatasetId(id)) throw new Error(`Control ${metadata.id} references unknown dataset ${id}`);
  }
  return applies === undefined ? { metadata, evaluate } : { metadata, applies, evaluate };
}
