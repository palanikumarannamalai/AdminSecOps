import type { CollectionStatus } from '@adminsecops/core';
import type { EvidenceBundle, LoadedDataset } from '@adminsecops/evidence/browser';
import {
  getDatasetDefinition,
  type DatasetData,
  type DatasetId,
  type EvidenceReference,
  type ManifestEnvironment,
} from '@adminsecops/schemas';

/** Evidence for a dataset that can be evaluated. */
export interface AvailableFact<T> {
  readonly available: true;
  /** True when the collector reported Partial collection: some objects may be missing. */
  readonly partial: boolean;
  readonly data: T;
  readonly reference: EvidenceReference;
}

/** Evidence that cannot be evaluated, with the reason. */
export interface UnavailableFact {
  readonly available: false;
  readonly reason: string;
  readonly collectionStatus: CollectionStatus | null;
  readonly reference: EvidenceReference;
}

export type Fact<T> = AvailableFact<T> | UnavailableFact;

export interface InventoryInit {
  assessmentId: string;
  /** Point in time the evidence describes (manifest createdAt). Controls use this, never the wall clock. */
  assessedAt: Date;
  environment: ManifestEnvironment;
  datasets: ReadonlyMap<string, LoadedDataset>;
}

/**
 * Normalized, typed and read-only view of validated evidence. Controls read facts
 * only through this interface; a dataset that is missing, failed, unauthorized or
 * invalid is returned as an UnavailableFact so it can never be mistaken for a
 * compliant configuration.
 */
export class Inventory {
  readonly assessmentId: string;
  readonly assessedAt: Date;
  readonly environment: ManifestEnvironment;
  private readonly datasets: ReadonlyMap<string, LoadedDataset>;

  constructor(init: InventoryInit) {
    this.assessmentId = init.assessmentId;
    this.assessedAt = init.assessedAt;
    this.environment = init.environment;
    this.datasets = init.datasets;
  }

  static fromBundle(bundle: EvidenceBundle): Inventory {
    return new Inventory({
      assessmentId: bundle.manifest.assessmentId,
      assessedAt: new Date(bundle.manifest.createdAt),
      environment: bundle.manifest.environment,
      datasets: bundle.datasets,
    });
  }

  get<K extends DatasetId>(id: K): Fact<DatasetData<K>> {
    const loaded = this.datasets.get(id);
    if (loaded === undefined) {
      return {
        available: false,
        reason: `Dataset ${id} is not present in the evidence package (the collector module was not run or the dataset was not collected).`,
        collectionStatus: null,
        reference: missingReference(id),
      };
    }
    if (loaded.state === 'unavailable') {
      return {
        available: false,
        reason: loaded.reason,
        collectionStatus: loaded.collectionStatus,
        reference: loaded.reference,
      };
    }
    return {
      available: true,
      partial: loaded.state === 'partial',
      data: loaded.data as DatasetData<K>,
      reference: loaded.reference,
    };
  }

  /** Evidence reference for a dataset regardless of availability. */
  reference(id: DatasetId): EvidenceReference {
    return this.datasets.get(id)?.reference ?? missingReference(id);
  }

  /** Loaded datasets, including unavailable ones (for availability reporting). */
  loadedDatasets(): readonly LoadedDataset[] {
    return [...this.datasets.values()];
  }
}

function missingReference(datasetId: string): EvidenceReference {
  return { datasetId, path: null, sha256: null, collectedAt: null, status: null, source: null };
}

/** Title of a dataset for user-facing messages. */
export function datasetTitle(id: string): string {
  return getDatasetDefinition(id)?.title ?? id;
}
