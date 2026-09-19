import type { CollectionStatus } from '@adminsecops/core';
import type { LoadedDataset } from '@adminsecops/evidence';
import { getDatasetDefinition, type DatasetId, type ManifestEnvironment } from '@adminsecops/schemas';
import { Inventory } from './inventory.js';

export interface FromDataOptions {
  assessmentId?: string;
  assessedAt?: Date | string;
  environment?: Partial<ManifestEnvironment>;
  /** Datasets to mark as Partial collection. */
  partial?: readonly DatasetId[];
  /** Datasets to include as unavailable with the given collection status. */
  unavailable?: Partial<Record<DatasetId, Exclude<CollectionStatus, 'Success' | 'Partial'>>>;
}

/**
 * Build an Inventory directly from dataset payloads (in collector/schema input form).
 * Every payload is validated with its dataset schema, exactly as during ingestion,
 * and an invalid payload throws. Used by control tests and fixture tooling.
 */
export function createInventoryFromData(
  data: Partial<Record<DatasetId, unknown>>,
  options: FromDataOptions = {},
): Inventory {
  const datasets = new Map<string, LoadedDataset>();
  const collectedAt = new Date(options.assessedAt ?? '2026-09-01T12:00:00Z').toISOString();

  for (const [id, payload] of Object.entries(data)) {
    const definition = getDatasetDefinition(id);
    if (definition === undefined) throw new Error(`Unknown dataset ${id}`);
    const parsed = (definition.schema).safeParse(payload);
    if (!parsed.success) {
      throw new Error(`Test data for ${id} is invalid: ${parsed.error.message}`);
    }
    const partial = options.partial?.includes(id as DatasetId) ?? false;
    datasets.set(id, {
      datasetId: id,
      definition,
      state: partial ? 'partial' : 'available',
      reason: partial ? 'Collector reported partial collection.' : 'Collected successfully and verified.',
      collectionStatus: partial ? 'Partial' : 'Success',
      data: parsed.data,
      reference: {
        datasetId: id,
        path: `evidence/${id}.json`,
        sha256: null,
        collectedAt,
        status: partial ? 'Partial' : 'Success',
        source: null,
      },
    });
  }

  for (const [id, status] of Object.entries(options.unavailable ?? {})) {
    const definition = getDatasetDefinition(id);
    if (definition === undefined || status === undefined) continue;
    datasets.set(id, {
      datasetId: id,
      definition,
      state: 'unavailable',
      reason: `Collector reported status ${status}.`,
      collectionStatus: status,
      data: null,
      reference: { datasetId: id, path: `evidence/${id}.json`, sha256: null, collectedAt, status, source: null },
    });
  }

  return new Inventory({
    assessmentId: options.assessmentId ?? '00000000-0000-4000-8000-000000000001',
    assessedAt: new Date(collectedAt),
    environment: {
      label: null,
      tenantId: null,
      tenantDisplayName: null,
      primaryDomain: null,
      adForestName: null,
      adDomainName: null,
      ...options.environment,
    },
    datasets,
  });
}
