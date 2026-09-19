import type { z } from 'zod';
import { AD_DATASETS } from './ad.js';
import { ADCS_DATASETS } from './adcs.js';
import { AZURE_DATASETS } from './azure.js';
import type { DatasetDefinition } from './define.js';
import { ENTRA_DATASETS } from './entra.js';
import { INTUNE_DATASETS } from './intune.js';
import { M365_DATASETS } from './m365.js';
import { WINDOWS_DATASETS } from './windows.js';

export const ALL_DATASETS = [
  ...ENTRA_DATASETS,
  ...M365_DATASETS,
  ...INTUNE_DATASETS,
  ...AZURE_DATASETS,
  ...AD_DATASETS,
  ...ADCS_DATASETS,
  ...WINDOWS_DATASETS,
] as const;

type AnyDataset = (typeof ALL_DATASETS)[number];

/** Identifier of a known dataset, e.g. 'entra.conditionalAccessPolicies'. */
export type DatasetId = AnyDataset['id'];

/** Validated (normalised by schema) payload type for each dataset. */
export type DatasetDataMap = {
  [D in AnyDataset as D['id']]: z.output<D['schema']>;
};

export type DatasetData<K extends DatasetId> = DatasetDataMap[K];

const BY_ID: ReadonlyMap<string, DatasetDefinition> = new Map(
  ALL_DATASETS.map((dataset) => [dataset.id, dataset as DatasetDefinition]),
);

if (BY_ID.size !== ALL_DATASETS.length) {
  throw new Error('Duplicate dataset identifier in registry');
}

export function getDatasetDefinition(id: string): DatasetDefinition | undefined {
  return BY_ID.get(id);
}

export function isKnownDatasetId(id: string): id is DatasetId {
  return BY_ID.has(id);
}

export function listDatasetDefinitions(): readonly DatasetDefinition[] {
  return [...BY_ID.values()];
}
