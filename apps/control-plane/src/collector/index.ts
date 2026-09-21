export {
  ENTRA_ADDITIONAL_REQUIREMENTS,
  ENTRA_GRAPH_PERMISSIONS,
  ENTRA_REQUIRED_GRAPH_PERMISSIONS,
  HOSTED_COLLECTOR_NAME,
  HOSTED_COLLECTOR_VERSION,
  HOSTED_ENTRA_DATASETS,
  HOSTED_ENTRA_UNSUPPORTED_DATASETS,
  collectEntra,
  collectEntraEvidence,
  type CollectEntraOptions,
  type EntraCollectionResult,
  type GraphPermissionRequirement,
} from './entra.js';
export {
  CollectionCancelledError,
  DEFAULT_GRAPH_LIMITS,
  GRAPH_BASE,
  GraphRequestError,
  validateGraphUrl,
  type GraphLimits,
} from './graph-client.js';
