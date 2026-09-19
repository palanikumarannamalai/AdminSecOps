import type {
  AssessmentComparison,
  AssessmentListItem,
  AssessmentResult,
  ControlLibraryResponse,
  CreatedAssessment,
  DatasetInfo,
  HealthResponse,
  SampleInfo,
  SampleName,
} from './types';

/** Header the local API requires on every request (mutating requests are rejected without it). */
export const CLIENT_HEADER = 'X-AdminSecOps-Client';
export const CLIENT_HEADER_VALUE = 'web';

const MAX_ERROR_MESSAGE_LENGTH = 500;

/**
 * Error raised by the API client. `status` is 0 when the request did not reach the
 * server (network failure, aborted) and `code` is either the server's error code or
 * one of the client codes: network_error, aborted, invalid_response, http_<status>.
 */
export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
  }
}

export function isApiError(value: unknown): value is ApiError {
  return value instanceof ApiError;
}

/** Plain-text description of any thrown value, suitable for rendering as React text. */
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return 'An unexpected error occurred.';
}

type Guard<T> = (value: unknown) => value is T;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasArray(value: unknown, ...keys: string[]): value is Record<string, unknown[]> {
  return isRecord(value) && keys.every((k) => Array.isArray(value[k]));
}

function hasString(value: unknown, key: string): boolean {
  return isRecord(value) && typeof value[key] === 'string';
}

const guards = {
  health: (v: unknown): v is HealthResponse => isRecord(v) && v.status === 'ok' && hasString(v, 'version'),
  assessmentList: (v: unknown): v is { assessments: AssessmentListItem[] } => hasArray(v, 'assessments'),
  created: (v: unknown): v is CreatedAssessment => hasString(v, 'assessmentId'),
  samples: (v: unknown): v is { samples: SampleInfo[] } => hasArray(v, 'samples'),
  assessment: (v: unknown): v is AssessmentResult =>
    isRecord(v) &&
    v.resultSchemaVersion === '1.0' &&
    hasString(v, 'assessmentId') &&
    hasArray(v, 'results', 'findings', 'inventory') &&
    isRecord(v.summary) &&
    isRecord(v.evidence) &&
    isRecord(v.collection),
  comparison: (v: unknown): v is AssessmentComparison =>
    hasArray(v, 'newFindings', 'resolvedFindings', 'changedFindings', 'controlStatusChanges') &&
    typeof v.direction === 'string' &&
    typeof v.sameEnvironment === 'boolean',
  controls: (v: unknown): v is ControlLibraryResponse => hasArray(v, 'controls') && hasString(v, 'libraryVersion'),
  datasets: (v: unknown): v is { datasets: DatasetInfo[] } => hasArray(v, 'datasets'),
};

function truncate(text: string): string {
  return text.length > MAX_ERROR_MESSAGE_LENGTH ? `${text.slice(0, MAX_ERROR_MESSAGE_LENGTH)}...` : text;
}

function defaultMessageFor(status: number): string {
  if (status === 400) return 'The request was not accepted by the local AdminSecOps service.';
  if (status === 403) return 'The local AdminSecOps service refused the request.';
  if (status === 404) return 'The requested item was not found. It may have been deleted.';
  if (status === 413) return 'The evidence package is too large.';
  if (status >= 500) return 'The local AdminSecOps service reported an internal error.';
  return `The local AdminSecOps service returned HTTP ${status}.`;
}

/** Map an error response body ({ error: { code, message } }) to an ApiError. */
export function toApiError(status: number, bodyText: string): ApiError {
  let parsed: unknown;
  try {
    parsed = bodyText === '' ? undefined : JSON.parse(bodyText);
  } catch {
    parsed = undefined;
  }
  if (isRecord(parsed) && isRecord(parsed.error)) {
    const { code, message } = parsed.error;
    const safeCode = typeof code === 'string' && code !== '' ? code.slice(0, 100) : `http_${status}`;
    const safeMessage = typeof message === 'string' && message.trim() !== '' ? truncate(message) : defaultMessageFor(status);
    return new ApiError(safeCode, safeMessage, status);
  }
  return new ApiError(`http_${status}`, defaultMessageFor(status), status);
}

function interpret<T>(status: number, bodyText: string, guard: Guard<T> | null): T {
  if (status < 200 || status >= 300) throw toApiError(status, bodyText);
  if (guard === null) return undefined as T;
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    throw new ApiError('invalid_response', 'The local AdminSecOps service returned a response that is not valid JSON.', status);
  }
  if (!guard(parsed)) {
    throw new ApiError('invalid_response', 'The local AdminSecOps service returned an unexpected response.', status);
  }
  return parsed;
}

export interface UploadOptions {
  /** Called with a fraction between 0 and 1 while the file is sent. */
  onProgress?: (fraction: number) => void;
  signal?: AbortSignal;
}

export interface ApiClientOptions {
  baseUrl?: string;
  fetch?: typeof fetch;
  createXhr?: () => XMLHttpRequest;
}

export type ReportFormat = 'html' | 'json';

/** On-device data controls (hosted mode only). */
export interface LocalDataControls {
  /** Whether this browser offers on-device storage (IndexedDB). */
  persistenceAvailable: boolean;
  isPersistenceEnabled: () => boolean;
  /** Turning persistence off deletes anything already stored on this device. */
  setPersistenceEnabled: (enabled: boolean) => Promise<void>;
  /** Clear every assessment from memory and delete all on-device data. */
  deleteAllLocalData: () => Promise<void>;
}

/**
 * Methods are plain functions (no `this`), so they can be passed around unbound.
 * `mode` is 'local' for the local API client and 'hosted' for the in-browser client.
 */
export interface ApiClient {
  mode: 'local' | 'hosted';
  localData?: LocalDataControls;
  health: (signal?: AbortSignal) => Promise<HealthResponse>;
  listAssessments: (signal?: AbortSignal) => Promise<AssessmentListItem[]>;
  getAssessment: (id: string, signal?: AbortSignal) => Promise<AssessmentResult>;
  deleteAssessment: (id: string) => Promise<void>;
  uploadPackage: (file: File, options?: UploadOptions) => Promise<CreatedAssessment>;
  listSamples: (signal?: AbortSignal) => Promise<SampleInfo[]>;
  loadSample: (name: SampleName) => Promise<CreatedAssessment>;
  compare: (baselineId: string, currentId: string, signal?: AbortSignal) => Promise<AssessmentComparison>;
  listControls: (signal?: AbortSignal) => Promise<ControlLibraryResponse>;
  listDatasets: (signal?: AbortSignal) => Promise<DatasetInfo[]>;
  reportUrl: (id: string, format: ReportFormat) => string;
}

export function createApiClient(options: ApiClientOptions = {}): ApiClient {
  const baseUrl = (options.baseUrl ?? '/api').replace(/\/+$/, '');
  const doFetch = options.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => globalThis.fetch(input, init));
  const createXhr = options.createXhr ?? (() => new XMLHttpRequest());

  async function request<T>(method: string, path: string, guard: Guard<T> | null, signal?: AbortSignal): Promise<T> {
    let response: Response;
    try {
      response = await doFetch(`${baseUrl}${path}`, {
        method,
        headers: { [CLIENT_HEADER]: CLIENT_HEADER_VALUE, Accept: 'application/json' },
        credentials: 'same-origin',
        signal,
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw new ApiError('aborted', 'The request was cancelled.', 0);
      }
      throw new ApiError(
        'network_error',
        'Cannot reach the local AdminSecOps service. Check that it is running on this machine.',
        0,
      );
    }
    const text = await response.text();
    return interpret(response.status, text, guard);
  }

  const id = (value: string) => encodeURIComponent(value);

  return {
    mode: 'local',
    health: (signal) => request('GET', '/health', guards.health, signal),
    listAssessments: async (signal) => (await request('GET', '/assessments', guards.assessmentList, signal)).assessments,
    getAssessment: (assessmentId, signal) => request('GET', `/assessments/${id(assessmentId)}`, guards.assessment, signal),
    deleteAssessment: (assessmentId) => request<void>('DELETE', `/assessments/${id(assessmentId)}`, null),
    listSamples: async (signal) => (await request('GET', '/samples', guards.samples, signal)).samples,
    loadSample: (name) => request('POST', `/samples/${id(name)}`, guards.created),
    compare: (baselineId, currentId, signal) =>
      request(
        'GET',
        `/compare?baseline=${id(baselineId)}&current=${id(currentId)}`,
        guards.comparison,
        signal,
      ),
    listControls: (signal) => request('GET', '/controls', guards.controls, signal),
    listDatasets: async (signal) => (await request('GET', '/datasets', guards.datasets, signal)).datasets,
    reportUrl: (assessmentId, format) => `${baseUrl}/assessments/${id(assessmentId)}/report.${format}`,

    uploadPackage(file, uploadOptions = {}) {
      return new Promise<CreatedAssessment>((resolve, reject) => {
        const xhr = createXhr();
        const { onProgress, signal } = uploadOptions;
        const onAbortSignal = () => xhr.abort();
        const cleanup = () => signal?.removeEventListener('abort', onAbortSignal);

        xhr.open('POST', `${baseUrl}/assessments`);
        xhr.setRequestHeader(CLIENT_HEADER, CLIENT_HEADER_VALUE);
        xhr.setRequestHeader('Accept', 'application/json');
        xhr.upload.onprogress = (event) => {
          if (event.lengthComputable && event.total > 0) onProgress?.(Math.min(1, event.loaded / event.total));
        };
        xhr.onload = () => {
          cleanup();
          try {
            resolve(interpret(xhr.status, xhr.responseText, guards.created));
          } catch (error) {
            reject(error instanceof Error ? error : new Error(String(error)));
          }
        };
        xhr.onerror = () => {
          cleanup();
          reject(
            new ApiError(
              'network_error',
              'The upload failed because the local AdminSecOps service could not be reached.',
              0,
            ),
          );
        };
        xhr.onabort = () => {
          cleanup();
          reject(new ApiError('aborted', 'The upload was cancelled.', 0));
        };
        if (signal !== undefined) {
          if (signal.aborted) {
            reject(new ApiError('aborted', 'The upload was cancelled.', 0));
            return;
          }
          signal.addEventListener('abort', onAbortSignal);
        }
        const form = new FormData();
        form.append('package', file, file.name);
        xhr.send(form);
      });
    },
  };
}

/** Client used by the application. Tests create their own with a mocked fetch. */
export const api = createApiClient();
