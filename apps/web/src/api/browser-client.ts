import { CONTROL_LIBRARY, CONTROL_LIBRARY_VERSION } from '@adminsecops/controls';
import { ENGINE_VERSION, PRODUCT_NAME, isAdminSecOpsError } from '@adminsecops/core';
import { DEFAULT_PACKAGE_LIMITS } from '@adminsecops/evidence/browser';
import { assessPackageFiles, assessZipBytes, compareAssessments } from '@adminsecops/engine/browser';
import { buildJsonReport, renderHtmlReport, serializeJsonReport } from '@adminsecops/reporting';
import { listDatasetDefinitions } from '@adminsecops/schemas';
import { ApiError, type ApiClient, type ReportFormat, type UploadOptions } from './client';
import { localStore, readPersistencePreference, type StoredAssessment } from './local-store';
import { loadSampleFiles, SAMPLES } from './samples';
import type { AssessmentListItem, AssessmentResult, CreatedAssessment, SampleName } from './types';

/*
 * In-browser implementation of the ConfigReview client (hosted mode).
 *
 * Evidence packages chosen by the visitor are read with File.arrayBuffer() and processed in
 * memory by the same engine packages the local service uses: ZIP limits, SHA-256 integrity
 * verification, secret-content rejection, schema validation, deterministic controls,
 * prioritisation and report generation. This module performs no network requests; the hosted
 * page's Content-Security-Policy additionally sets connect-src 'none'.
 */

function notFound(): ApiError {
  return new ApiError('NOT_FOUND', 'The assessment was not found in this browser. It may have been cleared.', 404);
}

function toApiError(error: unknown): ApiError {
  if (isAdminSecOpsError(error)) return new ApiError(error.code, error.message, error.statusCode);
  return new ApiError('INTERNAL_ERROR', 'The evidence package could not be processed in this browser.', 500);
}

/** Let the browser paint progress before synchronous processing starts. */
const nextFrame = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

function listItem(entry: StoredAssessment): AssessmentListItem {
  const { result, source } = entry;
  const env = result.collection.environment;
  return {
    assessmentId: result.assessmentId,
    label: env.label,
    tenantDisplayName: env.tenantDisplayName,
    primaryDomain: env.primaryDomain,
    adForestName: env.adForestName,
    assessedAt: result.assessedAt,
    processedAt: result.processedAt,
    integrityVerified: result.evidence.integrityVerified,
    source,
    summary: result.summary,
  };
}

async function readFile(file: File, onProgress?: (fraction: number) => void): Promise<Uint8Array> {
  onProgress?.(0);
  const bytes = new Uint8Array(await file.arrayBuffer());
  onProgress?.(1);
  return bytes;
}

export function createBrowserClient(): ApiClient {
  const store = new Map<string, StoredAssessment>();
  const reportUrls = new Map<string, string>();
  let restoring: Promise<void> | null = null;

  /** Restore opted-in assessments once; concurrent callers share the same promise. */
  function ensureRestored(): Promise<void> {
    restoring ??= localStore
      .loadAll()
      .then((items) => {
        for (const item of items) store.set(item.assessmentId.toLowerCase(), item);
      })
      .catch(() => {
        // A damaged or blocked local database is ignored; the app keeps working in memory.
      });
    return restoring;
  }

  function get(id: string): StoredAssessment {
    const item = store.get(id.toLowerCase());
    if (item === undefined) throw notFound();
    return item;
  }

  function revokeReports(id: string): void {
    for (const format of ['html', 'json'] as const) {
      const key = `${id.toLowerCase()}:${format}`;
      const url = reportUrls.get(key);
      if (url !== undefined) URL.revokeObjectURL(url);
      reportUrls.delete(key);
    }
  }

  async function add(result: AssessmentResult, source: 'upload' | 'sample'): Promise<CreatedAssessment> {
    const entry: StoredAssessment = { assessmentId: result.assessmentId, source, result };
    revokeReports(result.assessmentId);
    store.set(result.assessmentId.toLowerCase(), entry);
    await localStore.put(entry).catch(() => undefined);
    return { assessmentId: result.assessmentId };
  }

  return {
    mode: 'hosted',
    localData: {
      persistenceAvailable: localStore.available(),
      isPersistenceEnabled: readPersistencePreference,
      setPersistenceEnabled: (enabled) => localStore.setEnabled(enabled, [...store.values()]),
      async deleteAllLocalData() {
        for (const id of store.keys()) revokeReports(id);
        store.clear();
        await localStore.deleteAll();
      },
    },

    health: () =>
      Promise.resolve({
        status: 'ok',
        product: PRODUCT_NAME,
        version: ENGINE_VERSION,
        engineVersion: ENGINE_VERSION,
        controlLibraryVersion: CONTROL_LIBRARY_VERSION,
      }),

    async listAssessments() {
      await ensureRestored();
      return [...store.values()].map(listItem).sort((a, b) => b.processedAt.localeCompare(a.processedAt));
    },

    async getAssessment(id) {
      await ensureRestored();
      return get(id).result;
    },

    async deleteAssessment(id) {
      await ensureRestored();
      get(id);
      revokeReports(id);
      store.delete(id.toLowerCase());
      await localStore.remove(id).catch(() => undefined);
    },

    async uploadPackage(file: File, options: UploadOptions = {}) {
      if (options.signal?.aborted === true) throw new ApiError('aborted', 'The import was cancelled.', 0);
      if (file.size > DEFAULT_PACKAGE_LIMITS.maxArchiveBytes) {
        throw new ApiError('PACKAGE_TOO_LARGE', `The evidence package exceeds the ${DEFAULT_PACKAGE_LIMITS.maxArchiveBytes} byte limit.`, 413);
      }
      const bytes = await readFile(file, options.onProgress);
      await nextFrame();
      let result: AssessmentResult;
      try {
        result = assessZipBytes(bytes);
      } catch (error) {
        throw toApiError(error);
      }
      return add(result, 'upload');
    },

    listSamples: () => Promise.resolve([...SAMPLES]),

    async loadSample(name: SampleName) {
      if (!SAMPLES.some((s) => s.name === name)) throw new ApiError('SAMPLE_NOT_FOUND', 'Unknown sample.', 404);
      const files = await loadSampleFiles(name);
      await nextFrame();
      try {
        return await add(assessPackageFiles(files), 'sample');
      } catch (error) {
        throw toApiError(error);
      }
    },

    async compare(baselineId, currentId) {
      await ensureRestored();
      return compareAssessments(get(baselineId).result, get(currentId).result);
    },

    listControls: () => Promise.resolve({ libraryVersion: CONTROL_LIBRARY_VERSION, controls: CONTROL_LIBRARY.map((c) => c.metadata) }),

    listDatasets: () =>
      Promise.resolve(
        listDatasetDefinitions().map((d) => ({
          id: d.id,
          module: d.module,
          technology: d.technology,
          title: d.title,
          description: d.description,
          source: d.source,
          operations: [...d.operations],
          permissions: [...d.permissions],
          prerequisites: d.prerequisites === undefined ? [] : [...d.prerequisites],
          personalData: d.personalData,
        })),
      ),

    /** Reports are generated in the browser and offered as local blob: downloads. */
    reportUrl(id: string, format: ReportFormat) {
      const key = `${id.toLowerCase()}:${format}`;
      const existing = reportUrls.get(key);
      if (existing !== undefined) return existing;
      const item = store.get(id.toLowerCase());
      if (item === undefined) return '#';
      const blob =
        format === 'html'
          ? new Blob([renderHtmlReport(item.result)], { type: 'text/html;charset=utf-8' })
          : new Blob([serializeJsonReport(buildJsonReport(item.result))], { type: 'application/json;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      reportUrls.set(key, url);
      return url;
    },
  };
}
