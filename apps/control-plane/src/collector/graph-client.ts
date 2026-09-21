import { AdminSecOpsError } from '@adminsecops/core';

/**
 * Bounded, read-only Microsoft Graph client used by the hosted collector.
 *
 * Security properties:
 * - GET only; there is no API for any other method.
 * - Every URL - including @odata.nextLink values returned by the service - is checked
 *   against a strict allowlist (https://graph.microsoft.com/v1.0/...) before a request
 *   is built, so the bearer token is never sent anywhere else. Redirects are refused.
 * - Page count, per-response bytes, total bytes, per-request time and total time are
 *   bounded. 429/503 are retried a bounded number of times, honouring a capped Retry-After.
 * - Tokens and response bodies are never logged or placed in error messages. For failed
 *   requests only a sanitised Graph error code and a licence hint are retained.
 */

export const GRAPH_ORIGIN = 'https://graph.microsoft.com';
export const GRAPH_BASE = `${GRAPH_ORIGIN}/v1.0`;

export interface GraphLimits {
  /** Maximum pages followed for one collection request. */
  maxPages: number;
  /** Maximum bytes accepted for one response body. */
  maxResponseBytes: number;
  /** Maximum bytes accepted across the whole collection. */
  maxTotalBytes: number;
  /** Timeout of one HTTP request, including reading the body. */
  requestTimeoutMs: number;
  /** Time budget of the whole collection. */
  totalTimeoutMs: number;
  /** Retries after a 429/503 response (not counting the first attempt). */
  maxRetries: number;
  /** Upper bound applied to Retry-After and to exponential backoff. */
  maxRetryDelayMs: number;
  /** First backoff delay when the service sends no Retry-After. */
  baseRetryDelayMs: number;
}

export const DEFAULT_GRAPH_LIMITS: Readonly<GraphLimits> = Object.freeze({
  maxPages: 500,
  maxResponseBytes: 8 * 1024 * 1024,
  maxTotalBytes: 128 * 1024 * 1024,
  requestTimeoutMs: 30_000,
  totalTimeoutMs: 10 * 60_000,
  maxRetries: 3,
  maxRetryDelayMs: 30_000,
  baseRetryDelayMs: 1_000,
});

const MAX_URL_LENGTH = 4096;
const MAX_ERROR_BODY_BYTES = 16 * 1024;
const RETRYABLE_STATUSES = new Set([429, 503]);
const SAFE_GRAPH_CODE = /^[A-Za-z0-9_.-]{1,100}$/;

/**
 * Service responses that mean a licence or feature is absent (ported from the PowerShell
 * collector's Resolve-AsoErrorStatus). Only the boolean result is kept, never the text.
 */
const LICENCE_PATTERN =
  /(premium( p?[12])? licen[cs]e|P2 licen[cs]e|Governance licen[cs]e|licen[cs]e is required|requires? (an? )?(Microsoft )?(Entra|Azure AD|AAD).{0,20}(P1|P2|Premium)|AadPremiumLicenseRequired|RequestFromNonPremiumTenant|NonPremiumTenant|does not have (a |an )?(valid )?licen[cs]e|not licensed|tenant is not licensed|Request not applicable to target tenant|LicenseNotFound|MissingLicense|without a valid licen[cs]e)/i;

export type GraphFailureKind =
  | 'http'
  | 'timeout'
  | 'budget-exhausted'
  | 'too-large'
  | 'invalid-json'
  | 'invalid-response'
  | 'network'
  | 'url-rejected';

/** A failed Graph request. `message` never contains tokens, URLs with query strings or response bodies. */
export class GraphRequestError extends Error {
  readonly kind: GraphFailureKind;
  readonly status: number | null;
  /** Sanitised `error.code` from the Graph error body, when present. */
  readonly graphCode: string | null;
  /** True when the error body indicated a missing licence or feature. */
  readonly licenceHint: boolean;

  constructor(kind: GraphFailureKind, message: string, details: { status?: number; graphCode?: string | null; licenceHint?: boolean } = {}) {
    super(message);
    this.name = 'GraphRequestError';
    this.kind = kind;
    this.status = details.status ?? null;
    this.graphCode = details.graphCode ?? null;
    this.licenceHint = details.licenceHint ?? false;
  }
}

/** The caller's AbortSignal fired. Collection stops; no bundle is produced. */
export class CollectionCancelledError extends AdminSecOpsError {
  constructor() {
    super('COLLECTION_CANCELLED', 'The collection was cancelled.', { statusCode: 499 });
    this.name = 'CollectionCancelledError';
  }
}

/**
 * Validate a Graph URL against the allowlist. Returns the normalised URL, or undefined when
 * the URL must not be requested (other host, scheme, port, credentials, API version...).
 */
export function validateGraphUrl(raw: unknown): string | undefined {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_URL_LENGTH) return undefined;
  // Control characters and backslashes have no place in a Graph URL and can confuse parsers.
  // eslint-disable-next-line no-control-regex -- Explicitly reject control characters before URL parsing.
  if (/[\u0000-\u001f\u007f\\]/.test(raw)) return undefined;
  if (!raw.startsWith(`${GRAPH_BASE}/`)) return undefined;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'https:' || url.hostname !== 'graph.microsoft.com' || url.port !== '') return undefined;
  if (url.username !== '' || url.password !== '' || url.hash !== '') return undefined;
  if (url.origin !== GRAPH_ORIGIN || !url.pathname.startsWith('/v1.0/')) return undefined;
  return url.href;
}

export interface GraphClientOptions {
  accessToken: string;
  fetch: typeof globalThis.fetch;
  signal?: AbortSignal | undefined;
  limits: GraphLimits;
  /** Monotonic-ish clock in ms; injectable for tests. */
  now?: () => number;
}

export interface GraphPageResult {
  items: unknown[];
  /** Set when collection stopped early; the items are incomplete. */
  incomplete: { code: 'PAGE_FAILED' | 'PAGE_LIMIT' | 'NEXT_LINK_REJECTED' | 'INVALID_PAGE'; message: string } | null;
}

export class GraphClient {
  private readonly accessToken: string;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly signal: AbortSignal | undefined;
  private readonly limits: GraphLimits;
  private readonly now: () => number;
  private readonly deadline: number;
  private totalBytes = 0;
  private requestCount = 0;

  constructor(options: GraphClientOptions) {
    this.accessToken = options.accessToken;
    this.fetchImpl = options.fetch;
    this.signal = options.signal;
    this.limits = options.limits;
    this.now = options.now ?? Date.now;
    this.deadline = this.now() + options.limits.totalTimeoutMs;
  }

  get requestsSent(): number {
    return this.requestCount;
  }

  throwIfCancelled(): void {
    if (this.signal?.aborted === true) throw new CollectionCancelledError();
  }

  /** GET one Graph resource and return the parsed JSON body. */
  async get(url: string): Promise<unknown> {
    const safeUrl = validateGraphUrl(url);
    if (safeUrl === undefined) {
      throw new GraphRequestError('url-rejected', 'A request URL was outside the Microsoft Graph v1.0 allowlist and was not sent.');
    }
    for (let attempt = 0; ; attempt += 1) {
      this.throwIfCancelled();
      const response = await this.send(safeUrl);
      if (response.ok) {
        const bytes = await this.readBody(response, this.limits.maxResponseBytes);
        return parseJson(bytes);
      }
      const retryDelay = RETRYABLE_STATUSES.has(response.status) && attempt < this.limits.maxRetries
        ? this.retryDelay(response.headers.get('retry-after'), attempt)
        : undefined;
      if (retryDelay !== undefined && this.now() + retryDelay < this.deadline) {
        await discardBody(response);
        await abortableSleep(retryDelay, this.signal);
        continue;
      }
      throw await this.httpError(response);
    }
  }

  /**
   * GET a Graph collection and follow @odata.nextLink. A failure on the first page throws;
   * a failure on a later page returns the items so far with `incomplete` set, so the
   * dataset can be reported Partial rather than silently complete.
   */
  async getAll(url: string): Promise<GraphPageResult> {
    const items: unknown[] = [];
    let next: string | undefined = url;
    let pages = 0;
    while (next !== undefined) {
      let body: unknown;
      try {
        body = await this.get(next);
      } catch (error) {
        if (pages === 0 || !(error instanceof GraphRequestError)) throw error;
        return { items, incomplete: { code: 'PAGE_FAILED', message: `A result page could not be read after ${pages} page(s); results are incomplete. ${describeGraphError(error)}` } };
      }
      const record = asRecord(body);
      const value = record?.['value'];
      if (record === undefined || !Array.isArray(value)) {
        if (pages === 0) throw new GraphRequestError('invalid-response', 'Microsoft Graph returned a collection response without a value array.');
        return { items, incomplete: { code: 'INVALID_PAGE', message: `Result page ${pages + 1} was not a valid collection page; results are incomplete.` } };
      }
      pages += 1;
      items.push(...(value as unknown[]));
      const rawNext = record['@odata.nextLink'];
      if (rawNext === undefined || rawNext === null) break;
      next = validateGraphUrl(rawNext);
      if (next === undefined) {
        return {
          items,
          incomplete: {
            code: 'NEXT_LINK_REJECTED',
            message: `The service returned a next-page link outside the Microsoft Graph v1.0 allowlist after ${pages} page(s). It was not followed and results are incomplete.`,
          },
        };
      }
      if (pages >= this.limits.maxPages) {
        return { items, incomplete: { code: 'PAGE_LIMIT', message: `Stopped after ${pages} page(s) (collection limit); results are incomplete.` } };
      }
    }
    return { items, incomplete: null };
  }

  private async send(url: string): Promise<Response> {
    const remaining = this.deadline - this.now();
    if (remaining <= 0) throw new GraphRequestError('budget-exhausted', 'The collection time budget was exhausted before this request.');
    const controller = new AbortController();
    const onAbort = (): void => controller.abort();
    this.signal?.addEventListener('abort', onAbort, { once: true });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, Math.min(this.limits.requestTimeoutMs, remaining));
    this.requestCount += 1;
    try {
      const response = await this.fetchImpl(url, {
        method: 'GET',
        headers: { Authorization: `Bearer ${this.accessToken}`, Accept: 'application/json', Prefer: 'include-unknown-enum-members' },
        redirect: 'error',
        signal: controller.signal,
      });
      // Keep the timer alive while the body is read; readBody honours the same signal.
      return wrapWithCleanup(response, () => {
        clearTimeout(timer);
        this.signal?.removeEventListener('abort', onAbort);
      });
    } catch {
      clearTimeout(timer);
      this.signal?.removeEventListener('abort', onAbort);
      if (this.signal?.aborted === true) throw new CollectionCancelledError();
      if (timedOut) throw new GraphRequestError('timeout', 'The Microsoft Graph request timed out.');
      // The underlying error may echo request details; it is deliberately not retained.
      throw new GraphRequestError('network', 'The Microsoft Graph request failed at the network level.');
    }
  }

  private async readBody(response: Response, maxBytes: number): Promise<Uint8Array> {
    try {
      const declared = response.headers.get('content-length');
      if (declared !== null && /^\d+$/.test(declared) && Number(declared) > maxBytes) {
        await discardBody(response);
        throw new GraphRequestError('too-large', 'A Microsoft Graph response exceeded the size limit and was not read.');
      }
      const chunks: Uint8Array[] = [];
      let total = 0;
      if (response.body === null) {
        const buffer = new Uint8Array(await response.arrayBuffer());
        total = buffer.byteLength;
        chunks.push(buffer);
      } else {
        const reader = response.body.getReader();
        for (;;) {
          const { done, value } = await reader.read() as { done: boolean; value?: unknown };
          if (done) break;
          if (!(value instanceof Uint8Array)) throw new GraphRequestError('invalid-response', 'The Microsoft Graph response stream was invalid.');
          total += value.byteLength;
          if (total > maxBytes) {
            await reader.cancel().catch(() => undefined);
            throw new GraphRequestError('too-large', 'A Microsoft Graph response exceeded the size limit and was not read.');
          }
          chunks.push(value);
        }
      }
      if (total > maxBytes) throw new GraphRequestError('too-large', 'A Microsoft Graph response exceeded the size limit and was not read.');
      this.totalBytes += total;
      if (this.totalBytes > this.limits.maxTotalBytes) {
        throw new GraphRequestError('budget-exhausted', 'The collection exceeded its total response size budget.');
      }
      return concat(chunks, total);
    } catch (error) {
      if (error instanceof GraphRequestError) throw error;
      if (this.signal?.aborted === true) throw new CollectionCancelledError();
      throw new GraphRequestError('timeout', 'Reading the Microsoft Graph response failed or timed out.');
    } finally {
      cleanupOf(response)?.();
    }
  }

  private retryDelay(header: string | null, attempt: number): number {
    const fromHeader = parseRetryAfter(header, Date.now());
    const backoff = this.limits.baseRetryDelayMs * 2 ** attempt;
    return Math.max(0, Math.min(fromHeader ?? backoff, this.limits.maxRetryDelayMs));
  }

  private async httpError(response: Response): Promise<GraphRequestError> {
    let graphCode: string | null = null;
    let licenceHint = false;
    try {
      const body = asRecord(parseJson(await this.readBody(response, MAX_ERROR_BODY_BYTES)));
      const error = asRecord(body?.['error']);
      const code = error?.['code'];
      const message = error?.['message'];
      if (typeof code === 'string' && SAFE_GRAPH_CODE.test(code)) graphCode = code;
      licenceHint = LICENCE_PATTERN.test(`${typeof code === 'string' ? code : ''} ${typeof message === 'string' ? message : ''}`);
    } catch (error) {
      if (error instanceof CollectionCancelledError) throw error;
      // Unreadable error bodies are ignored; only the status code is used.
    }
    return new GraphRequestError('http', `Microsoft Graph returned HTTP ${response.status}${graphCode !== null ? ` (${graphCode})` : ''}.`, {
      status: response.status,
      graphCode,
      licenceHint,
    });
  }
}

/** One-line description of a Graph failure that is safe to store in evidence. */
export function describeGraphError(error: GraphRequestError): string {
  return error.message;
}

export function parseRetryAfter(header: string | null, nowMs: number): number | undefined {
  if (header === null) return undefined;
  const value = header.trim();
  if (/^\d{1,9}$/.test(value)) return Number(value) * 1000;
  const date = Date.parse(value);
  return Number.isNaN(date) ? undefined : Math.max(0, date - nowMs);
}

export function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function parseJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new GraphRequestError('invalid-json', 'Microsoft Graph returned a response that is not valid JSON.');
  }
}

function concat(chunks: readonly Uint8Array[], total: number): Uint8Array {
  if (chunks.length === 1 && chunks[0] !== undefined) return chunks[0];
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

async function discardBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // Nothing useful to do; the body is not needed.
  } finally {
    cleanupOf(response)?.();
  }
}

const CLEANUP = new WeakMap<Response, () => void>();

function wrapWithCleanup(response: Response, cleanup: () => void): Response {
  let done = false;
  CLEANUP.set(response, () => {
    if (done) return;
    done = true;
    cleanup();
  });
  return response;
}

function cleanupOf(response: Response): (() => void) | undefined {
  return CLEANUP.get(response);
}

function abortableSleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted === true) {
      reject(new CollectionCancelledError());
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(new CollectionCancelledError());
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}
