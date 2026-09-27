import { describe, expect, it, vi } from 'vitest';
import { sampleComparison, sampleListItem, sampleResult } from '../test/sample-result';
import { ApiError, CLIENT_HEADER, createApiClient, toApiError } from './client';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function mockFetch(response: Response | Error) {
  return vi.fn<typeof fetch>(() => (response instanceof Error ? Promise.reject(response) : Promise.resolve(response)));
}

function headersOf(fetchMock: ReturnType<typeof mockFetch>, call = 0): Record<string, string> {
  const init = fetchMock.mock.calls[call]?.[1];
  return (init?.headers ?? {}) as Record<string, string>;
}

describe('api client', () => {
  it('sends the client header on reads and returns typed data', async () => {
    const fetchMock = mockFetch(jsonResponse({ assessments: [sampleListItem] }));
    const api = createApiClient({ fetch: fetchMock });

    const list = await api.listAssessments();

    expect(list).toHaveLength(1);
    expect(fetchMock).toHaveBeenCalledWith('/api/assessments', expect.objectContaining({ method: 'GET' }));
    expect(headersOf(fetchMock)[CLIENT_HEADER]).toBe('web');
  });

  it('sends the client header on DELETE and accepts 204', async () => {
    const fetchMock = mockFetch(new Response(null, { status: 204 }));
    const api = createApiClient({ fetch: fetchMock });

    await expect(api.deleteAssessment(sampleResult.assessmentId)).resolves.toBeUndefined();
    expect(fetchMock.mock.calls[0]?.[0]).toBe(`/api/assessments/${sampleResult.assessmentId}`);
    expect(fetchMock.mock.calls[0]?.[1]?.method).toBe('DELETE');
    expect(headersOf(fetchMock)[CLIENT_HEADER]).toBe('web');
  });

  it('posts sample loads with the header', async () => {
    const fetchMock = mockFetch(jsonResponse({ assessmentId: sampleResult.assessmentId }, 201));
    const api = createApiClient({ fetch: fetchMock });

    await expect(api.loadSample('contoso-followup')).resolves.toEqual({ assessmentId: sampleResult.assessmentId });
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/samples/contoso-followup');
    expect(fetchMock.mock.calls[0]?.[1]?.method).toBe('POST');
    expect(headersOf(fetchMock)[CLIENT_HEADER]).toBe('web');
  });

  it('encodes identifiers in URLs', async () => {
    const fetchMock = mockFetch(jsonResponse(sampleComparison));
    const api = createApiClient({ fetch: fetchMock });

    await api.compare('a/b', 'c&d');
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/compare?baseline=a%2Fb&current=c%26d');
    expect(api.reportUrl('x y', 'html')).toBe('/api/assessments/x%20y/report.html');
  });

  it('maps the API error envelope to ApiError', async () => {
    const fetchMock = mockFetch(jsonResponse({ error: { code: 'integrity_failed', message: 'Manifest hash mismatch.' } }, 422));
    const api = createApiClient({ fetch: fetchMock });

    const error = await api.getAssessment('id').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ code: 'integrity_failed', message: 'Manifest hash mismatch.', status: 422 });
  });

  it('uses a safe default message for non-JSON errors', () => {
    const error = toApiError(502, '<html><script>alert(1)</script></html>');
    expect(error.code).toBe('http_502');
    expect(error.message).toBe('The local ConfigReview service reported an internal error.');
    expect(error.message).not.toContain('<script>');
  });

  it('maps 404 without a body', () => {
    const error = toApiError(404, '');
    expect(error).toMatchObject({ code: 'http_404', status: 404 });
    expect(error.message).toContain('not found');
  });

  it('truncates very long server messages', () => {
    const error = toApiError(400, JSON.stringify({ error: { code: 'bad', message: 'x'.repeat(5000) } }));
    expect(error.message.length).toBeLessThan(510);
  });

  it('reports network failures as network_error', async () => {
    const api = createApiClient({ fetch: mockFetch(new TypeError('Failed to fetch')) });
    await expect(api.health()).rejects.toMatchObject({ code: 'network_error', status: 0 });
  });

  it('rejects unexpected response shapes', async () => {
    const api = createApiClient({ fetch: mockFetch(jsonResponse({ something: 'else' })) });
    await expect(api.getAssessment('id')).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('rejects invalid JSON bodies', async () => {
    const api = createApiClient({ fetch: mockFetch(new Response('not json', { status: 200 })) });
    await expect(api.listSamples()).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('accepts a valid assessment result', async () => {
    const api = createApiClient({ fetch: mockFetch(jsonResponse(sampleResult)) });
    await expect(api.getAssessment(sampleResult.assessmentId)).resolves.toMatchObject({
      assessmentId: sampleResult.assessmentId,
    });
  });
});

class FakeXhr {
  static last: FakeXhr | null = null;
  method = '';
  url = '';
  headers: Record<string, string> = {};
  body: unknown = null;
  status = 0;
  responseText = '';
  upload: { onprogress: ((e: { lengthComputable: boolean; loaded: number; total: number }) => void) | null } = {
    onprogress: null,
  };
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onabort: (() => void) | null = null;

  constructor() {
    FakeXhr.last = this;
  }
  open(method: string, url: string) {
    this.method = method;
    this.url = url;
  }
  setRequestHeader(name: string, value: string) {
    this.headers[name] = value;
  }
  send(body: unknown) {
    this.body = body;
  }
  abort() {
    this.onabort?.();
  }
}

describe('api client upload', () => {
  const createXhr = () => new FakeXhr() as unknown as XMLHttpRequest;
  const file = new File(['PK'], 'evidence.zip', { type: 'application/zip' });

  it('posts multipart form data with the header and reports progress', async () => {
    const api = createApiClient({ createXhr });
    const progress: number[] = [];
    const promise = api.uploadPackage(file, { onProgress: (f) => progress.push(f) });
    const xhr = FakeXhr.last!;

    expect(xhr.method).toBe('POST');
    expect(xhr.url).toBe('/api/assessments');
    expect(xhr.headers[CLIENT_HEADER]).toBe('web');
    expect(xhr.body).toBeInstanceOf(FormData);
    expect((xhr.body as FormData).get('package')).toBeInstanceOf(File);

    xhr.upload.onprogress?.({ lengthComputable: true, loaded: 50, total: 100 });
    xhr.status = 201;
    xhr.responseText = JSON.stringify({ assessmentId: sampleResult.assessmentId });
    xhr.onload?.();

    await expect(promise).resolves.toEqual({ assessmentId: sampleResult.assessmentId });
    expect(progress).toEqual([0.5]);
  });

  it('maps upload errors', async () => {
    const api = createApiClient({ createXhr });
    const promise = api.uploadPackage(file);
    const xhr = FakeXhr.last!;
    xhr.status = 413;
    xhr.responseText = JSON.stringify({ error: { code: 'package_too_large', message: 'The package exceeds 100 MB.' } });
    xhr.onload?.();
    await expect(promise).rejects.toMatchObject({ code: 'package_too_large', status: 413 });
  });

  it('maps network failures during upload', async () => {
    const api = createApiClient({ createXhr });
    const promise = api.uploadPackage(file);
    FakeXhr.last!.onerror?.();
    await expect(promise).rejects.toMatchObject({ code: 'network_error' });
  });
});
