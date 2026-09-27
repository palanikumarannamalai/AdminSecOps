import { render, type RenderResult } from '@testing-library/react';
import type { ReactElement } from 'react';
import { MemoryRouter } from 'react-router';
import { vi } from 'vitest';
import type { ApiClient } from '../api/client';
import { AppRoutes } from '../App';
import { AppProvider } from '../app/context';
import { followupListItem, sampleComparison, sampleListItem, sampleResult } from './sample-result';

/** ApiClient whose methods are vi.fn() mocks returning the sample data. */
export function createFakeApi(overrides: Partial<ApiClient> = {}): ApiClient {
  return {
    mode: 'local',
    health: vi.fn(() =>
      Promise.resolve({
        status: 'ok' as const,
        product: 'ConfigReview' as const,
        version: '0.1.0',
        engineVersion: '0.1.0',
        controlLibraryVersion: '0.1.0',
      }),
    ),
    listAssessments: vi.fn(() => Promise.resolve([followupListItem, sampleListItem])),
    getAssessment: vi.fn(() => Promise.resolve(sampleResult)),
    deleteAssessment: vi.fn(() => Promise.resolve()),
    uploadPackage: vi.fn(() => Promise.resolve({ assessmentId: sampleResult.assessmentId })),
    listSamples: vi.fn(() =>
      Promise.resolve([{ name: 'contoso' as const, title: 'Contoso', description: 'Fictional hybrid organization.' }]),
    ),
    loadSample: vi.fn(() => Promise.resolve({ assessmentId: sampleResult.assessmentId })),
    compare: vi.fn(() => Promise.resolve(sampleComparison)),
    listControls: vi.fn(() => Promise.resolve({ controls: [], libraryVersion: '0.1.0' })),
    listDatasets: vi.fn(() => Promise.resolve([])),
    reportUrl: (id, format) => `/api/assessments/${id}/report.${format}`,
    ...overrides,
  };
}

/** Render the full application at `route` with a fake API. */
export function renderApp(route: string, api: ApiClient = createFakeApi()): RenderResult & { api: ApiClient } {
  const view = render(
    <MemoryRouter initialEntries={[route]}>
      <AppProvider api={api}>
        <AppRoutes />
      </AppProvider>
    </MemoryRouter>,
  );
  return { ...view, api };
}

export function renderWithRouter(ui: ReactElement, route = '/'): RenderResult {
  return render(<MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>);
}
