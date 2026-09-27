import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ApiError } from './api/client';
import { createFakeApi, renderApp } from './test/render';
import { ASSESSMENT_ID, sampleResult } from './test/sample-result';

const base = `/assessments/${ASSESSMENT_ID}`;

describe('application routes', () => {
  it('renders the home page with tagline, samples and assessments', async () => {
    renderApp('/');
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Evidence-based security configuration review for Microsoft environments.');
    await waitFor(() => expect(screen.getByRole('button', { name: 'Load sample' })).toBeTruthy());
    const table = await screen.findByRole('table');
    expect(within(table).getAllByRole('row')).toHaveLength(3);
  });

  it('deletes an assessment after confirmation', async () => {
    const api = createFakeApi();
    const user = userEvent.setup();
    renderApp('/', api);
    const buttons = await screen.findAllByRole('button', { name: /^Delete assessment/ });
    await user.click(buttons[0]!);
    await user.click(screen.getByRole('button', { name: 'Confirm delete' }));
    expect(api.deleteAssessment).toHaveBeenCalledTimes(1);
  });

  it('renders the overview with modules, coverage and fix-first tiers but no score', async () => {
    renderApp(base);
    await screen.findByRole('heading', { name: 'What should I fix first?' });
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Contoso production');
    for (const label of ['Microsoft 365', 'Entra ID', 'Azure', 'Intune', 'Active Directory', 'Windows']) {
      expect(screen.getByRole('heading', { level: 3, name: label })).toBeTruthy();
    }
    expect(screen.getAllByText('Not collected').length).toBeGreaterThanOrEqual(3);
    expect(screen.getByRole('heading', { name: 'Assessment coverage' })).toBeTruthy();
    expect(screen.getByText(/It is not a security score/)).toBeTruthy();
    expect(screen.getAllByText('Fix now').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Fix next').length).toBeGreaterThan(0);
  });

  it('renders the findings table sorted by priority and filters by module from the URL', async () => {
    renderApp(`${base}/findings?module=ad`);
    const table = await screen.findByRole('table');
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows.map((r) => within(r).getAllByRole('cell')[0]?.textContent)).toEqual(['1', '4']);
  });

  it('opens a finding detail page', async () => {
    renderApp(`${base}/findings/${encodeURIComponent(sampleResult.findings[1]!.findingId)}`);
    expect(await screen.findByRole('heading', { name: 'WHAT DID YOU FIND?' })).toBeTruthy();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(sampleResult.findings[1]!.title);
  });

  it('renders controls, evidence, inventory, frameworks and reports pages', async () => {
    const { unmount } = renderApp(`${base}/controls?status=NOT_ASSESSED`);
    expect(await screen.findByText('AZ-DEF-001')).toBeTruthy();
    expect(screen.queryByText('ADCS-TPL-001')).toBeNull();
    unmount();

    const evidence = renderApp(`${base}/evidence`);
    expect(await screen.findByText('Integrity verified.')).toBeTruthy();
    expect(screen.getByText('SchemaValidationFailed')).toBeTruthy();
    evidence.unmount();

    const inventory = renderApp(`${base}/inventory`);
    expect(await screen.findByText('Guest users')).toBeTruthy();
    expect(screen.getByText('Not collected')).toBeTruthy();
    inventory.unmount();

    const frameworks = renderApp(`${base}/frameworks`);
    expect(await screen.findByRole('heading', { name: 'MITRE ATT&CK (Enterprise)' })).toBeTruthy();
    expect(screen.getByText('T1649')).toBeTruthy();
    frameworks.unmount();

    renderApp(`${base}/reports`);
    const html = await screen.findByRole('link', { name: 'Download HTML report' });
    expect(html.getAttribute('href')).toBe(`/api/assessments/${ASSESSMENT_ID}/report.html`);
  });

  it('shows a not-found state for an unknown assessment', async () => {
    const api = createFakeApi({
      getAssessment: vi.fn(() => Promise.reject(new ApiError('not_found', 'Assessment not found.', 404))),
    });
    renderApp('/assessments/unknown', api);
    expect(await screen.findByRole('heading', { name: 'Assessment not found' })).toBeTruthy();
  });

  it('shows an error state with retry when the service is unreachable', async () => {
    const api = createFakeApi({
      getAssessment: vi.fn(() => Promise.reject(new ApiError('network_error', 'Cannot reach the local service.', 0))),
    });
    renderApp(base, api);
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeTruthy();
  });
});
