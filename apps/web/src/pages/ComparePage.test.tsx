import { render, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { createFakeApi, renderApp } from '../test/render';
import { ASSESSMENT_ID, FOLLOWUP_ASSESSMENT_ID, sampleComparison } from '../test/sample-result';
import { ComparisonView } from './ComparePage';

describe('ComparisonView', () => {
  it('shows direction, counts and each change list', () => {
    render(<ComparisonView comparison={sampleComparison} baselineName="Contoso" currentName="Contoso follow-up" />);

    expect(screen.getByText('Mixed')).toBeTruthy();
    expect(screen.getByText('Some findings were resolved and some new findings appeared.')).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();

    const newPanel = screen.getByRole('region', { name: 'New findings (1)' });
    expect(within(newPanel).getByText('Guest users can invite other guests')).toBeTruthy();
    const resolved = screen.getByRole('region', { name: 'Resolved findings (2)' });
    expect(within(resolved).getAllByRole('row')).toHaveLength(3);
    const changed = screen.getByRole('region', { name: 'Changed findings (1)' });
    expect(within(changed).getByText('Affected objects: 3 to 1')).toBeTruthy();
    expect(within(changed).getByText(/adele.vance@contoso.example/)).toBeTruthy();
    const controls = screen.getByRole('region', { name: 'Control status changes (2)' });
    expect(within(controls).getByText('Not evaluated')).toBeTruthy();
  });

  it('warns when the assessments are from different environments', () => {
    render(
      <ComparisonView
        comparison={{ ...sampleComparison, sameEnvironment: false }}
        baselineName="Contoso"
        currentName="Fabrikam"
      />,
    );
    expect(screen.getByRole('alert').textContent).toContain('different environments');
  });

  it('shows empty states when nothing changed', () => {
    render(
      <ComparisonView
        comparison={{
          ...sampleComparison,
          newFindings: [],
          resolvedFindings: [],
          changedFindings: [],
          controlStatusChanges: [],
          direction: 'unchanged',
        }}
        baselineName="A"
        currentName="B"
      />,
    );
    expect(screen.getByText('Unchanged')).toBeTruthy();
    expect(screen.getByText('No new findings.')).toBeTruthy();
    expect(screen.getByText('No findings were resolved.')).toBeTruthy();
  });
});

describe('ComparePage', () => {
  it('compares the older assessment (baseline) with the newest (current) by default', async () => {
    const api = createFakeApi();
    renderApp('/compare', api);
    await waitFor(() => expect(api.compare).toHaveBeenCalled());
    expect(api.compare).toHaveBeenCalledWith(ASSESSMENT_ID, FOLLOWUP_ASSESSMENT_ID, expect.anything());
    await waitFor(() => expect(screen.getByText('Mixed')).toBeTruthy());
  });

  it('refuses to compare an assessment with itself', async () => {
    const api = createFakeApi();
    renderApp(`/compare?baseline=${ASSESSMENT_ID}&current=${ASSESSMENT_ID}`, api);
    await waitFor(() => expect(screen.getByText('Select two different assessments.')).toBeTruthy());
    expect(api.compare).not.toHaveBeenCalled();
  });
});
