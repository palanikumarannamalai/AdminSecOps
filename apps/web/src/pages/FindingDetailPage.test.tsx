import { screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { renderWithRouter } from '../test/render';
import { ASSESSMENT_ID, sampleFindings } from '../test/sample-result';
import { FINDING_SECTIONS, FindingDetail } from './FindingDetailPage';

const base = sampleFindings[0]!;

describe('FindingDetail', () => {
  it('renders every question section heading', () => {
    renderWithRouter(<FindingDetail finding={base} assessmentId={ASSESSMENT_ID} />);
    const headings = screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent);
    for (const section of FINDING_SECTIONS) expect(headings).toContain(section.title);
    expect(FINDING_SECTIONS.map((s) => s.title)).toEqual([
      'WHAT DID YOU FIND?',
      'WHY DOES IT MATTER?',
      'WHAT DID YOU OBSERVE?',
      'WHAT SHOULD IT BE?',
      'WHAT IS AFFECTED?',
      'WHAT EVIDENCE SUPPORTS THIS?',
      'WHAT SHOULD I CHECK BEFORE CHANGING IT?',
      'HOW DO I FIX IT?',
      'HOW DO I ROLL IT BACK?',
      'HOW DO I VERIFY THE FIX?',
      'AUTHORITATIVE REFERENCES',
    ]);
  });

  it('shows control, evidence hash, remediation steps and the script disclaimer', () => {
    renderWithRouter(<FindingDetail finding={base} assessmentId={ASSESSMENT_ID} />);
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(base.title);
    expect(screen.getAllByText('ADCS-TPL-001').length).toBeGreaterThan(0);
    expect(screen.getByText(base.evidence[0]!.sha256!)).toBeTruthy();
    expect(screen.getByText(/AdminSecOps never runs scripts/)).toBeTruthy();
    const fix = document.getElementById('section-fix')!;
    expect(within(fix).getAllByRole('listitem')).toHaveLength(base.remediation.steps.length);
    expect(fix.querySelector('pre > code')?.textContent).toBe(base.remediation.scriptExample);
  });

  it('renders references as https links with noopener noreferrer', () => {
    renderWithRouter(<FindingDetail finding={base} assessmentId={ASSESSMENT_ID} />);
    const refs = document.getElementById('section-references')!;
    const links = within(refs).getAllByRole('link');
    expect(links).toHaveLength(2);
    for (const link of links) {
      expect(link.getAttribute('href')).toMatch(/^https:\/\//);
      expect(link.getAttribute('rel')).toBe('noopener noreferrer');
      expect(link.getAttribute('target')).toBe('_blank');
    }
  });

  it('does not render non-https references as links', () => {
    const finding = {
      ...base,
      references: [{ title: 'Bad link', url: 'javascript:alert(1)', publisher: 'Other' as const }],
    };
    renderWithRouter(<FindingDetail finding={finding} assessmentId={ASSESSMENT_ID} />);
    const refs = document.getElementById('section-references')!;
    expect(within(refs).queryAllByRole('link')).toHaveLength(0);
    expect(within(refs).getByText('Bad link')).toBeTruthy();
  });

  it('escapes markup in finding text', () => {
    const payload = '<script>window.__pwned = true</script><img src=x onerror="window.__pwned=true">';
    const finding = {
      ...base,
      title: `Title ${payload}`,
      description: `Description ${payload}`,
      risk: payload,
      observedState: { summary: payload, facts: [{ label: payload, value: payload }] },
      affectedObjects: [{ type: 'user', id: payload, name: payload, detail: payload }],
      notes: [payload],
      remediation: { ...base.remediation, steps: [payload], scriptExample: payload },
    };
    const { container } = renderWithRouter(<FindingDetail finding={finding} assessmentId={ASSESSMENT_ID} />);
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('img')).toBeNull();
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe(`Title ${payload}`);
    expect(screen.getAllByText(payload).length).toBeGreaterThan(3);
    expect((window as unknown as { __pwned?: boolean }).__pwned).toBeUndefined();
  });

  it('notes when more objects are affected than shown', () => {
    const finding = { ...base, affectedObjectCount: 750 };
    renderWithRouter(<FindingDetail finding={finding} assessmentId={ASSESSMENT_ID} />);
    expect(screen.getByText(/Showing the first 1;/)).toBeTruthy();
  });
});
