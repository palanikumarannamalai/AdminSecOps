import { TECHNOLOGY_LABELS } from '@adminsecops/core/vocabulary';
import type { Finding } from '@adminsecops/schemas';
import type { ReactNode } from 'react';
import { Link, useParams } from 'react-router';
import { useAssessment } from '../app/AssessmentLayout';
import {
  CollectionStatusBadge,
  ConfidenceBadge,
  EffortBadge,
  SeverityBadge,
  StatusBadge,
  TierBadge,
} from '../components/Badges';
import { CopyButton } from '../components/CopyButton';
import { ExternalLink } from '../components/ExternalLink';
import { PageHeader } from '../components/PageHeader';
import { EmptyState } from '../components/States';
import { formatCount, formatDateTime, formatFactValue } from '../lib/format';
import { frameworkLabel } from '../lib/labels';
import { moduleForTechnology, moduleLabel } from '../lib/modules';
import { assessmentPath } from '../lib/paths';

/** Section headings, in order. Exported so tests can assert that every question is answered. */
export const FINDING_SECTIONS = [
  { id: 'what', title: 'WHAT DID YOU FIND?' },
  { id: 'why', title: 'WHY DOES IT MATTER?' },
  { id: 'observed', title: 'WHAT DID YOU OBSERVE?' },
  { id: 'expected', title: 'WHAT SHOULD IT BE?' },
  { id: 'affected', title: 'WHAT IS AFFECTED?' },
  { id: 'evidence', title: 'WHAT EVIDENCE SUPPORTS THIS?' },
  { id: 'before', title: 'WHAT SHOULD I CHECK BEFORE CHANGING IT?' },
  { id: 'fix', title: 'HOW DO I FIX IT?' },
  { id: 'rollback', title: 'HOW DO I ROLL IT BACK?' },
  { id: 'verify', title: 'HOW DO I VERIFY THE FIX?' },
  { id: 'references', title: 'AUTHORITATIVE REFERENCES' },
] as const;

type SectionId = (typeof FINDING_SECTIONS)[number]['id'] | 'frameworks' | 'priority' | 'notes';

function Section({ id, title, children }: { id: SectionId; title: string; children: ReactNode }) {
  return (
    <section className="qa" id={`section-${id}`} aria-labelledby={`heading-${id}`}>
      <h2 className="qa__title" id={`heading-${id}`}>
        {title}
      </h2>
      <div className="qa__body">{children}</div>
    </section>
  );
}

function titleOf(id: (typeof FINDING_SECTIONS)[number]['id']): string {
  return FINDING_SECTIONS.find((s) => s.id === id)?.title ?? id;
}

function TextList({ items, ordered = false, empty }: { items: readonly string[]; ordered?: boolean; empty: string }) {
  if (items.length === 0) return <p className="muted">{empty}</p>;
  const children = items.map((item, index) => <li key={index}>{item}</li>);
  return ordered ? <ol className="steps">{children}</ol> : <ul className="bullets">{children}</ul>;
}

function EvidenceTable({ finding }: { finding: Finding }) {
  if (finding.evidence.length === 0) return <p className="muted">No evidence references were recorded for this finding.</p>;
  return (
    <ul className="evidence-refs">
      {finding.evidence.map((ref, index) => (
        <li key={`${ref.datasetId}-${index}`} className="evidence-ref">
          <dl className="dl-grid dl-grid--compact">
            <div className="dl-grid__item">
              <dt>Dataset</dt>
              <dd>
                <code>{ref.datasetId}</code>
              </dd>
            </div>
            <div className="dl-grid__item">
              <dt>File in package</dt>
              <dd>{ref.path !== null ? <code>{ref.path}</code> : 'Not available'}</dd>
            </div>
            <div className="dl-grid__item">
              <dt>Collected</dt>
              <dd>{formatDateTime(ref.collectedAt)}</dd>
            </div>
            <div className="dl-grid__item">
              <dt>Collection status</dt>
              <dd>
                <CollectionStatusBadge status={ref.status} />
              </dd>
            </div>
            <div className="dl-grid__item dl-grid__item--full">
              <dt>SHA-256</dt>
              <dd className="hash-cell">
                {ref.sha256 !== null ? (
                  <>
                    <code className="hash">{ref.sha256}</code>
                    <CopyButton text={ref.sha256} label="Copy hash" />
                  </>
                ) : (
                  'Not available'
                )}
              </dd>
            </div>
            <div className="dl-grid__item dl-grid__item--full">
              <dt>Source</dt>
              <dd>
                {ref.source === null ? (
                  'Not recorded'
                ) : (
                  <>
                    <span>
                      {ref.source.system}
                      {ref.source.apiVersion !== null ? ` (API version ${ref.source.apiVersion})` : ''}
                    </span>
                    {ref.source.operations.length > 0 ? (
                      <ul className="operations">
                        {ref.source.operations.map((op, i) => (
                          <li key={i}>
                            <code>{op}</code>
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </>
                )}
              </dd>
            </div>
          </dl>
        </li>
      ))}
    </ul>
  );
}

export function FindingDetail({ finding, assessmentId }: { finding: Finding; assessmentId: string }) {
  const shown = finding.affectedObjects.length;
  const script = finding.remediation.scriptExample;

  return (
    <article className="page finding" aria-labelledby="finding-title">
      <nav aria-label="Breadcrumb" className="breadcrumb">
        <Link to={assessmentPath(assessmentId, 'findings')}>Findings</Link>
        <span aria-hidden="true"> / </span>
        <span aria-current="page">{finding.controlId}</span>
      </nav>
      <PageHeader
        eyebrow={`Priority rank ${finding.priority.rank} - ${moduleLabel(moduleForTechnology(finding.technology))}`}
        title={finding.title}
        titleId="finding-title"
      />
      <div className="finding__badges">
        <StatusBadge status={finding.status} />
        {finding.status === 'REVIEW' ? <span>Potential impact if confirmed: <SeverityBadge severity={finding.severity} /></span> : <SeverityBadge severity={finding.severity} />}
        {finding.status === 'REVIEW' ? <span className="badge">Confirmation pending</span> : <ConfidenceBadge confidence={finding.confidence} />}
        <TierBadge tier={finding.priority.tier} />
        <EffortBadge effort={finding.effort} />
      </div>

      <nav className="toc" aria-label="Sections of this finding">
        <ul>
          {FINDING_SECTIONS.map((s) => (
            <li key={s.id}>
              <a href={`#section-${s.id}`} onClick={event => { event.preventDefault(); const section = document.getElementById(`section-${s.id}`); if (section) { section.tabIndex = -1; section.focus({ preventScroll: true }); section.scrollIntoView({ block: 'start' }); } }}>{s.title}</a>
            </li>
          ))}
        </ul>
      </nav>

      <Section id="what" title={titleOf('what')}>
        <p className="lead">{finding.observedState.summary}</p>
        {finding.status === 'REVIEW' ? <p role="note">This check needs verification. It does not establish a confirmed security gap. Validate the evidence, exclusions and alternative controls before making changes.</p> : null}
        <p>{finding.description}</p>
        <dl className="dl-grid">
          <div className="dl-grid__item">
            <dt>Status</dt>
            <dd>
              <StatusBadge status={finding.status} />
            </dd>
          </div>
          <div className="dl-grid__item">
            <dt>{finding.status === 'REVIEW' ? 'Potential impact if confirmed' : 'Severity'}</dt>
            <dd>
              <SeverityBadge severity={finding.severity} />
            </dd>
          </div>
          <div className="dl-grid__item">
            <dt>{finding.status === 'REVIEW' ? 'Evidence confidence (confirmation pending)' : 'Confidence'}</dt>
            <dd>
              <ConfidenceBadge confidence={finding.confidence} />
            </dd>
          </div>
          <div className="dl-grid__item">
            <dt>Control</dt>
            <dd>
              <code>{finding.controlId}</code> version {finding.controlVersion}
            </dd>
          </div>
          <div className="dl-grid__item">
            <dt>Technology</dt>
            <dd>{TECHNOLOGY_LABELS[finding.technology]}</dd>
          </div>
          <div className="dl-grid__item">
            <dt>Category</dt>
            <dd>{finding.category}</dd>
          </div>
        </dl>
      </Section>

      <Section id="why" title={titleOf('why')}>
        <p>{finding.risk}</p>
      </Section>

      <Section id="observed" title={titleOf('observed')}>
        <p>{finding.observedState.summary}</p>
        {finding.observedState.facts.length > 0 ? (
          <div className="table-wrap" tabIndex={0}>
            <table className="table table--compact">
              <caption className="visually-hidden">Observed facts</caption>
              <thead>
                <tr>
                  <th scope="col">Observation</th>
                  <th scope="col">Value</th>
                </tr>
              </thead>
              <tbody>
                {finding.observedState.facts.map((fact, index) => (
                  <tr key={index}>
                    <th scope="row">{fact.label}</th>
                    <td>{formatFactValue(fact.value)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Section>

      <Section id="expected" title={titleOf('expected')}>
        <p>{finding.expectedState}</p>
      </Section>

      <Section id="affected" title={titleOf('affected')}>
        <p>
          {formatCount(finding.affectedObjectCount, 'affected object')}.
          {finding.affectedObjectCount > shown
            ? ` Showing the first ${shown}; the complete list is in the JSON report and the evidence package.`
            : ''}
        </p>
        {shown > 0 ? (
          <div className="table-wrap" tabIndex={0}>
            <table className="table table--compact">
              <caption className="visually-hidden">Affected objects</caption>
              <thead>
                <tr>
                  <th scope="col">Type</th>
                  <th scope="col">Name</th>
                  <th scope="col">Identifier</th>
                  <th scope="col">Detail</th>
                </tr>
              </thead>
              <tbody>
                {finding.affectedObjects.map((o, index) => (
                  <tr key={`${o.id}-${index}`}>
                    <td>{o.type}</td>
                    <th scope="row">{o.name === '' ? <span className="muted">(no name)</span> : o.name}</th>
                    <td>
                      <code className="break">{o.id}</code>
                    </td>
                    <td>{o.detail ?? ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Section>

      <Section id="evidence" title={titleOf('evidence')}>
        <EvidenceTable finding={finding} />
        <p className="small">
          <Link to={assessmentPath(assessmentId, 'evidence')}>View integrity checks for all evidence files</Link>
        </p>
      </Section>

      <Section id="before" title={titleOf('before')}>
        <TextList items={finding.implementationConsiderations} empty="No specific considerations are recorded." />
        <h3 className="qa__subtitle">Impact of the change</h3>
        <p>{finding.impact}</p>
      </Section>

      <Section id="fix" title={titleOf('fix')}>
        <p>{finding.remediation.summary}</p>
        <TextList items={finding.remediation.steps} ordered empty="No steps are recorded." />
        {script !== undefined && script !== '' ? (
          <div className="script">
            <div className="script__header">
              <h3 className="qa__subtitle">Script example</h3>
              <CopyButton text={script} label="Copy script" />
            </div>
            <p className="script__note" role="note">
              Example for you to review, adapt and run yourself. AdminSecOps never runs scripts or changes your
              environment. Test in a non-production environment first.
            </p>
            <pre className="code" tabIndex={0} aria-label="Script example">
              <code>{script}</code>
            </pre>
          </div>
        ) : null}
      </Section>

      <Section id="rollback" title={titleOf('rollback')}>
        <TextList items={finding.rollback} ordered empty="No rollback steps are recorded." />
      </Section>

      <Section id="verify" title={titleOf('verify')}>
        <TextList items={finding.validation} ordered empty="No verification steps are recorded." />
        <p className="muted small">After changing the configuration, collect new evidence and compare it with this assessment.</p>
      </Section>

      <Section id="references" title={titleOf('references')}>
        {finding.references.length === 0 ? (
          <p className="muted">No references are recorded.</p>
        ) : (
          <ul className="references">
            {finding.references.map((ref, index) => (
              <li key={index}>
                <ExternalLink href={ref.url}>{ref.title}</ExternalLink> <span className="muted small">{ref.publisher}</span>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section id="frameworks" title="Framework mappings">
        {finding.frameworkMappings.length === 0 ? (
          <p className="muted">This control is not mapped to a framework.</p>
        ) : (
          <ul className="bullets">
            {finding.frameworkMappings.map((m, index) => (
              <li key={index}>
                {frameworkLabel(m.framework)}: <code>{m.id}</code>
                {m.note !== undefined ? <span className="muted"> ({m.note})</span> : null}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section id="priority" title="Why this priority?">
        <p>
          Rank {finding.priority.rank}, tier <TierBadge tier={finding.priority.tier} />. The rank orders work; it is not a
          security score.
        </p>
        <TextList items={finding.priority.factors} empty="No priority factors are recorded." />
      </Section>

      {finding.notes.length > 0 || finding.tags.length > 0 ? (
        <Section id="notes" title="Notes">
          <TextList items={finding.notes} empty="No notes." />
          {finding.tags.length > 0 ? (
            <p className="tags">
              {finding.tags.map((tag) => (
                <span key={tag} className="tag">
                  {tag}
                </span>
              ))}
            </p>
          ) : null}
        </Section>
      ) : null}
    </article>
  );
}

export function FindingDetailPage() {
  const result = useAssessment();
  const { findingId = '' } = useParams();
  const finding = result.findings.find((f) => f.findingId === findingId);
  if (finding === undefined) {
    return (
      <EmptyState title="Finding not found">
        <p>This finding is not part of the selected assessment.</p>
        <p>
          <Link to={assessmentPath(result.assessmentId, 'findings')}>Back to findings</Link>
        </p>
      </EmptyState>
    );
  }
  return <FindingDetail finding={finding} assessmentId={result.assessmentId} />;
}
