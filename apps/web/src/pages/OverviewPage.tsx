import type { ControlStatus } from '@adminsecops/core';
import { CONTROL_STATUSES, SEVERITIES, TECHNOLOGY_LABELS } from '@adminsecops/core/vocabulary';
import type { Finding } from '@adminsecops/schemas';
import { Link } from 'react-router';
import { useAssessment } from '../app/AssessmentLayout';
import {
  ConfidenceBadge,
  EffortBadge,
  IntegrityBadge,
  SeverityBadge,
  StatusBadge,
  TierBadge,
} from '../components/Badges';
import { BarList, CoverageBar, StackedBar } from '../components/Charts';
import { PageHeader, Panel } from '../components/PageHeader';
import { groupByTier } from '../lib/findings';
import { environmentName, formatCount, formatDateTime, percent } from '../lib/format';
import { SEVERITY_LABELS, STATUS_LABELS, TIER_DESCRIPTIONS, TIER_LABELS, TIER_ORDER } from '../lib/labels';
import { buildModuleCards, type ModuleCard } from '../lib/modules';

const TOP_PER_TIER = 5;

function statusTone(status: ControlStatus): string {
  return `status-${status.toLowerCase().replace(/_/g, '-')}`;
}

function EnvironmentPanel() {
  const result = useAssessment();
  const { environment, collector } = result.collection;
  const rows: [string, string][] = [
    ['Tenant', environment.tenantDisplayName ?? 'Not collected'],
    ['Tenant ID', environment.tenantId ?? 'Not collected'],
    ['Primary domain', environment.primaryDomain ?? 'Not collected'],
    ['AD forest', environment.adForestName ?? 'Not collected'],
    ['AD domain', environment.adDomainName ?? 'Not collected'],
    ['Assessed (evidence collected)', formatDateTime(result.assessedAt)],
    ['Processed', formatDateTime(result.processedAt)],
    ['Collector', `${collector.name} ${collector.version}`],
    ['PowerShell', collector.powershellVersion ?? 'Not recorded'],
    ['Engine / control library', `${result.engineVersion} / ${result.controlLibraryVersion}`],
  ];
  return (
    <Panel
      title="Environment"
      id="environment"
      actions={
        <Link to="evidence" className="plain-link">
          <IntegrityBadge verified={result.evidence.integrityVerified} />
        </Link>
      }
    >
      <dl className="dl-grid">
        {rows.map(([label, value]) => (
          <div key={label} className="dl-grid__item">
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>
    </Panel>
  );
}

function ModuleCardView({ card }: { card: ModuleCard }) {
  const items = CONTROL_STATUSES.map((s) => ({ key: s, label: STATUS_LABELS[s], value: card.counts[s], tone: statusTone(s) }));
  return (
    <li className={`module-card${card.notCollected ? ' module-card--empty' : ''}`}>
      <h3 className="module-card__title">{card.label}</h3>
      <p className="module-card__tech muted small">{card.technologies.map((t) => TECHNOLOGY_LABELS[t]).join(', ')}</p>
      {card.notCollected ? (
        <p className="module-card__state">
          <strong>Not collected</strong>
          <span className="muted small">
            {card.total === 0
              ? 'No controls were evaluated for this module.'
              : `${formatCount(card.total, 'control')} could not be assessed with the evidence provided.`}
          </span>
        </p>
      ) : (
        <>
          <StackedBar items={items} />
          <ul className="module-card__counts">
            {items
              .filter((i) => i.value > 0)
              .map((i) => (
                <li key={i.key}>
                  <StatusBadge status={i.key} /> <span className="num">{i.value}</span>
                </li>
              ))}
          </ul>
        </>
      )}
      {card.counts.FAIL + card.counts.REVIEW > 0 ? (
        <Link className="module-card__link" to={`findings?module=${card.id}`}>
          View {formatCount(card.counts.FAIL + card.counts.REVIEW, 'finding')}
          <span className="visually-hidden"> for {card.label}</span>
        </Link>
      ) : null}
    </li>
  );
}

function FixFirstPanel({ findings }: { findings: Finding[] }) {
  const groups = groupByTier(findings);
  return (
    <Panel
      title="What should I fix first?"
      id="fix-first"
      actions={
        <Link to="findings" className="button button--small">
          All findings
        </Link>
      }
    >
      <p className="muted small">
        Ordered by severity, status, confidence, exposure and effort. This is an ordering to plan work, not a security
        score.
      </p>
      {findings.length === 0 ? (
        <p>No FAIL or REVIEW findings in this assessment. Check the not-assessed controls below to understand coverage.</p>
      ) : (
        TIER_ORDER.map((tier) => {
          const items = groups[tier];
          if (items.length === 0) return null;
          return (
            <section key={tier} className="tier" aria-labelledby={`tier-${tier}`}>
              <h3 className="tier__title" id={`tier-${tier}`}>
                <TierBadge tier={tier} /> <span className="tier__count">{formatCount(items.length, 'finding')}</span>
              </h3>
              <p className="muted small">{TIER_DESCRIPTIONS[tier]}</p>
              <ol className="fix-list">
                {items.slice(0, TOP_PER_TIER).map((f) => (
                  <li key={f.findingId} className="fix-list__item">
                    <span className="fix-list__rank" aria-label={`Priority rank ${f.priority.rank}`}>
                      {f.priority.rank}
                    </span>
                    <span className="fix-list__main">
                      <Link to={`findings/${encodeURIComponent(f.findingId)}`} className="fix-list__title">
                        {f.title}
                      </Link>
                      <span className="fix-list__meta">
                        <SeverityBadge severity={f.severity} />
                        <ConfidenceBadge confidence={f.confidence} />
                        <EffortBadge effort={f.effort} />
                        <span className="muted small">
                          {formatCount(f.affectedObjectCount, 'affected object')} - {f.controlId}
                        </span>
                      </span>
                    </span>
                  </li>
                ))}
              </ol>
              {items.length > TOP_PER_TIER ? (
                <Link to={`findings?tier=${tier}`} className="small">
                  Show all {items.length} {TIER_LABELS[tier]} findings
                </Link>
              ) : null}
            </section>
          );
        })
      )}
    </Panel>
  );
}

export function OverviewPage() {
  const result = useAssessment();
  const { summary } = result;
  const cards = buildModuleCards(summary);
  const coveragePct = percent(summary.assessmentCoverage.assessed, summary.assessmentCoverage.applicable);
  const errors = result.evidence.issues.filter((i) => i.level === 'error');
  const warnings = result.evidence.issues.filter((i) => i.level === 'warning');
  const notAssessed = result.results.filter((r) => r.status === 'NOT_ASSESSED' || r.status === 'ERROR');

  return (
    <div className="page">
      <PageHeader
        eyebrow="Assessment overview"
        title={environmentName(result.collection.environment)}
        description={
          <p>
            Evidence collected {formatDateTime(result.assessedAt)}. {formatCount(summary.controlsEvaluated, 'control')}{' '}
            evaluated, {formatCount(result.findings.length, 'finding')}.
          </p>
        }
      />

      <dl className="overview-metrics" aria-label="Assessment summary">
        <div><dt>Assessed</dt><dd>{summary.assessmentCoverage.assessed}</dd><dd className="metric-caption">Controls with evidence</dd></div>
        <div><dt>Findings</dt><dd>{result.findings.length}</dd><dd className="metric-caption">Prioritized for review</dd></div>
        <div><dt>Needs review</dt><dd>{summary.byStatus.REVIEW}</dd><dd className="metric-caption">Require your judgment</dd></div>
        <div><dt>Not assessed</dt><dd>{summary.byStatus.NOT_ASSESSED + summary.byStatus.ERROR}</dd><dd className="metric-caption">Unknown, never passing</dd></div>
      </dl>
      <details className="environment-details"><summary>Environment and collection details</summary><EnvironmentPanel /></details>

      <section aria-labelledby="modules-heading" className="section">
        <h2 id="modules-heading" className="section__title">
          Modules
        </h2>
        <ul className="module-grid">
          {cards.map((card) => (
            <ModuleCardView key={card.id} card={card} />
          ))}
        </ul>
      </section>

      <div className="grid grid--3">
        <Panel title="Control results by status" id="status-dist">
          <BarList
            caption={`${formatCount(summary.controlsEvaluated, 'control')} evaluated`}
            items={CONTROL_STATUSES.map((s) => ({
              key: s,
              label: STATUS_LABELS[s],
              value: summary.byStatus[s],
              tone: statusTone(s),
            }))}
          />
        </Panel>
        <Panel title="Findings by severity" id="severity-dist">
          <BarList
            caption={`${formatCount(result.findings.length, 'finding')} (FAIL and REVIEW)`}
            items={SEVERITIES.map((s) => ({
              key: s,
              label: SEVERITY_LABELS[s],
              value: summary.findingsBySeverity[s],
              tone: `severity-${s}`,
            }))}
          />
        </Panel>
        <Panel title="Assessment coverage" id="coverage">
          <p className="coverage__value">
            <span className="coverage__number">{coveragePct === null ? 'n/a' : `${coveragePct}%`}</span>
            <span>
              {summary.assessmentCoverage.assessed} of {summary.assessmentCoverage.applicable} applicable controls could be
              assessed
            </span>
          </p>
          <CoverageBar assessed={summary.assessmentCoverage.assessed} applicable={summary.assessmentCoverage.applicable} />
          <p className="muted small">
            Coverage shows how much of the control library the collected evidence allowed ConfigReview to evaluate
            (PASS, FAIL or REVIEW). It is not a security score: high coverage with many failures is not secure, and low
            coverage means parts of the environment were not checked.
          </p>
        </Panel>
      </div>

      <FixFirstPanel findings={result.findings} />

      <div className="grid grid--2">
        <Panel
          title="Collection errors and warnings"
          id="collection-issues"
          actions={
            <Link to="evidence#issues" className="button button--small">
              Evidence details
            </Link>
          }
        >
          {errors.length === 0 && warnings.length === 0 ? (
            <p>The collector and the ingestion checks reported no errors or warnings.</p>
          ) : (
            <>
              <p>
                <strong>{formatCount(errors.length, 'error')}</strong> and{' '}
                <strong>{formatCount(warnings.length, 'warning')}</strong> were reported. Affected datasets may lead to
                controls that are not assessed.
              </p>
              <ul className="issue-list">
                {[...errors, ...warnings].slice(0, 6).map((issue, index) => (
                  <li key={`${issue.code}-${index}`} className={`issue-list__item issue-list__item--${issue.level}`}>
                    <span className="issue-list__level">{issue.level === 'error' ? 'Error' : 'Warning'}</span>
                    <span>
                      {issue.module ?? 'Package'}
                      {issue.datasetId !== null ? ` / ${issue.datasetId}` : ''}: {issue.message}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </Panel>
        <Panel
          title="Not assessed"
          id="not-assessed"
          actions={
            <Link to="controls?status=NOT_ASSESSED" className="button button--small">
              All controls
            </Link>
          }
        >
          {notAssessed.length === 0 ? (
            <p>Every applicable control was assessed.</p>
          ) : (
            <>
              <p>
                {formatCount(notAssessed.length, 'control')} could not be assessed. Their status is unknown, not passed.
              </p>
              <ul className="issue-list">
                {notAssessed.slice(0, 6).map((r) => (
                  <li key={r.controlId} className="issue-list__item">
                    <StatusBadge status={r.status} />
                    <span>
                      <strong>{r.controlId}</strong> {r.title}. <span className="muted">{r.statusReason}</span>
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </Panel>
      </div>
    </div>
  );
}
