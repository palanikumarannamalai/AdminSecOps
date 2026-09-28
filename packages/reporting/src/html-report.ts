import {
  PRODUCT_DESCRIPTION,
  PRODUCT_NAME,
  PRODUCT_TAGLINE,
  SEVERITIES,
  TECHNOLOGY_LABELS,
  sha256Base64,
  type ControlStatus,
} from '@adminsecops/core';
import { FRAMEWORKS, type AssessmentResult, type ControlResult, type Finding, type PriorityTier } from '@adminsecops/schemas';
import { anchorId, html, link, SafeHtml } from './html-builder.js';
import { REPORT_CSS } from './report-style.js';

export interface HtmlReportOptions {
  executiveOnly?: boolean;
  /** Override the generation timestamp (for reproducible output). */
  generatedAt?: Date;
  /** Maximum affected objects rendered per finding (the full count is always shown). */
  maxAffectedObjects?: number;
}

const TIER_LABELS: Record<PriorityTier, string> = {
  'fix-now': 'Fix now',
  'fix-next': 'Fix next',
  plan: 'Plan',
  review: 'Review',
};

const STATUS_LABELS: Record<ControlStatus, string> = {
  PASS: 'Pass',
  FAIL: 'Fail',
  REVIEW: 'Review',
  NOT_APPLICABLE: 'Not applicable',
  NOT_ASSESSED: 'Not assessed',
  ERROR: 'Error',
};

function statusBadge(status: ControlStatus): SafeHtml {
  return html`<span class="badge status-${status.toLowerCase()}">${STATUS_LABELS[status]}</span>`;
}

function severityBadge(severity: string): SafeHtml {
  return html`<span class="badge sev-${severity}">${severity}</span>`;
}

function environmentName(result: AssessmentResult): string {
  const env = result.collection.environment;
  return env.label ?? env.tenantDisplayName ?? env.primaryDomain ?? env.adForestName ?? 'Unnamed environment';
}

function list(items: readonly string[], ordered = false): SafeHtml {
  if (items.length === 0) return html`<p class="muted">None.</p>`;
  const body = items.map((i) => html`<li>${i}</li>`);
  return ordered ? html`<ol>${body}</ol>` : html`<ul>${body}</ul>`;
}

function summarySection(result: AssessmentResult): SafeHtml {
  const s = result.summary;
  const statuses: ControlStatus[] = ['FAIL', 'REVIEW', 'PASS', 'NOT_APPLICABLE', 'NOT_ASSESSED', 'ERROR'];
  return html`<section id="summary">
    <h2>Assessment summary</h2>
    <div class="cards">
      ${statuses.map((st) => html`<div class="card"><div class="card-value">${s.byStatus[st]}</div><div class="card-label">${STATUS_LABELS[st]}</div></div>`)}
    </div>
    <p>
      <strong>Assessment coverage:</strong> ${s.assessmentCoverage.assessed} of ${s.assessmentCoverage.applicable} applicable controls could be assessed
      from the collected evidence. This is a coverage measure, not a security score: controls that were not assessed are
      unknown, not compliant.
    </p>
    <table>
      <caption>Findings by severity</caption>
      <thead><tr>${SEVERITIES.map((sev) => html`<th>${sev}</th>`)}</tr></thead>
      <tbody><tr>${SEVERITIES.map((sev) => html`<td>${s.findingsBySeverity[sev]}</td>`)}</tr></tbody>
    </table>
    <table>
      <caption>Results by technology</caption>
      <thead><tr><th>Technology</th>${statuses.map((st) => html`<th>${STATUS_LABELS[st]}</th>`)}</tr></thead>
      <tbody>
        ${Object.entries(s.byTechnology)
          .filter(([, counts]) => Object.values(counts).some((n) => n > 0))
          .map(
            ([tech, counts]) =>
              html`<tr><th scope="row">${TECHNOLOGY_LABELS[tech as keyof typeof TECHNOLOGY_LABELS] ?? tech}</th>${statuses.map((st) => html`<td>${counts[st]}</td>`)}</tr>`,
          )}
      </tbody>
    </table>
  </section>`;
}

function fixFirstSection(findings: readonly Finding[]): SafeHtml {
  const tiers: PriorityTier[] = ['fix-now', 'fix-next', 'plan', 'review'];
  return html`<section id="fix-first">
    <h2>What should I fix first?</h2>
    <p class="muted">Findings are ordered deterministically by severity, then confirmed failures before items needing review, then confidence,
    exposure and effort. The order is a recommendation, not a score.</p>
    ${tiers.map((tier) => {
      const items = findings.filter((f) => f.priority.tier === tier);
      if (items.length === 0) return '';
      return html`<h3>${TIER_LABELS[tier]} (${items.length})</h3>
        <table>
          <thead><tr><th>#</th><th>Finding</th><th>Severity</th><th>Status</th><th>Confidence</th><th>Affected</th><th>Effort</th></tr></thead>
          <tbody>
            ${items.map(
              (f) => html`<tr>
                <td>${f.priority.rank}</td>
                <td><a href="#${anchorId('finding', f.controlId)}">${f.title}</a><div class="muted small">${f.controlId} - ${TECHNOLOGY_LABELS[f.technology]}</div></td>
                <td>${severityBadge(f.severity)}</td>
                <td>${statusBadge(f.status)}</td>
                <td>${f.confidence}</td>
                <td>${f.affectedObjectCount}</td>
                <td>${f.effort}</td>
              </tr>`,
            )}
          </tbody>
        </table>`;
    })}
    ${findings.length === 0 ? html`<p>No findings. Review the not-assessed controls below before concluding the environment is secure.</p>` : ''}
  </section>`;
}

function findingSection(f: Finding, maxObjects: number): SafeHtml {
  const shown = f.affectedObjects.slice(0, maxObjects);
  return html`<article class="finding" id="${anchorId('finding', f.controlId)}">
    <header>
      <h3>${f.priority.rank}. ${f.title}</h3>
      <div>${statusBadge(f.status)} ${f.status === 'REVIEW' ? 'Potential impact if confirmed: ' : ''}${severityBadge(f.severity)} <span class="badge">${f.status === 'REVIEW' ? 'confirmation pending' : `confidence: ${f.confidence}`}</span>
      <span class="badge">${TIER_LABELS[f.priority.tier]}</span></div>
      <div class="muted small">${f.controlId} v${f.controlVersion} - ${TECHNOLOGY_LABELS[f.technology]} - ${f.category} - finding ${f.findingId}</div>
    </header>
    <h4>What did you find?</h4>
    ${f.status === 'REVIEW' ? html`<p><strong>Verification required.</strong> This does not establish a confirmed security gap. Validate evidence, exclusions and alternative controls before making changes.</p>` : ''}
    <p>${f.description}</p>
    <p><strong>${f.observedState.summary}</strong></p>
    <h4>Why does it matter?</h4>
    <p>${f.risk}</p>
    <h4>What did you observe?</h4>
    ${
      f.observedState.facts.length > 0
        ? html`<table class="facts"><tbody>${f.observedState.facts.map((x) => html`<tr><th scope="row">${x.label}</th><td>${x.value === null ? 'not reported' : String(x.value)}</td></tr>`)}</tbody></table>`
        : html`<p class="muted">No additional facts.</p>`
    }
    ${f.notes.length > 0 ? html`<div class="notes"><strong>Notes</strong>${list(f.notes)}</div>` : ''}
    <h4>What should it be?</h4>
    <p>${f.expectedState}</p>
    <h4>What is affected?</h4>
    ${
      f.affectedObjectCount === 0
        ? html`<p class="muted">This finding applies to the tenant or environment configuration as a whole.</p>`
        : html`<table><thead><tr><th>Type</th><th>Name</th><th>Identifier</th><th>Detail</th></tr></thead><tbody>
            ${shown.map((o) => html`<tr><td>${o.type}</td><td>${o.name}</td><td class="mono">${o.id}</td><td>${o.detail ?? ''}</td></tr>`)}
          </tbody></table>
          ${f.affectedObjectCount > shown.length ? html`<p class="muted">Showing ${shown.length} of ${f.affectedObjectCount} affected objects; see the JSON report for the stored list.</p>` : ''}`
    }
    <h4>What evidence supports this?</h4>
    <table><thead><tr><th>Dataset</th><th>File</th><th>SHA-256</th><th>Collected</th><th>Status</th><th>Source</th></tr></thead><tbody>
      ${f.evidence.map(
        (e) => html`<tr><td>${e.datasetId}</td><td class="mono">${e.path ?? 'not collected'}</td><td class="mono small">${e.sha256 ?? '-'}</td>
          <td>${e.collectedAt ?? '-'}</td><td>${e.status ?? 'not collected'}</td>
          <td>${e.source === null ? '-' : html`${e.source.system}${e.source.operations.length > 0 ? html`<div class="small mono">${e.source.operations.join('; ')}</div>` : ''}`}</td></tr>`,
      )}
    </tbody></table>
    <h4>What should I check before changing it?</h4>
    ${list(f.implementationConsiderations)}
    <p><strong>Impact:</strong> ${f.impact}</p>
    <h4>How do I fix it?</h4>
    <p>${f.remediation.summary}</p>
    ${list(f.remediation.steps, true)}
    ${
      f.remediation.scriptExample !== undefined
        ? html`<p class="muted small">Example for an administrator to review and run. AdminSecOps never makes changes to your environment.</p><pre><code>${f.remediation.scriptExample}</code></pre>`
        : ''
    }
    <h4>How do I roll it back?</h4>
    ${list(f.rollback, true)}
    <h4>How do I verify the fix?</h4>
    ${list(f.validation, true)}
    <h4>Authoritative references</h4>
    <ul>${f.references.map((r) => html`<li>${link(r.url, r.title)} <span class="muted small">(${r.publisher})</span></li>`)}</ul>
    ${
      f.frameworkMappings.length > 0
        ? html`<p class="small"><strong>Framework mappings:</strong> ${f.frameworkMappings.map((m, i) => html`${i > 0 ? ', ' : ''}${FRAMEWORKS[m.framework]} ${m.id}${m.note !== undefined ? ` (${m.note})` : ''}`)}</p>`
        : ''
    }
    <p class="small muted">Priority factors: ${f.priority.factors.join('; ')}</p>
  </article>`;
}

function resultsTable(results: readonly ControlResult[], title: string, id: string, empty: string): SafeHtml {
  return html`<section id="${id}">
    <h2>${title}</h2>
    ${
      results.length === 0
        ? html`<p class="muted">${empty}</p>`
        : html`<table><thead><tr><th>Control</th><th>Title</th><th>Technology</th><th>Severity</th><th>Status</th><th>Reason</th></tr></thead><tbody>
          ${results.map(
            (r) => html`<tr><td class="mono">${r.controlId}</td><td>${r.title}</td><td>${TECHNOLOGY_LABELS[r.technology]}</td><td>${severityBadge(r.severity)}</td><td>${statusBadge(r.status)}</td><td class="small">${r.statusReason}</td></tr>`,
          )}
        </tbody></table>`
    }
  </section>`;
}

function evidenceSection(result: AssessmentResult): SafeHtml {
  const ev = result.evidence;
  return html`<section id="evidence">
    <h2>Evidence integrity</h2>
    <p class="${ev.integrityVerified ? 'ok' : 'warn'}"><strong>${
      ev.integrityVerified
        ? 'All evidence files listed in the manifest were present and matched their SHA-256 hashes.'
        : 'One or more evidence files failed integrity verification. Affected datasets were not used.'
    }</strong></p>
    <p class="small">Manifest SHA-256: <span class="mono">${result.collection.manifestSha256}</span>. SHA-256 verification detects accidental corruption and
    modification after collection; the package is not digitally signed.</p>
    <table><thead><tr><th>File</th><th>Dataset</th><th>Integrity</th><th>Schema</th><th>Collection status</th><th>SHA-256</th></tr></thead><tbody>
      ${ev.files.map(
        (f) => html`<tr><td class="mono">${f.path}</td><td>${f.datasetId ?? '-'}</td><td>${f.integrity}${f.sensitiveContent ? ' (secret-like content rejected)' : ''}</td>
          <td>${f.schema}</td><td>${f.collectionStatus ?? '-'}</td><td class="mono small">${f.sha256 ?? '-'}</td></tr>`,
      )}
    </tbody></table>
    <h3>Collection errors and warnings</h3>
    ${
      ev.issues.length === 0
        ? html`<p class="muted">None reported.</p>`
        : html`<table><thead><tr><th>Level</th><th>Module</th><th>Dataset</th><th>Origin</th><th>Code</th><th>Message</th></tr></thead><tbody>
          ${ev.issues.map((i) => html`<tr><td>${i.level}</td><td>${i.module ?? '-'}</td><td>${i.datasetId ?? '-'}</td><td>${i.origin}</td><td class="mono">${i.code}</td><td>${i.message}</td></tr>`)}
        </tbody></table>`
    }
    <h3>Dataset availability</h3>
    <table><thead><tr><th>Dataset</th><th>Module</th><th>State</th><th>Reason</th></tr></thead><tbody>
      ${ev.datasets.map((d) => html`<tr><td>${d.title} <span class="muted small mono">${d.datasetId}</span></td><td>${d.module}</td><td>${d.state}</td><td class="small">${d.reason}</td></tr>`)}
    </tbody></table>
  </section>`;
}

function inventorySection(result: AssessmentResult): SafeHtml {
  return html`<section id="inventory">
    <h2>Environment inventory</h2>
    <table><thead><tr><th>Technology</th><th>Item</th><th>Count</th></tr></thead><tbody>
      ${result.inventory.map((i) => html`<tr><td>${TECHNOLOGY_LABELS[i.technology]}</td><td>${i.label}</td><td>${i.count === null ? 'not collected' : i.count}</td></tr>`)}
    </tbody></table>
  </section>`;
}

function frameworkSection(findings: readonly Finding[]): SafeHtml {
  const index = new Map<string, string[]>();
  for (const f of findings) {
    for (const m of f.frameworkMappings) {
      const key = `${FRAMEWORKS[m.framework]}|${m.id}`;
      index.set(key, [...(index.get(key) ?? []), f.controlId]);
    }
  }
  const rows = [...index.entries()].sort(([a], [b]) => a.localeCompare(b, 'en'));
  return html`<section id="frameworks">
    <h2>Framework mapping of findings</h2>
    <p class="muted small">Mappings reference framework identifiers only. They indicate related requirements, not certification or compliance status.</p>
    ${
      rows.length === 0
        ? html`<p class="muted">No mapped findings.</p>`
        : html`<table><thead><tr><th>Framework</th><th>Identifier</th><th>Findings</th></tr></thead><tbody>
          ${rows.map(([key, controls]) => {
            const [framework, id] = key.split('|');
            return html`<tr><td>${framework}</td><td class="mono">${id}</td><td>${[...new Set(controls)].join(', ')}</td></tr>`;
          })}
        </tbody></table>`
    }
  </section>`;
}

function styleHash(css: string): string {
  return `'sha256-${sha256Base64(css)}'`;
}

/**
 * Render a self-contained HTML assessment report. The report contains no scripts;
 * a Content-Security-Policy restricts it to its own hashed inline stylesheet.
 */
export function renderHtmlReport(result: AssessmentResult, options: HtmlReportOptions = {}): string {
  const generatedAt = (options.generatedAt ?? new Date()).toISOString();
  const maxObjects = options.maxAffectedObjects ?? 200;
  const env = result.collection.environment;
  const findings = [...result.findings].sort((a, b) => a.priority.rank - b.priority.rank);
  const notAssessed = result.results.filter((r) => r.status === 'NOT_ASSESSED' || r.status === 'ERROR');
  const csp = `default-src 'none'; style-src ${styleHash(REPORT_CSS)}; img-src data:; base-uri 'none'; form-action 'none'`;

  const body = html`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${PRODUCT_NAME} assessment report - ${environmentName(result)}</title>
<style>${new SafeHtml(REPORT_CSS)}</style>
</head>
<body>
<header class="report-header">
  <div class="brand">${PRODUCT_NAME}</div>
  <div class="tagline">${PRODUCT_TAGLINE}</div>
  <div class="muted">${PRODUCT_DESCRIPTION}</div>
</header>
<main>
<section id="overview">
  <h1>${options.executiveOnly ? "Executive summary" : "Security assessment report"}: ${environmentName(result)}</h1>
  <p class="confidential">Confidential: this report describes the security configuration of your environment. Share it only with people who need it.</p>
  <table class="facts"><tbody>
    <tr><th scope="row">Tenant</th><td>${env.tenantDisplayName ?? '-'} ${env.tenantId !== null ? html`<span class="mono small">(${env.tenantId})</span>` : ''}</td></tr>
    <tr><th scope="row">Primary domain</th><td>${env.primaryDomain ?? '-'}</td></tr>
    <tr><th scope="row">Active Directory forest</th><td>${env.adForestName ?? '-'}</td></tr>
    <tr><th scope="row">Evidence collected</th><td>${result.assessedAt}</td></tr>
    <tr><th scope="row">Processed</th><td>${result.processedAt}</td></tr>
    <tr><th scope="row">Report generated</th><td>${generatedAt}</td></tr>
    <tr><th scope="row">Assessment ID</th><td class="mono">${result.assessmentId}</td></tr>
    <tr><th scope="row">Collector</th><td>${result.collection.collector.name} ${result.collection.collector.version}</td></tr>
    <tr><th scope="row">Engine / control library</th><td>${result.engineVersion} / ${result.controlLibraryVersion}</td></tr>
    <tr><th scope="row">Modules collected</th><td>${result.collection.modules.map((m) => `${m.name} (${m.status})`).join(', ') || '-'}</td></tr>
  </tbody></table>
  <nav class="toc"><strong>Contents:</strong>${options.executiveOnly ? html`<a href="#summary">Summary</a><a href="#method">Method</a>` : html`
    <a href="#summary">Summary</a> <a href="#fix-first">What to fix first</a> <a href="#findings">Findings</a>
    <a href="#not-assessed">Not assessed</a> <a href="#all-results">All results</a> <a href="#evidence">Evidence</a>
    <a href="#inventory">Inventory</a> <a href="#frameworks">Frameworks</a> <a href="#method">Method</a>`}</nav>
</section>
<section id="executive-summary"><h2>Executive summary</h2><p>${result.summary.byStatus.FAIL} checks failed, ${result.summary.byStatus.REVIEW} need administrator review, and ${result.summary.byStatus.NOT_ASSESSED + result.summary.byStatus.ERROR} remain untested. Results describe the evidence collected on ${result.assessedAt}; they are not a security certification.</p><p>Scope: ${result.collection.modules.map(m=>m.name).join(', ')}. Control library ${result.controlLibraryVersion}. Framework mappings indicate alignment, not complete baseline compliance. Review excluded and unreadable evidence before planning changes.</p></section>
${summarySection(result)}
${options.executiveOnly ? html`<section><h2>Recommended priorities</h2><ol>${findings.slice(0,5).map(f=>html`<li><strong>${f.title}</strong> (${f.status}): ${f.remediation.summary}</li>`)}</ol><p>Use the full technical report for affected objects, exclusions, rollback and verification.</p></section>` : fixFirstSection(findings)}
${options.executiveOnly ? html`` : html`<section id="findings">
  <h2>Findings (${findings.length})</h2>
  ${findings.map((f) => findingSection(f, maxObjects))}
</section>
${resultsTable(notAssessed, 'Controls not assessed', 'not-assessed', 'Every control could be evaluated from the collected evidence.')}
${resultsTable(result.results, 'All control results', 'all-results', 'No controls were evaluated.')}
${evidenceSection(result)}
${inventorySection(result)}
${frameworkSection(findings)}`}
<section id="method">
  <h2>How this assessment was produced</h2>
  <ul>
    <li>Evidence was collected by read-only collectors and verified against the SHA-256 hashes in the evidence manifest.</li>
    <li>Every result was produced by deterministic, version-controlled rules. No AI or heuristic scoring determined any result.</li>
    <li>Missing, failed or unauthorized evidence results in "Not assessed", never in "Pass".</li>
    <li>"Review" means the evidence shows a configuration that needs an administrator's judgement.</li>
    <li>Remediation guidance must be tested before production changes. AdminSecOps never changes your environment.</li>
  </ul>
</section>
</main>
<footer class="muted small">Generated by ${PRODUCT_NAME} engine ${result.engineVersion}.</footer>
</body>
</html>
`;
  return body.value;
}
