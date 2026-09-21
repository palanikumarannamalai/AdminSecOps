import type { DatasetAvailability, EvidenceFileCheck } from '@adminsecops/schemas';
import { TECHNOLOGY_LABELS } from '@adminsecops/core/vocabulary';
import { useAssessment } from '../app/AssessmentLayout';
import { CollectionStatusBadge, ToneBadge, type Tone } from '../components/Badges';
import { CopyButton } from '../components/CopyButton';
import { PageHeader, Panel } from '../components/PageHeader';
import { EmptyState } from '../components/States';
import { formatBytes, formatCount, formatDateTime, shortHash } from '../lib/format';

const INTEGRITY: Record<EvidenceFileCheck['integrity'], { label: string; tone: Tone }> = {
  verified: { label: 'Verified', tone: 'ok' },
  'hash-mismatch': { label: 'Hash mismatch', tone: 'bad' },
  missing: { label: 'Missing', tone: 'bad' },
  unlisted: { label: 'Not in manifest', tone: 'bad' },
  'size-mismatch': { label: 'Size mismatch', tone: 'bad' },
};

const SCHEMA: Record<EvidenceFileCheck['schema'], { label: string; tone: Tone }> = {
  valid: { label: 'Valid', tone: 'ok' },
  invalid: { label: 'Invalid', tone: 'bad' },
  'unknown-dataset': { label: 'Unknown dataset', tone: 'warn' },
  'not-checked': { label: 'Not checked', tone: 'muted' },
};

const AVAILABILITY: Record<DatasetAvailability['state'], { label: string; tone: Tone }> = {
  available: { label: 'Available', tone: 'ok' },
  partial: { label: 'Partial', tone: 'warn' },
  unavailable: { label: 'Unavailable', tone: 'bad' },
};

export function EvidencePage() {
  const result = useAssessment();
  const { evidence, collection } = result;
  const errors = evidence.issues.filter((i) => i.level === 'error');
  const warnings = evidence.issues.filter((i) => i.level === 'warning');
  const availabilityCounts = {
    available: evidence.datasets.filter((d) => d.state === 'available').length,
    partial: evidence.datasets.filter((d) => d.state === 'partial').length,
    unavailable: evidence.datasets.filter((d) => d.state === 'unavailable').length,
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="Evidence"
        title="Evidence and integrity"
        description={<p>What was collected, how it was verified and what could not be collected.</p>}
      />

      {evidence.integrityVerified ? (
        <div className="banner banner--ok" role="status">
          <strong>Integrity verified.</strong> Every evidence file matched the SHA-256 hash and size recorded in the
          collector manifest, so the results are based on the evidence exactly as it was collected.
        </div>
      ) : (
        <div className="banner banner--bad" role="alert">
          <strong>Integrity not verified.</strong> One or more evidence files did not match the collector manifest, were
          missing or were not listed. Results that depend on these files may not reflect the environment. Review the
          file table below and collect new evidence if the package may have been altered.
        </div>
      )}

      <Panel title="Collection" id="collection">
        <dl className="dl-grid">
          <div className="dl-grid__item">
            <dt>Collector</dt>
            <dd>
              {collection.collector.name} {collection.collector.version}
            </dd>
          </div>
          <div className="dl-grid__item">
            <dt>Platform</dt>
            <dd>{collection.collector.platform ?? 'Not recorded'}</dd>
          </div>
          <div className="dl-grid__item">
            <dt>Manifest SHA-256</dt>
            <dd className="hash-cell">
              <code className="hash" title={collection.manifestSha256}>
                {shortHash(collection.manifestSha256)}
              </code>
              <CopyButton text={collection.manifestSha256} label="Copy" />
            </dd>
          </div>
          <div className="dl-grid__item">
            <dt>Evidence files</dt>
            <dd>{evidence.files.length}</dd>
          </div>
        </dl>
        {collection.modules.length > 0 ? (
          <div className="table-wrap" tabIndex={0}>
            <table className="table table--compact">
              <caption>Collector modules</caption>
              <thead>
                <tr>
                  <th scope="col">Module</th>
                  <th scope="col">Version</th>
                  <th scope="col">Status</th>
                  <th scope="col">Completed</th>
                  <th scope="col">Prerequisites</th>
                </tr>
              </thead>
              <tbody>
                {collection.modules.map((m) => (
                  <tr key={m.name}>
                    <th scope="row">{m.name}</th>
                    <td>{m.version}</td>
                    <td>
                      <ToneBadge
                        tone={
                          m.status === 'Completed' ? 'ok' : m.status === 'CompletedWithErrors' ? 'warn' : m.status === 'Failed' ? 'bad' : 'muted'
                        }
                      >
                        {m.status === 'CompletedWithErrors' ? 'Completed with errors' : m.status}
                      </ToneBadge>
                    </td>
                    <td>{formatDateTime(m.completedAt)}</td>
                    <td>
                      {m.prerequisites.length === 0
                        ? 'None recorded'
                        : m.prerequisites.map((p) => `${p.name}: ${p.satisfied ? 'met' : 'not met'}`).join('; ')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Panel>

      <Panel title="Evidence files" id="files">
        {evidence.files.length === 0 ? (
          <EmptyState title="No evidence files" />
        ) : (
          <div className="table-wrap" tabIndex={0}>
            <table className="table table--compact">
              <caption className="visually-hidden">Evidence files and integrity checks</caption>
              <thead>
                <tr>
                  <th scope="col">Path</th>
                  <th scope="col">Dataset</th>
                  <th scope="col">Module</th>
                  <th scope="col">Integrity</th>
                  <th scope="col">Schema</th>
                  <th scope="col">Collection</th>
                  <th scope="col">SHA-256</th>
                  <th scope="col" className="num">
                    Size
                  </th>
                  <th scope="col">Messages</th>
                </tr>
              </thead>
              <tbody>
                {evidence.files.map((file) => (
                  <tr key={file.path}>
                    <th scope="row">
                      <code className="break">{file.path}</code>
                    </th>
                    <td>{file.datasetId !== null ? <code>{file.datasetId}</code> : <span className="muted">Unknown</span>}</td>
                    <td>{file.module ?? 'Unknown'}</td>
                    <td>
                      <ToneBadge tone={INTEGRITY[file.integrity].tone}>{INTEGRITY[file.integrity].label}</ToneBadge>
                    </td>
                    <td>
                      <ToneBadge tone={SCHEMA[file.schema].tone}>{SCHEMA[file.schema].label}</ToneBadge>
                      {file.sensitiveContent ? (
                        <div>
                          <ToneBadge tone="bad">Sensitive content blocked</ToneBadge>
                        </div>
                      ) : null}
                    </td>
                    <td>
                      <CollectionStatusBadge status={file.collectionStatus} />
                    </td>
                    <td className="hash-cell">
                      {file.sha256 !== null ? (
                        <>
                          <code className="hash" title={file.sha256}>
                            {shortHash(file.sha256)}
                          </code>
                          <CopyButton text={file.sha256} label="Copy" />
                        </>
                      ) : (
                        <span className="muted">Not available</span>
                      )}
                      {file.expectedSha256 !== null && file.sha256 !== null && file.expectedSha256 !== file.sha256 ? (
                        <div className="small error-text">Expected {shortHash(file.expectedSha256)}</div>
                      ) : null}
                    </td>
                    <td className="num">{formatBytes(file.sizeBytes)}</td>
                    <td>
                      {file.messages.length === 0 ? (
                        <span className="muted">None</span>
                      ) : (
                        <ul className="bullets small">
                          {file.messages.map((m, i) => (
                            <li key={i}>{m}</li>
                          ))}
                        </ul>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="Dataset availability" id="datasets">
        <p className="muted small">
          {availabilityCounts.available} available, {availabilityCounts.partial} partial, {availabilityCounts.unavailable}{' '}
          unavailable. Controls that need an unavailable dataset are reported as not assessed.
        </p>
        {evidence.datasets.length === 0 ? (
          <EmptyState title="No datasets recorded" />
        ) : (
          <div className="table-wrap" tabIndex={0}>
            <table className="table table--compact">
              <caption className="visually-hidden">Dataset availability</caption>
              <thead>
                <tr>
                  <th scope="col">Dataset</th>
                  <th scope="col">Technology</th>
                  <th scope="col">Module</th>
                  <th scope="col">State</th>
                  <th scope="col">Collection</th>
                  <th scope="col">Reason</th>
                </tr>
              </thead>
              <tbody>
                {evidence.datasets.map((d) => (
                  <tr key={d.datasetId}>
                    <th scope="row">
                      {d.title}
                      <div className="muted small">
                        <code>{d.datasetId}</code>
                      </div>
                    </th>
                    <td>{TECHNOLOGY_LABELS[d.technology]}</td>
                    <td>{d.module}</td>
                    <td>
                      <ToneBadge tone={AVAILABILITY[d.state].tone}>{AVAILABILITY[d.state].label}</ToneBadge>
                    </td>
                    <td>
                      <CollectionStatusBadge status={d.collectionStatus} />
                    </td>
                    <td>{d.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="Collection issues" id="issues">
        <p className="muted small">
          {formatCount(errors.length, 'error')} and {formatCount(warnings.length, 'warning')}, reported by the collector
          or by the ingestion checks during assessment processing.
        </p>
        {evidence.issues.length === 0 ? (
          <p>No errors or warnings were reported.</p>
        ) : (
          <div className="table-wrap" tabIndex={0}>
            <table className="table table--compact">
              <caption className="visually-hidden">Collection errors and warnings</caption>
              <thead>
                <tr>
                  <th scope="col">Level</th>
                  <th scope="col">Module</th>
                  <th scope="col">Dataset</th>
                  <th scope="col">Origin</th>
                  <th scope="col">Code</th>
                  <th scope="col">Message</th>
                </tr>
              </thead>
              <tbody>
                {[...errors, ...warnings].map((issue, i) => (
                  <tr key={`${issue.code}-${i}`}>
                    <td>
                      <ToneBadge tone={issue.level === 'error' ? 'bad' : 'warn'}>
                        {issue.level === 'error' ? 'Error' : 'Warning'}
                      </ToneBadge>
                    </td>
                    <td>{issue.module ?? 'Package'}</td>
                    <td>{issue.datasetId !== null ? <code>{issue.datasetId}</code> : <span className="muted">None</span>}</td>
                    <td>{issue.origin === 'collector' ? 'Collector' : 'Ingestion'}</td>
                    <td>
                      <code>{issue.code}</code>
                    </td>
                    <td>
                      {issue.message}
                      {issue.target !== null ? <div className="muted small">Target: {issue.target}</div> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
