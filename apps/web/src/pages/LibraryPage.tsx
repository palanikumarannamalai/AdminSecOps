import type { ControlMetadata } from '@adminsecops/schemas';
import { TECHNOLOGY_LABELS } from '@adminsecops/core/vocabulary';
import { useState } from 'react';
import type { DatasetInfo } from '../api/types';
import { useApi } from '../app/context';
import { ConfidenceBadge, SeverityBadge, ToneBadge } from '../components/Badges';
import { ExternalLink } from '../components/ExternalLink';
import { PageHeader, Panel } from '../components/PageHeader';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { useAsync } from '../hooks/useAsync';
import { formatCount } from '../lib/format';
import { frameworkLabel } from '../lib/labels';
import { DASHBOARD_MODULES, moduleForTechnology, moduleLabel, type DashboardModuleId } from '../lib/modules';

function DatasetList({ ids, datasets }: { ids: readonly string[]; datasets: Map<string, DatasetInfo> }) {
  return (
    <ul className="bullets">
      {ids.map((id) => {
        const ds = datasets.get(id);
        return (
          <li key={id}>
            <code>{id}</code>
            {ds !== undefined ? (
              <>
                {' '}
                - {ds.title} <span className="muted small">({ds.source}; permissions: {ds.permissions.join(', ') || 'none listed'})</span>
              </>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}

function ControlEntry({ control, datasets }: { control: ControlMetadata; datasets: Map<string, DatasetInfo> }) {
  return (
    <li className="library-item" id={`library-${control.id}`}>
      <details>
        <summary className="library-item__summary">
          <code>{control.id}</code>
          <span className="library-item__title">{control.title}</span>
          <span className="library-item__badges">
            <SeverityBadge severity={control.severity} />
            {control.lifecycle !== 'stable' ? (
              <ToneBadge tone={control.lifecycle === 'preview' ? 'info' : 'warn'}>
                {control.lifecycle === 'preview' ? 'Preview' : 'Deprecated'}
              </ToneBadge>
            ) : null}
          </span>
        </summary>
        <div className="library-item__body">
          <p className="muted small">
            {TECHNOLOGY_LABELS[control.technology]} - {control.category} / {control.subcategory} - version {control.version}{' '}
            - <ConfidenceBadge confidence={control.confidence} />
          </p>
          <h3 className="qa__subtitle">What it checks</h3>
          <p>{control.description}</p>
          <h3 className="qa__subtitle">Why it matters</h3>
          <p>{control.rationale}</p>
          <h3 className="qa__subtitle">Applies to</h3>
          <p>{control.applicability.description}</p>
          <h3 className="qa__subtitle">How it is evaluated</h3>
          <p>{control.evaluation.logic}</p>
          {Object.keys(control.evaluation.parameters).length > 0 ? (
            <ul className="bullets small">
              {Object.entries(control.evaluation.parameters).map(([key, value]) => (
                <li key={key}>
                  <code>{key}</code>: {String(value)}
                </li>
              ))}
            </ul>
          ) : null}
          <h3 className="qa__subtitle">Expected state</h3>
          <p>{control.expectedState}</p>
          <h3 className="qa__subtitle">Required evidence</h3>
          <DatasetList ids={control.requiredEvidence} datasets={datasets} />
          {control.optionalEvidence.length > 0 ? (
            <>
              <h3 className="qa__subtitle">Optional evidence</h3>
              <DatasetList ids={control.optionalEvidence} datasets={datasets} />
            </>
          ) : null}
          <h3 className="qa__subtitle">References</h3>
          <ul className="references">
            {control.references.map((ref, i) => (
              <li key={i}>
                <ExternalLink href={ref.url}>{ref.title}</ExternalLink> <span className="muted small">{ref.publisher}</span>
              </li>
            ))}
          </ul>
          {control.frameworkMappings.length > 0 ? (
            <>
              <h3 className="qa__subtitle">Framework mappings</h3>
              <p className="small">
                {control.frameworkMappings.map((m) => `${frameworkLabel(m.framework)} ${m.id}`).join('; ')}
              </p>
            </>
          ) : null}
        </div>
      </details>
    </li>
  );
}

export function LibraryPage() {
  const api = useApi();
  const library = useAsync('controls', (signal) => api.listControls(signal));
  const datasets = useAsync('datasets', (signal) => api.listDatasets(signal));
  const [module, setModule] = useState<DashboardModuleId | 'all'>('all');
  const [search, setSearch] = useState('');

  const datasetMap = new Map((datasets.status === 'success' ? datasets.data : []).map((d) => [d.id, d]));

  return (
    <div className="page">
      <PageHeader
        eyebrow="Control library"
        title="Control library"
        description={
          <p>
            What each control checks, the evidence it needs and the authoritative references it is based on.
            {library.status === 'success' ? ` Library version ${library.data.libraryVersion}.` : ''}
          </p>
        }
      />
      {library.status === 'loading' ? <LoadingState label="Loading control library" /> : null}
      {library.status === 'error' ? (
        <ErrorState title="The control library could not be loaded" error={library.error} onRetry={library.reload} />
      ) : null}
      {library.status === 'success'
        ? (() => {
            const needle = search.trim().toLowerCase();
            const visible = library.data.controls
              .filter(
                (c) =>
                  (module === 'all' || moduleForTechnology(c.technology) === module) &&
                  (needle === '' ||
                    `${c.id}\n${c.title}\n${c.category}\n${c.description}\n${c.tags.join(' ')}`.toLowerCase().includes(needle)),
              )
              .sort((a, b) => a.id.localeCompare(b.id));
            return (
              <Panel>
                <div className="filters">
                  <div className="field field--wide">
                    <label htmlFor="l-search">Search</label>
                    <input
                      id="l-search"
                      className="input"
                      type="search"
                      value={search}
                      placeholder="Control ID, title, category or tag"
                      onChange={(e) => setSearch(e.target.value)}
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="l-module">Module</label>
                    <select
                      id="l-module"
                      className="select"
                      value={module}
                      onChange={(e) => setModule(e.target.value as DashboardModuleId | 'all')}
                    >
                      <option value="all">All modules</option>
                      {DASHBOARD_MODULES.map((m) => (
                        <option key={m.id} value={m.id}>
                          {m.label}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
                <p className="muted small" role="status" aria-live="polite">
                  Showing {visible.length} of {formatCount(library.data.controls.length, 'control')}
                  {module !== 'all' ? ` in ${moduleLabel(module)}` : ''}.
                </p>
                {datasets.status === 'error' ? (
                  <p className="muted small">Dataset descriptions are unavailable; dataset IDs are shown instead.</p>
                ) : null}
                {visible.length === 0 ? (
                  <EmptyState title="No controls match" />
                ) : (
                  <ul className="library">
                    {visible.map((c) => (
                      <ControlEntry key={c.id} control={c} datasets={datasetMap} />
                    ))}
                  </ul>
                )}
              </Panel>
            );
          })()
        : null}
    </div>
  );
}
