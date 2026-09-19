import { PRODUCT_DESCRIPTION, PRODUCT_NAME, PRODUCT_TAGLINE } from '@adminsecops/core/version';
import { useApi } from '../app/context';
import { PageHeader, Panel } from '../components/PageHeader';
import { useAsync } from '../hooks/useAsync';

export function AboutPage() {
  const api = useApi();
  const health = useAsync('health', (signal) => api.health(signal));

  return (
    <div className="page page--narrow">
      <PageHeader eyebrow="About" title={`About ${PRODUCT_NAME}`} description={<p>{PRODUCT_DESCRIPTION}</p>} />

      <Panel title="What AdminSecOps is" id="about-what">
        <p>
          {PRODUCT_TAGLINE} {PRODUCT_NAME} helps Microsoft administrators without a dedicated security team assess the
          configuration of Microsoft 365, Entra ID, Azure, Intune, Active Directory and Windows, and understand what to fix
          first, how to fix it safely, how to roll back and how to verify the change.
        </p>
        <p>
          It reads configuration evidence and reports findings. It never changes your environment and never runs the
          script examples it shows.
        </p>
      </Panel>

      <Panel title="Privacy and local processing" id="about-privacy">
        <ul className="bullets">
          <li>
            Evidence packages are processed on this machine by the local AdminSecOps service. Evidence, results and
            reports are not uploaded anywhere.
          </li>
          <li>This dashboard only talks to the local service. It loads no external scripts, fonts or analytics.</li>
          <li>There is no telemetry, usage tracking or crash reporting.</li>
          <li>
            External reference links (for example to Microsoft Learn) open only when you select them, in a new tab without
            a referrer.
          </li>
          <li>
            Collectors are designed not to request secrets or content (passwords, hashes, tokens, keys, mail or files).
            As a second line of defence, every evidence file is checked for such properties on ingestion and flagged.
          </li>
        </ul>
      </Panel>

      <Panel title="What is stored locally" id="about-storage">
        <ul className="bullets">
          <li>The processed assessment result for each package: control results, findings and inventory counts.</li>
          <li>
            Evidence metadata: file paths, SHA-256 hashes, collection status, collection errors and warnings. Findings
            include identifiers of affected objects such as user principal names, object IDs, group and device names.
          </li>
          <li>Reports are generated on demand when you download them.</li>
        </ul>
        <p>Treat the local data folder and downloaded reports as sensitive administrative information.</p>
      </Panel>

      <Panel title="How to delete data" id="about-delete">
        <ol className="steps">
          <li>On the Assessments page, select Delete next to an assessment and confirm. The stored result is removed.</li>
          <li>Delete downloaded reports and the original evidence ZIP files from wherever you saved them.</li>
          <li>To remove everything, stop the local service and delete its data folder.</li>
        </ol>
      </Panel>

      <Panel title="Versions" id="about-versions">
        {health.status === 'success' ? (
          <dl className="dl-grid">
            <div className="dl-grid__item">
              <dt>Service</dt>
              <dd>{health.data.version}</dd>
            </div>
            <div className="dl-grid__item">
              <dt>Engine</dt>
              <dd>{health.data.engineVersion}</dd>
            </div>
            <div className="dl-grid__item">
              <dt>Control library</dt>
              <dd>{health.data.controlLibraryVersion}</dd>
            </div>
          </dl>
        ) : health.status === 'error' ? (
          <p className="error-text">The local service did not respond. Check that it is running.</p>
        ) : (
          <p className="muted">Checking the local service...</p>
        )}
      </Panel>
    </div>
  );
}
