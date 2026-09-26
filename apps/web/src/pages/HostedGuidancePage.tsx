import { useApi } from '../app/context';
import { PageHeader, Panel } from '../components/PageHeader';
import { useAsync } from '../hooks/useAsync';
import { OVERVIEW_URL } from '../mode';
import { IMPORT_WARNING } from './HostedHomePage';

/** Hosted mode: privacy, safety and evidence-collection guidance. */
export function HostedGuidancePage() {
  const api = useApi();
  const health = useAsync('health', (signal) => api.health(signal));

  return (
    <div className="page page--narrow">
      <PageHeader
        eyebrow="Privacy and safety"
        title="Privacy and safety guidance"
        description={<p>How this browser application handles evidence, what it is and is not, and how to collect evidence safely.</p>}
      />

      <Panel title="How your evidence is handled" id="guidance-handling">
        <ul className="bullets">
          <li>
            Evidence packages you import are read from your computer and processed entirely in this browser: ZIP safety
            checks, SHA-256 integrity verification, secret-content rejection, schema validation, control evaluation,
            prioritisation and report generation all run on this device.
          </li>
          <li>
            Evidence, results and reports are not uploaded to palanikumar.net or any other service. The application has no
            server component, and its security policy blocks it from making network connections.
          </li>
          <li>This browser edition has no analytics, telemetry, cookies or remote logging.</li>
          <li>
            By default assessments exist only in memory and disappear when you refresh or close the page. If you choose
            &quot;Keep assessments on this device&quot;, processed results (not the evidence package) are stored in this
            browser until you select &quot;Delete local data&quot;.
          </li>
          <li>Reports are generated in the browser and saved to your computer only when you export them.</li>
        </ul>
        <p className="notice" role="note">
          {IMPORT_WARNING}
        </p>
      </Panel>

      <Panel title="What AdminSecOps is and is not" id="guidance-scope">
        <p>
          AdminSecOps performs a point-in-time configuration assessment of Microsoft environments from read-only
          evidence, with deterministic, documented controls and remediation guidance.
        </p>
        <p>
          It is not a penetration test, a compliance certification or a guarantee of security. A control that could not
          be assessed is reported as &quot;Not assessed&quot;, never as passed. Remediation guidance may include commands
          that change configuration; review, approve and test any change separately before applying it.
        </p>
        <p>Contoso and Fabrikam are fictional sample environments. Their data is invented and clearly labelled.</p>
      </Panel>

      <Panel title="How to collect evidence" id="guidance-collect">
        <ul className="bullets">
          <li>This application analyses the fictional samples and compatible AdminSecOps evidence packages (.zip).</li>
          <li>
            Browser security restrictions prevent a website from directly inspecting Active Directory, AD CS, Group Policy
            or Windows hosts, and this application does not sign in to Microsoft services. It cannot collect evidence
            itself.
          </li>
          <li>
            Live evidence collection is a separate, read-only administrative operation performed with the AdminSecOps
            PowerShell collector on a computer you control.
          </li>
          <li>Test collection in a non-production environment first.</li>
          <li>
            Before signing in, verify the expected tenant ID and review the Microsoft permissions the collector requests.
            The collector refuses to collect when a session belongs to a different tenant than the one you specify.
          </li>
          <li>
            Review the evidence package before sharing or importing it, and store it securely: it can contain account
            identifiers, security settings and weaknesses. Delete it when it is no longer needed.
          </li>
        </ul>
        <p>
          Collector documentation and the advanced download are on the{' '}
          <a href={OVERVIEW_URL}>AdminSecOps overview page</a>.
        </p>
      </Panel>

      <Panel title="Versions" id="guidance-versions">
        {health.status === 'success' ? (
          <dl className="dl-grid">
            <div className="dl-grid__item">
              <dt>Engine</dt>
              <dd>{health.data.engineVersion}</dd>
            </div>
            <div className="dl-grid__item">
              <dt>Control library</dt>
              <dd>{health.data.controlLibraryVersion}</dd>
            </div>
            <div className="dl-grid__item">
              <dt>Evidence package format</dt>
              <dd>manifest 1.0, evidence schema 1.0</dd>
            </div>
          </dl>
        ) : (
          <p className="muted">Loading version information...</p>
        )}
      </Panel>
    </div>
  );
}
