import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { errorMessage } from '../api/client';
import type { SampleName } from '../api/types';
import { useApi, useAssessmentList } from '../app/context';
import { LocalDataPanel } from '../components/LocalDataPanel';
import { PageHeader, Panel } from '../components/PageHeader';
import { UploadPanel } from '../components/UploadPanel';
import { AssessmentsPanel } from './HomePage';

/** Warning shown next to the import control (hosted mode). */
export const IMPORT_WARNING =
  'Evidence is processed locally in your browser. Do not use a shared or untrusted computer. Assessment evidence can contain account identifiers, security settings and weaknesses.';

export function HostedHomePage() {
  const api = useApi();
  const list = useAssessmentList();
  const navigate = useNavigate();
  const [loading, setLoading] = useState<SampleName | null>(null);
  const [sampleError, setSampleError] = useState<string | null>(null);

  const open = (id: string) => {
    list.reload();
    void navigate(`/assessments/${encodeURIComponent(id)}`);
  };

  const loadSample = async (name: SampleName) => {
    setLoading(name);
    setSampleError(null);
    try {
      open((await api.loadSample(name)).assessmentId);
    } catch (error) {
      setSampleError(errorMessage(error));
    } finally {
      setLoading(null);
    }
  };

  const focusImport = () => {
    document.getElementById('import')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    document.querySelector<HTMLInputElement>('#import input[type="file"]')?.focus();
  };

  return (
    <div className="page">
      <PageHeader
        eyebrow="AdminSecOps"
        title="Microsoft security assessment in your browser"
        description={
          <p>
            Explore a Microsoft security assessment using fictional sample environments, or analyse a compatible AdminSecOps
            evidence package locally in your browser. Your evidence is processed on this device and is not uploaded to
            palanikumar.net.
          </p>
        }
      />

      <section aria-labelledby="start-heading" className="start">
        <h2 id="start-heading" className="visually-hidden">
          Choose how to start
        </h2>
        <ul className="start__options">
          <li className="start__option">
            <h3 className="start__title">Explore Contoso sample</h3>
            <p className="muted small">Fictional hybrid organisation across Microsoft 365, Entra ID, Intune, Azure and Active Directory.</p>
            <button type="button" className="button button--primary" disabled={loading !== null} onClick={() => void loadSample('contoso')}>
              {loading === 'contoso' ? 'Loading sample...' : 'Load Contoso sample'}
            </button>
          </li>
          <li className="start__option">
            <h3 className="start__title">Explore Fabrikam sample</h3>
            <p className="muted small">Fictional on-premises organisation: Active Directory, AD CS, Group Policy and Windows.</p>
            <button type="button" className="button button--primary" disabled={loading !== null} onClick={() => void loadSample('fabrikam')}>
              {loading === 'fabrikam' ? 'Loading sample...' : 'Load Fabrikam sample'}
            </button>
          </li>
          <li className="start__option">
            <h3 className="start__title">Import an evidence package</h3>
            <p className="muted small">Analyse an AdminSecOps evidence package (.zip) from your computer, in this browser only.</p>
            <button type="button" className="button" onClick={focusImport}>
              Import evidence
            </button>
          </li>
          <li className="start__option">
            <h3 className="start__title">Read privacy and safety guidance</h3>
            <p className="muted small">How evidence is handled, what this tool is not, and how to collect evidence safely.</p>
            <Link className="button" to="/about">
              Privacy and safety guidance
            </Link>
          </li>
        </ul>
        <p className="upload__status upload__status--error" role="status" aria-live="polite">
          {sampleError !== null ? `The sample could not be loaded: ${sampleError}` : ''}
        </p>
        <p className="muted small">
          Contoso and Fabrikam are fictional sample data. Also available:{' '}
          <button type="button" className="link-button" disabled={loading !== null} onClick={() => void loadSample('contoso-followup')}>
            Contoso follow-up sample
          </button>{' '}
          (load it with Contoso to try Compare).
        </p>
      </section>

      <div className="grid grid--2">
        <Panel title="Import an evidence package" id="import">
          <p className="notice" role="note">
            {IMPORT_WARNING}
          </p>
          <UploadPanel api={api} onUploaded={open} />
        </Panel>
        <LocalDataPanel onDeleted={list.reload} />
      </div>

      <AssessmentsPanel />

      <p className="muted small disclaimer">
        AdminSecOps performs a point-in-time configuration assessment. It is not a penetration test, a compliance
        certification or a guarantee of security. Results depend on the evidence provided.
      </p>
    </div>
  );
}
