import { useId, useState } from 'react';
import { useNavigate } from 'react-router';
import { errorMessage } from '../api/client';
import { useApi } from '../app/context';
import { Panel } from './PageHeader';

/**
 * Hosted mode: explicit control over on-device data. Persistence is off by default; turning it
 * on stores processed results (not raw evidence) in this browser's IndexedDB only.
 */
export function LocalDataPanel({ onDeleted }: { onDeleted: () => void }) {
  const api = useApi();
  const navigate = useNavigate();
  const local = api.localData;
  const [keep, setKeep] = useState(() => local?.isPersistenceEnabled() ?? false);
  const [confirming, setConfirming] = useState(false);
  const [message, setMessage] = useState('');
  const checkboxId = useId();
  const hintId = useId();

  if (local === undefined) return null;

  const toggle = async (enabled: boolean) => {
    try {
      await local.setPersistenceEnabled(enabled);
      setKeep(enabled);
      setMessage(
        enabled
          ? 'Processed assessments are now kept in this browser until you delete them.'
          : 'Assessments are no longer kept. Stored copies on this device were deleted.',
      );
    } catch (error) {
      setMessage(`The setting could not be changed: ${errorMessage(error)}`);
    }
  };

  const deleteAll = async () => {
    try {
      await local.deleteAllLocalData();
      setKeep(false);
      setConfirming(false);
      setMessage('All assessments were cleared from this browser and local data was deleted.');
      onDeleted();
      void navigate('/');
    } catch (error) {
      setMessage(`Local data could not be deleted: ${errorMessage(error)}`);
    }
  };

  return (
    <Panel title="Data on this device" id="local-data">
      <p className="small">
        By default assessments exist only in this browser tab's memory and are gone when you close or refresh the page.
        Nothing is uploaded, and no analytics, telemetry or cookies are used.
      </p>
      {local.persistenceAvailable ? (
        <div className="checkbox-row">
          <input
            id={checkboxId}
            type="checkbox"
            checked={keep}
            aria-describedby={hintId}
            onChange={(event) => void toggle(event.target.checked)}
          />
          <label htmlFor={checkboxId}>Keep assessments on this device</label>
        </div>
      ) : (
        <p className="small muted">This browser does not offer on-device storage; assessments stay in memory only.</p>
      )}
      <p className="small muted" id={hintId}>
        When enabled, processed results (not the evidence package) are stored in this browser for this site until you
        delete them. Do not enable this on a shared computer.
      </p>
      {confirming ? (
        <span className="inline-actions">
          <button type="button" className="button button--danger" onClick={() => void deleteAll()}>
            Confirm: delete local data
          </button>
          <button type="button" className="button" onClick={() => setConfirming(false)}>
            Cancel
          </button>
        </span>
      ) : (
        <button type="button" className="button button--danger" onClick={() => setConfirming(true)}>
          Delete local data
        </button>
      )}
      <p className="upload__status upload__status--info" role="status" aria-live="polite">
        {message}
      </p>
    </Panel>
  );
}
