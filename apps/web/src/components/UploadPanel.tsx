import { useId, useRef, useState, type ChangeEvent, type DragEvent } from 'react';
import { errorMessage, type ApiClient } from '../api/client';
import { formatBytes } from '../lib/format';
import { MAX_UPLOAD_BYTES, validatePackageFile } from '../lib/upload';
import { IS_HOSTED } from '../mode';

type UploadState =
  | { phase: 'idle' }
  | { phase: 'invalid'; message: string }
  | { phase: 'uploading'; fileName: string; fraction: number }
  | { phase: 'processing'; fileName: string }
  | { phase: 'done'; fileName: string; assessmentId: string }
  | { phase: 'failed'; fileName: string; message: string };

function statusText(state: UploadState): string {
  switch (state.phase) {
    case 'idle':
      return '';
    case 'invalid':
      return state.message;
    case 'uploading':
      return IS_HOSTED ? `Reading ${state.fileName} in this browser...` : `Uploading ${state.fileName}: ${Math.round(state.fraction * 100)}%`;
    case 'processing':
      return IS_HOSTED
        ? `Verifying and assessing ${state.fileName} in this browser...`
        : `Upload complete. Verifying and assessing ${state.fileName}...`;
    case 'done':
      return `${state.fileName} was processed.`;
    case 'failed':
      return `${state.fileName} could not be processed: ${state.message}`;
  }
}

export function UploadPanel({
  api,
  onUploaded,
}: {
  api: Pick<ApiClient, 'uploadPackage'>;
  onUploaded: (assessmentId: string) => void;
}) {
  const [state, setState] = useState<UploadState>({ phase: 'idle' });
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const inputId = useId();
  const hintId = useId();
  const busy = state.phase === 'uploading' || state.phase === 'processing';

  const start = async (file: File | undefined) => {
    if (busy) return;
    const validation = validatePackageFile(file);
    if (!validation.ok || file === undefined) {
      setState({ phase: 'invalid', message: validation.ok ? 'Select a file.' : validation.message });
      return;
    }
    setState({ phase: 'uploading', fileName: file.name, fraction: 0 });
    try {
      const created = await api.uploadPackage(file, {
        onProgress: (fraction) =>
          setState(fraction >= 1 ? { phase: 'processing', fileName: file.name } : { phase: 'uploading', fileName: file.name, fraction }),
      });
      setState({ phase: 'done', fileName: file.name, assessmentId: created.assessmentId });
      onUploaded(created.assessmentId);
    } catch (error) {
      setState({ phase: 'failed', fileName: file.name, message: errorMessage(error) });
    } finally {
      if (inputRef.current !== null) inputRef.current.value = '';
    }
  };

  const onInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    void start(event.target.files?.[0]);
  };

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragging(false);
    if (event.dataTransfer.files.length > 1) {
      setState({ phase: 'invalid', message: 'Drop one evidence package at a time.' });
      return;
    }
    void start(event.dataTransfer.files[0]);
  };

  const tone =
    state.phase === 'invalid' || state.phase === 'failed' ? 'error' : state.phase === 'done' ? 'success' : 'info';

  return (
    <div className="upload">
      <div
        className={`dropzone${dragging ? ' dropzone--active' : ''}${busy ? ' dropzone--busy' : ''}`}
        onDragOver={(event) => {
          event.preventDefault();
          if (!busy) setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        <p className="dropzone__title">{IS_HOSTED ? 'Drop an evidence package here to import it' : 'Drop an evidence package here'}</p>
        <p className="dropzone__hint" id={hintId}>
          A .zip file produced by the ConfigReview Collector, up to {formatBytes(MAX_UPLOAD_BYTES)}.{' '}
          {IS_HOSTED
            ? 'It is processed in this browser and is not uploaded to any server.'
            : 'It is processed on this machine only.'}
        </p>
        <input
          ref={inputRef}
          id={inputId}
          className="visually-hidden file-input"
          type="file"
          accept=".zip,application/zip,application/x-zip-compressed"
          aria-describedby={hintId}
          disabled={busy}
          onChange={onInputChange}
        />
        <label htmlFor={inputId} className={`button button--primary${busy ? ' button--disabled' : ''}`}>
          {IS_HOSTED ? 'Import evidence' : 'Choose evidence package'}
        </label>
      </div>
      {state.phase === 'uploading' ? (
        <progress className="upload__progress" max={100} value={Math.round(state.fraction * 100)} aria-label={IS_HOSTED ? 'Reading the evidence package' : 'Upload progress'} />
      ) : null}
      {state.phase === 'processing' ? <progress className="upload__progress" aria-label="Processing evidence" /> : null}
      <p className={`upload__status upload__status--${tone}`} role="status" aria-live="polite">
        {statusText(state)}
      </p>
    </div>
  );
}
