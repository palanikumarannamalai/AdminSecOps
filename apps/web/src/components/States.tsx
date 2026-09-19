import type { ReactNode } from 'react';
import { errorMessage, isApiError } from '../api/client';

export function LoadingState({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="state state--loading" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      <span>{label}...</span>
    </div>
  );
}

export function ErrorState({
  title = 'Something went wrong',
  error,
  onRetry,
}: {
  title?: string;
  error: unknown;
  onRetry?: () => void;
}) {
  const code = isApiError(error) ? error.code : null;
  return (
    <div className="state state--error" role="alert">
      <h2 className="state__title">{title}</h2>
      <p>{errorMessage(error)}</p>
      {code !== null ? <p className="muted small">Error code: {code}</p> : null}
      {onRetry !== undefined ? (
        <button type="button" className="button" onClick={onRetry}>
          Try again
        </button>
      ) : null}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="state state--empty">
      <h2 className="state__title">{title}</h2>
      {children}
    </div>
  );
}
