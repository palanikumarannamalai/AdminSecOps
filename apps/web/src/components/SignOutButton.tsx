import { useState } from 'react';
import { onlineRequest } from '../app/OnlineSession';
import { errorMessage } from '../api/client';

export function SignOutButton() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const signOut = async () => {
    setBusy(true);
    setError(null);
    try {
      await onlineRequest('/auth/logout', undefined, 'POST');
      window.location.assign('/');
    } catch (cause) {
      setError(errorMessage(cause));
      setBusy(false);
    }
  };
  return (
    <div className="account-action">
      <button
        className="button button--small sign-out"
        disabled={busy}
        onClick={() => void signOut()}
      >
        {busy ? 'Signing out…' : 'Sign out'}
      </button>
      {error ? (
        <p className="account-action__error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
