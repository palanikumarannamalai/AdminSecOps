import { useEffect, useState } from 'react';

type CopyState = 'idle' | 'copied' | 'failed';

/** Copies text to the clipboard and announces the result to assistive technology. */
export function CopyButton({ text, label = 'Copy', className }: { text: string; label?: string; className?: string }) {
  const [state, setState] = useState<CopyState>('idle');

  useEffect(() => {
    if (state === 'idle') return;
    const timer = window.setTimeout(() => setState('idle'), 2500);
    return () => window.clearTimeout(timer);
  }, [state]);

  const copy = async () => {
    try {
      if (navigator.clipboard === undefined) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(text);
      setState('copied');
    } catch {
      setState('failed');
    }
  };

  return (
    <span className="copy">
      <button type="button" className={`button button--small ${className ?? ''}`} onClick={() => void copy()}>
        {label}
      </button>
      <span className="copy__status" role="status" aria-live="polite">
        {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed: select the text and copy it manually' : ''}
      </span>
    </span>
  );
}
