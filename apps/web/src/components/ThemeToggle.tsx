import { useEffect, useState } from 'react';
import { currentTheme, setTheme, type Theme } from '../lib/theme';

/** Light/dark switch. Shares the palanikumar.net preference (localStorage 'theme'). */
export function ThemeToggle() {
  const [theme, setState] = useState<Theme>(() => currentTheme());

  // Without an explicit choice the theme follows the operating system; keep the label in step.
  useEffect(() => {
    if (typeof matchMedia !== 'function') return undefined;
    const query = matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => setState(currentTheme());
    query.addEventListener('change', onChange);
    return () => query.removeEventListener('change', onChange);
  }, []);

  const next: Theme = theme === 'dark' ? 'light' : 'dark';
  return (
    <button
      type="button"
      className="button button--small theme-toggle"
      aria-pressed={theme === 'dark'}
      aria-label={`Switch to ${next} theme`}
      onClick={() => {
        setTheme(next);
        setState(next);
      }}
    >
      {theme === 'dark' ? 'Light theme' : 'Dark theme'}
    </button>
  );
}
