/*
 * Light/dark theme. The hosted application shares the site's preference: palanikumar.net stores
 * the visitor's choice in localStorage['theme'] ('light' | 'dark') on the same origin. Without a
 * saved choice, CSS follows prefers-color-scheme (see tokens.css). The preference is a display
 * setting only; it is not sent anywhere.
 */
export type Theme = 'light' | 'dark';
const KEY = 'theme';

function saved(): Theme | null {
  try {
    const value = localStorage.getItem(KEY);
    return value === 'light' || value === 'dark' ? value : null;
  } catch {
    return null;
  }
}

export function currentTheme(): Theme {
  const explicit = document.documentElement.dataset.theme;
  if (explicit === 'light' || explicit === 'dark') return explicit;
  return typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function applySavedTheme(): void {
  const theme = saved();
  if (theme !== null) document.documentElement.dataset.theme = theme;
}

export function setTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    // Storage unavailable: the choice applies to this page view only.
  }
}
