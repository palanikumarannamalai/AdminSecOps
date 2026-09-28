/*
 * Uses the personal site's dark default and light/dark choices. Storage is local to this
 * app's origin: the parent site's preference is not shared across subdomains.
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
  document.documentElement.dataset.theme = theme ?? 'dark';
}

export function setTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    // Storage unavailable: the choice applies to this page view only.
  }
}
