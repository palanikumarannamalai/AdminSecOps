import './zod-config';
import { StrictMode, type ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, HashRouter } from 'react-router';
import { AppRoutes } from './App';
import { api as localApi, type ApiClient } from './api/client';
import { AppProvider } from './app/context';
import { applySavedTheme } from './lib/theme';
import { IS_HOSTED, IS_ONLINE } from './mode';
import { OnlineSession } from './app/OnlineSession';
import './styles/tokens.css';
import './styles/app.css';

applySavedTheme();

const container = document.getElementById('root');
if (container === null) throw new Error('Root element #root is missing');
const root = createRoot(container);

function render(client: ApiClient): void {
  // Hosted mode uses hash routing: every view is served by the same static index.html, so a
  // direct refresh always works, and assessment identifiers in the URL fragment are never
  // sent to the web server.
  const Router = IS_HOSTED || IS_ONLINE ? HashRouter : BrowserRouter;
  const app = <AppProvider api={client}><AppRoutes /></AppProvider>;
  const tree: ReactNode = (
    <StrictMode>
      <Router>
        {IS_ONLINE ? <OnlineSession>{app}</OnlineSession> : app}
      </Router>
    </StrictMode>
  );
  root.render(tree);
}

// Compared inline (not via IS_HOSTED) so the local build drops the in-browser engine entirely.
if (import.meta.env.VITE_ADMINSECOPS_MODE === 'hosted') {
  // The in-browser engine is loaded only by the hosted build.
  void import('./api/browser-client').then(({ createBrowserClient }) => render(createBrowserClient()));
} else {
  render(localApi);
}
