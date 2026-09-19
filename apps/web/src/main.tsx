import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router';
import { AppRoutes } from './App';
import { AppProvider } from './app/context';
import './styles/tokens.css';
import './styles/app.css';

const container = document.getElementById('root');
if (container === null) throw new Error('Root element #root is missing');

createRoot(container).render(
  <StrictMode>
    <BrowserRouter>
      <AppProvider>
        <AppRoutes />
      </AppProvider>
    </BrowserRouter>
  </StrictMode>,
);
