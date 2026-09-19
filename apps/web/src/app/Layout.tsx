import { PRODUCT_DESCRIPTION, PRODUCT_NAME, PRODUCT_TAGLINE } from '@adminsecops/core/version';
import { type ChangeEvent } from 'react';
import { NavLink, Outlet, useLocation, useMatch, useNavigate } from 'react-router';
import { environmentName, formatDate } from '../lib/format';
import { IS_HOSTED, OVERVIEW_URL } from '../mode';
import { ThemeToggle } from '../components/ThemeToggle';
import { useAssessmentList } from './context';

/** Assessment-scoped pages, in navigation order. */
export const ASSESSMENT_PAGES = [
  { path: '', label: 'Overview' },
  { path: 'findings', label: 'Findings' },
  { path: 'controls', label: 'Controls' },
  { path: 'evidence', label: 'Evidence' },
  { path: 'inventory', label: 'Inventory' },
  { path: 'frameworks', label: 'Frameworks' },
  { path: 'reports', label: 'Reports' },
] as const;

function useSelectedAssessmentId(): string | null {
  const match = useMatch('/assessments/:assessmentId/*');
  const list = useAssessmentList();
  if (match?.params.assessmentId !== undefined) return match.params.assessmentId;
  if (list.status === 'success' && list.data.length > 0) return list.data[0]?.assessmentId ?? null;
  return null;
}

/** Path for the same page of another assessment (finding detail falls back to the findings list). */
export function switchAssessmentPath(pathname: string, newId: string): string {
  const match = /^\/assessments\/[^/]+(?:\/([^/]+))?/.exec(pathname);
  const page = match?.[1];
  if (page === undefined) return `/assessments/${encodeURIComponent(newId)}`;
  return `/assessments/${encodeURIComponent(newId)}/${page}`;
}

function AssessmentSwitcher({ selectedId }: { selectedId: string | null }) {
  const list = useAssessmentList();
  const navigate = useNavigate();
  const location = useLocation();

  if (list.status !== 'success' || list.data.length === 0) return null;

  const onChange = (event: ChangeEvent<HTMLSelectElement>) => {
    const id = event.target.value;
    if (id === '') return;
    void navigate(
      location.pathname.startsWith('/assessments/')
        ? switchAssessmentPath(location.pathname, id)
        : `/assessments/${encodeURIComponent(id)}`,
    );
  };

  const inList = selectedId !== null && list.data.some((a) => a.assessmentId === selectedId);

  return (
    <div className="switcher">
      <label htmlFor="assessment-switcher" className="switcher__label">
        Assessment
      </label>
      <select id="assessment-switcher" className="select" value={inList ? selectedId : ''} onChange={onChange}>
        {!inList ? <option value="">Select an assessment</option> : null}
        {list.data.map((a) => (
          <option key={a.assessmentId} value={a.assessmentId}>
            {environmentName(a)} - {formatDate(a.assessedAt)}
            {a.source === 'sample' ? ' (sample)' : ''}
          </option>
        ))}
      </select>
    </div>
  );
}

function navClass({ isActive }: { isActive: boolean }): string {
  return isActive ? 'nav__link nav__link--active' : 'nav__link';
}

export function Layout() {
  const selectedId = useSelectedAssessmentId();
  const base = selectedId !== null ? `/assessments/${encodeURIComponent(selectedId)}` : null;

  return (
    <div className="shell">
      <a
        href="#main"
        className="skip-link"
        onClick={(event) => {
          // Move focus without changing the URL: with hash routing, "#main" would be treated as a route.
          event.preventDefault();
          document.getElementById('main')?.focus();
        }}
      >
        Skip to main content
      </a>
      <header className="topbar">
        <div className="topbar__brand">
          <NavLink to="/" className="brand">
            <span className="brand__mark" aria-hidden="true">
              <svg viewBox="0 0 24 24" width="22" height="22" focusable="false">
                <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="currentColor" />
                <path className="brand__check" d="m8.5 12 2.5 2.5 4.5-5" fill="none" strokeWidth="2" strokeLinecap="round" />
              </svg>
            </span>
            <span className="brand__name">{PRODUCT_NAME}</span>
          </NavLink>
          <span className="topbar__tagline">
            <span className="topbar__tagline-main">{PRODUCT_TAGLINE}</span>
            <span className="topbar__tagline-sub">{PRODUCT_DESCRIPTION}</span>
          </span>
        </div>
        <div className="topbar__actions">
          <AssessmentSwitcher selectedId={selectedId} />
          <ThemeToggle />
          {IS_HOSTED ? (
            <a className="button button--small topbar__overview" href={OVERVIEW_URL}>
              Return to AdminSecOps overview
            </a>
          ) : null}
        </div>
      </header>
      <div className="shell__body">
        <nav className="nav" aria-label="Main">
          <ul className="nav__list">
            <li>
              <NavLink to="/" end className={navClass}>
                {IS_HOSTED ? 'Start' : 'Assessments'}
              </NavLink>
            </li>
          </ul>
          <p className="nav__heading" id="nav-assessment-heading">
            Selected assessment
          </p>
          <ul className="nav__list" aria-labelledby="nav-assessment-heading">
            {ASSESSMENT_PAGES.map((page) => (
              <li key={page.label}>
                {base !== null ? (
                  <NavLink to={page.path === '' ? base : `${base}/${page.path}`} end={page.path === ''} className={navClass}>
                    {page.label}
                  </NavLink>
                ) : (
                  <span className="nav__link nav__link--disabled" aria-disabled="true">
                    {page.label}
                  </span>
                )}
              </li>
            ))}
          </ul>
          <p className="nav__heading" id="nav-tools-heading">
            Tools
          </p>
          <ul className="nav__list" aria-labelledby="nav-tools-heading">
            <li>
              <NavLink to="/compare" className={navClass}>
                Compare
              </NavLink>
            </li>
            <li>
              <NavLink to="/library" className={navClass}>
                Control library
              </NavLink>
            </li>
            <li>
              <NavLink to="/about" className={navClass}>
                {IS_HOSTED ? 'Privacy and safety' : 'About and privacy'}
              </NavLink>
            </li>
          </ul>
          <p className="nav__footnote">
            {IS_HOSTED
              ? 'Processed in this browser. Evidence is not uploaded to palanikumar.net.'
              : 'Local-only. Evidence never leaves this machine.'}
          </p>
        </nav>
        <main id="main" className="main" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
