import { useState } from 'react';
import { ThemeToggle } from '../components/ThemeToggle';

const features = [
  [
    '01',
    'Connect with control',
    'Use your Microsoft identity. Review consent and connect the workloads you want to assess.',
  ],
  [
    '02',
    'See what matters',
    'Review prioritized findings alongside their evidence and an honest view of what could not be tested.',
  ],
  [
    '03',
    'Move forward clearly',
    'Understand the recommended change, prerequisites, rollback and verification before acting.',
  ],
];

export function SignInPage() {
  const [tenant, setTenant] = useState('');
  const tenantId = tenant.trim();
  const validTenant = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
    tenantId,
  );
  // Scroll without changing the hash-router location.
  const scrollTo = (id: string) =>
    document.getElementById(id)?.scrollIntoView({
      behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches
        ? 'instant'
        : 'smooth',
      block: 'start',
    });
  return (
    <div className="marketing">
      <a
        className="skip-link"
        href="#landing-main"
        onClick={(e) => {
          e.preventDefault();
          document.getElementById('landing-main')?.focus();
        }}
      >
        Skip to main content
      </a>
      <header className="marketing-nav">
        <a className="brand" href="/" aria-label="ConfigReview home">
          <span className="brand-symbol" aria-hidden="true">
            ◈
          </span>{' '}
          ConfigReview
        </a>
        <nav aria-label="Product">
          <button onClick={() => scrollTo('platform')}>Platform</button>
          <button onClick={() => scrollTo('how-it-works')}>How it works</button>
          <button onClick={() => scrollTo('trust')}>Trust &amp; privacy</button>
          <a href="https://github.com/palanikumarannamalai/AdminSecOps">GitHub</a>
        </nav>
        <div className="inline-actions">
          <ThemeToggle />
          <a className="button button--primary" href="/auth/login">
            Open workspace <span aria-hidden="true">↗</span>
          </a>
        </div>
      </header>
      <main id="landing-main" tabIndex={-1}>
        <section className="marketing-hero" aria-labelledby="hero-title">
          <div className="hero-copy">
            <p className="eyebrow">Microsoft security. Clearer.</p>
            <h1 id="hero-title">
              Less noise.
              <br />
              More security
              <br />
              <span>clarity.</span>
            </h1>
            <p className="hero-description">
              Understand your Microsoft environment, prioritize findings, and turn evidence into a
              clear next step.
            </p>
            <p className="notice" role="note">
              <strong>Test release.</strong> No live tenant has been validated in this release —
              connect an authorised test tenant, not production.
            </p>
            <a className="button button--primary button--large" href="/auth/login">
              Sign in with Microsoft <span aria-hidden="true">→</span>
            </a>
            <p className="hero-assurance">
              Read-only assessments <span>·</span> Browser-based <span>·</span> Test release
            </p>
          </div>
          <div className="product-preview" aria-label="Illustrative assessment preview">
            <p className="eyebrow">Contoso / Example assessment</p>
            <h2>Know where you stand.</h2>
            <dl className="preview-stats">
              <div>
                <dd>38</dd>
                <dt>Assessed</dt>
              </div>
              <div>
                <dd>6</dd>
                <dt>Findings</dt>
              </div>
              <div>
                <dd>12</dd>
                <dt>To review</dt>
              </div>
            </dl>
            <p className="eyebrow">Priority findings</p>
            <ul className="preview-findings">
              <li>Review administrator MFA coverage</li>
              <li>Review external sharing settings</li>
              <li>Confirm device compliance requirements</li>
            </ul>
            <p className="preview-caption">Illustrative data · coverage is not a security score</p>
          </div>
        </section>
        <section className="workload-strip" id="platform" aria-labelledby="platform-title">
          <h2 className="eyebrow" id="platform-title">
            One workspace for your Microsoft environment
          </h2>
          <ul>
            {['Entra ID', 'Microsoft 365', 'Intune', 'Azure', 'Exchange Online'].map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
          <p className="muted small">
            Coverage depends on connected workloads, permissions and licensing. On-premises checks
            are not available online.
          </p>
        </section>
        <section className="marketing-features" id="how-it-works" aria-labelledby="workflow-title">
          <p className="eyebrow">A clearer way to assess</p>
          <h2 id="workflow-title">From configuration to confidence.</h2>
          <div className="feature-grid">
            {features.map(([number, title, description]) => (
              <article key={number}>
                <span className="feature-number">{number}</span>
                <h3>{title}</h3>
                <p>{description}</p>
              </article>
            ))}
          </div>
        </section>
        <section className="marketing-trust" id="trust" aria-labelledby="trust-title">
          <div>
            <p className="eyebrow">Built around your control</p>
            <h2 id="trust-title">Your tenant. Your control.</h2>
            <p>
              Fixed read operations. Clear permission requirements.
              <br />
              No automatic remediation. Unknown stays unknown.
            </p>
          </div>
          <a className="button button--primary button--large" href="/auth/login">
            Start your assessment <span aria-hidden="true">→</span>
          </a>
        </section>
        <section className="onboarding" aria-labelledby="onboarding-title">
          <div>
            <p className="eyebrow">Getting started</p>
            <h2 id="onboarding-title">Connect the right organization.</h2>
            <p>
              Sign in with your Microsoft work account, or enter a specific organization's directory
              ID.
            </p>
            <p className="muted small">
              Supported roles: Global Administrator, Security Administrator, Global Reader, Security
              Reader, or Privileged Role Administrator.
            </p>
            <p className="muted small">
              A tenant administrator must grant consent on Microsoft's screen. A supported sign-in
              role does not automatically grant permission to consent.
            </p>
          </div>
          <div className="tenant-entry">
            <label htmlFor="login-tenant-id">Directory (tenant) ID</label>
            <input
              id="login-tenant-id"
              className="input"
              type="text"
              value={tenant}
              autoComplete="off"
              spellCheck={false}
              aria-describedby="tenant-help tenant-validation"
              aria-invalid={tenantId !== '' && !validTenant}
              onChange={(event) => setTenant(event.target.value)}
            />
            <p id="tenant-help" className="muted small">
              Use the directory ID from Microsoft Entra overview. Customer directories are not
              publicly listed.
            </p>
            <p id="tenant-validation" className="error-text" role="status">
              {tenantId !== '' && !validTenant
                ? 'Enter a valid directory ID in UUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).'
                : ''}
            </p>
            {validTenant ? (
              <a
                className="button"
                href={`/auth/login?tenantId=${encodeURIComponent(tenantId.toLowerCase())}`}
              >
                Sign in to customer tenant
              </a>
            ) : (
              <button className="button" disabled>
                Sign in to customer tenant
              </button>
            )}
          </div>
        </section>
        <section className="marketing-details" aria-label="Access and data handling">
          <details>
            <summary>Permissions, licensing and data handling</summary>
            <p>
              Reading SharePoint settings needs Global Reader or SharePoint Administrator. Intune
              needs a licence and a role with Intune read access. Connect Azure subscriptions
              separately after sign-in. Its delegated permission may carry your account's write
              authority; ConfigReview executes only fixed read operations. Exchange Online assessment
              is not enabled in the hosted service. The only Exchange connection Microsoft offers
              for this data requires a management-scoped permission, so it stays off until there is
              a read-only path or an explicit opt-in.
            </p>
            <p>
              Raw evidence is processed in memory by the hosted service. Results are stored for 30
              days and audit events for 90 days. Missing data is reported as not assessed, never as
              passing. This test release does not provide security certification.
            </p>
          </details>
        </section>
      </main>
      <footer className="marketing-footer">
        <a className="brand" href="/">
          ◈ ConfigReview
        </a>
        <span>A community project by Palanikumar Annamalai</span>
        <a href="https://www.palanikumar.net/tools/configreview">Meet the author</a>
        <a href="https://github.com/palanikumarannamalai/AdminSecOps/blob/main/CONTRIBUTING.md">
          Contribute
        </a>
      </footer>
    </div>
  );
}
