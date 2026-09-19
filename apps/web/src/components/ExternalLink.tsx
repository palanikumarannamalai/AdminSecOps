import { safeHttpsUrl } from '../lib/url';

/**
 * External link from API data. Only https URLs are rendered as links; anything else
 * is shown as plain text so it can be reviewed but not followed.
 */
export function ExternalLink({ href, children }: { href: string; children: string }) {
  const safe = safeHttpsUrl(href);
  if (safe === null) {
    return (
      <span>
        {children} <span className="muted small">(link not shown: only https links are opened)</span>
      </span>
    );
  }
  return (
    <a href={safe} target="_blank" rel="noopener noreferrer" className="external-link">
      {children}
      <span className="visually-hidden"> (opens in a new tab)</span>
    </a>
  );
}
