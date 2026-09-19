export interface BarItem {
  key: string;
  label: string;
  value: number;
  /** CSS modifier used for the bar colour, e.g. "severity-high" or "status-fail". */
  tone: string;
}

/**
 * Horizontal bar list. Every value is printed as text next to its label, so the bars
 * are decorative (aria-hidden) and the information never depends on colour alone.
 */
export function BarList({ items, caption }: { items: readonly BarItem[]; caption: string }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <figure className="barlist">
      <figcaption className="barlist__caption">{caption}</figcaption>
      <ul className="barlist__rows">
        {items.map((item) => (
          <li key={item.key} className="barlist__row">
            <span className="barlist__label">{item.label}</span>
            <span className="barlist__track" aria-hidden="true">
              <span
                className={`barlist__bar tone-${item.tone}`}
                style={{ width: `${item.value === 0 ? 0 : Math.max(2, (item.value / max) * 100)}%` }}
              />
            </span>
            <span className="barlist__value">{item.value.toLocaleString()}</span>
          </li>
        ))}
      </ul>
    </figure>
  );
}

/** Single stacked bar. Decorative: callers must also render the counts as text. */
export function StackedBar({ items }: { items: readonly BarItem[] }) {
  const total = items.reduce((sum, i) => sum + i.value, 0);
  return (
    <span className="stacked" aria-hidden="true">
      {total === 0 ? (
        <span className="stacked__segment tone-empty" style={{ width: '100%' }} />
      ) : (
        items
          .filter((i) => i.value > 0)
          .map((i) => (
            <span key={i.key} className={`stacked__segment tone-${i.tone}`} style={{ width: `${(i.value / total) * 100}%` }} />
          ))
      )}
    </span>
  );
}

/** Progress-style bar for coverage values. */
export function CoverageBar({ assessed, applicable }: { assessed: number; applicable: number }) {
  const pct = applicable === 0 ? 0 : Math.round((assessed / applicable) * 100);
  return (
    <span className="coverage-bar" aria-hidden="true">
      <span className="coverage-bar__fill" style={{ width: `${pct}%` }} />
    </span>
  );
}
