/**
 * Minimal contextual HTML templating for reports. Every interpolated value is
 * HTML-escaped unless it is already a SafeHtml produced by this module, so evidence
 * values (object names, policy names, collector messages) can never inject markup.
 */
export class SafeHtml {
  constructor(readonly value: string) {}
  toString(): string {
    return this.value;
  }
}

const ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;',
};

export function escapeHtml(value: string): string {
  return value.replace(/[&<>"'`]/g, (c) => ESCAPES[c] ?? c);
}

function render(value: unknown): string {
  if (value instanceof SafeHtml) return value.value;
  if (value === null || value === undefined || value === false) return '';
  if (Array.isArray(value)) return value.map(render).join('');
  if (typeof value === 'string') return escapeHtml(value);
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') return escapeHtml(String(value));
  return escapeHtml(JSON.stringify(value));
}

/** Tagged template: `html\`<p>${text}</p>\`` escapes `text`. */
export function html(strings: TemplateStringsArray, ...values: unknown[]): SafeHtml {
  let out = strings[0] ?? '';
  values.forEach((value, index) => {
    out += render(value) + (strings[index + 1] ?? '');
  });
  return new SafeHtml(out);
}

/** Only absolute https URLs become links; anything else is rendered as text. */
export function safeUrl(url: string): string | undefined {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' ? parsed.toString() : undefined;
  } catch {
    return undefined;
  }
}

export function link(url: string, text: string): SafeHtml {
  const safe = safeUrl(url);
  return safe === undefined ? html`${text} (${url})` : html`<a href="${safe}" rel="noopener noreferrer">${text}</a>`;
}

/** Stable, attribute-safe anchor ID. */
export function anchorId(prefix: string, value: string): string {
  return `${prefix}-${value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')}`;
}
