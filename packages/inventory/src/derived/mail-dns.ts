/**
 * Deterministic parsers for SPF (RFC 7208) and DMARC (RFC 7489) TXT records. They
 * extract facts only; whether a policy is adequate is decided by controls.
 */

export type SpfAllQualifier = 'pass' | 'fail' | 'softfail' | 'neutral';

export interface SpfAnalysis {
  /** none: no v=spf1 record; single: exactly one; multiple: RFC 7208 permerror */
  recordState: 'none' | 'single' | 'multiple';
  record: string | null;
  /** Qualifier of the terminating `all` mechanism, if present. */
  allQualifier: SpfAllQualifier | null;
  /** Value of a redirect= modifier, if present. */
  redirect: string | null;
}

const QUALIFIERS: Record<string, SpfAllQualifier> = {
  '+': 'pass',
  '-': 'fail',
  '~': 'softfail',
  '?': 'neutral',
};

/** DNS TXT strings may be returned quoted or split; normalise whitespace and quotes. */
function cleanTxt(record: string): string {
  return record.replace(/^"|"$/g, '').replace(/"\s*"/g, '').trim();
}

export function analyzeSpf(txtRecords: readonly string[]): SpfAnalysis {
  const spf = txtRecords.map(cleanTxt).filter((r) => /^v=spf1(\s|$)/i.test(r));
  if (spf.length === 0) return { recordState: 'none', record: null, allQualifier: null, redirect: null };
  if (spf.length > 1) return { recordState: 'multiple', record: null, allQualifier: null, redirect: null };
  const record = spf[0] ?? '';
  const terms = record.split(/\s+/).slice(1);
  let allQualifier: SpfAllQualifier | null = null;
  let redirect: string | null = null;
  for (const term of terms) {
    const match = /^([+\-~?]?)all$/i.exec(term);
    if (match) {
      allQualifier = QUALIFIERS[match[1] === '' || match[1] === undefined ? '+' : match[1]] ?? 'pass';
      continue;
    }
    const redirectMatch = /^redirect=(.+)$/i.exec(term);
    if (redirectMatch?.[1] !== undefined) redirect = redirectMatch[1];
  }
  return { recordState: 'single', record, allQualifier, redirect };
}

export interface DmarcAnalysis {
  recordState: 'none' | 'single' | 'multiple';
  record: string | null;
  /** p= tag: none | quarantine | reject, or null when missing/invalid */
  policy: 'none' | 'quarantine' | 'reject' | null;
  subdomainPolicy: 'none' | 'quarantine' | 'reject' | null;
  /** pct= tag (defaults to 100 when absent) */
  percentage: number;
  hasAggregateReporting: boolean;
}

function parsePolicy(value: string | undefined): DmarcAnalysis['policy'] {
  const v = value?.trim().toLowerCase();
  return v === 'none' || v === 'quarantine' || v === 'reject' ? v : null;
}

export function analyzeDmarc(txtRecords: readonly string[]): DmarcAnalysis {
  const dmarc = txtRecords.map(cleanTxt).filter((r) => /^v\s*=\s*DMARC1\s*(;|$)/i.test(r));
  const empty: DmarcAnalysis = {
    recordState: 'none',
    record: null,
    policy: null,
    subdomainPolicy: null,
    percentage: 100,
    hasAggregateReporting: false,
  };
  if (dmarc.length === 0) return empty;
  if (dmarc.length > 1) return { ...empty, recordState: 'multiple' };
  const record = dmarc[0] ?? '';
  const tags = new Map<string, string>();
  for (const part of record.split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    tags.set(part.slice(0, index).trim().toLowerCase(), part.slice(index + 1).trim());
  }
  const pctRaw = tags.get('pct');
  const pct = pctRaw === undefined ? 100 : Number.parseInt(pctRaw, 10);
  return {
    recordState: 'single',
    record,
    policy: parsePolicy(tags.get('p')),
    subdomainPolicy: parsePolicy(tags.get('sp')),
    percentage: Number.isFinite(pct) ? Math.min(Math.max(pct, 0), 100) : 100,
    hasAggregateReporting: (tags.get('rua') ?? '').length > 0,
  };
}
