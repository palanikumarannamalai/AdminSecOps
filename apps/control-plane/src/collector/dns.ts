import { Resolver } from 'node:dns/promises';
import { CollectionCancelledError } from './graph-client.js';

/**
 * Public DNS TXT lookups for mail authentication records (SPF and DMARC).
 *
 * Limits of this evidence, recorded in every dataset it produces:
 * - Answers come from the hosting platform's recursive resolver, not from the domain's
 *   authoritative servers, and are not DNSSEC-validated. They show what was published at
 *   collection time.
 * - DNS never establishes Exchange accepted domains or DKIM signing state: the domain list
 *   comes from Exchange Online (accepted domains) when that connector ran, otherwise from the
 *   tenant's verified domains with the Email capability.
 */

export type TxtLookupStatus = 'Found' | 'NotFound' | 'Error';

export interface TxtLookup {
  readonly status: TxtLookupStatus;
  /** Complete TXT strings (multi-string records concatenated). */
  readonly records: readonly string[];
}

export interface TxtResolver {
  resolveTxt(name: string, signal?: AbortSignal): Promise<TxtLookup>;
}

/** Only LDH host names with at least two labels; no IP literals, wildcards or trailing dots. */
export function isQueryableDomain(name: string): boolean {
  if (name.length === 0 || name.length > 253) return false;
  const labels = name.split('.');
  return labels.length >= 2 && labels.every((l) => /^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(l)) && !/^\d+$/.test(labels[labels.length - 1] ?? '');
}

const NOT_FOUND_CODES = new Set(['ENODATA', 'ENOTFOUND']);
const aborted = (signal: AbortSignal | undefined): boolean => signal?.aborted === true;

/** Resolver using the platform's configured DNS servers with bounded time and retries. */
export function createSystemTxtResolver(options: { timeoutMs?: number; tries?: number } = {}): TxtResolver {
  return {
    async resolveTxt(name, signal) {
      if (signal?.aborted === true) throw new CollectionCancelledError();
      const resolver = new Resolver({ timeout: options.timeoutMs ?? 3000, tries: options.tries ?? 2 });
      const onAbort = (): void => resolver.cancel();
      signal?.addEventListener('abort', onAbort, { once: true });
      try {
        const chunks = await resolver.resolveTxt(name);
        const records = chunks.map((parts) => parts.join(''));
        return { status: records.length > 0 ? 'Found' : 'NotFound', records };
      } catch (error) {
        if (aborted(signal)) throw new CollectionCancelledError();
        const code = (error as { code?: unknown }).code;
        return { status: typeof code === 'string' && NOT_FOUND_CODES.has(code) ? 'NotFound' : 'Error', records: [] };
      } finally {
        signal?.removeEventListener('abort', onAbort);
      }
    },
  };
}
