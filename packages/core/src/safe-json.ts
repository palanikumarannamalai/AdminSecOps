import { AdminSecOpsError } from './errors.js';

export interface SafeJsonOptions {
  /** Maximum size of the input in bytes (UTF-8). Default 50 MiB. */
  maxBytes?: number;
  /** Maximum nesting depth of objects/arrays. Default 64. */
  maxDepth?: number;
  /** Label used in error messages (e.g. file path inside the package). Must not contain evidence. */
  label?: string;
}

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const DEFAULT_MAX_BYTES = 50 * 1024 * 1024;
const DEFAULT_MAX_DEPTH = 64;

/**
 * Parse JSON from untrusted input.
 * - enforces a size limit before parsing
 * - requires valid UTF-8 and strips a leading BOM (Windows PowerShell writes one)
 * - rejects prototype-pollution keys (`__proto__`, `constructor`, `prototype`)
 * - enforces a maximum nesting depth
 * Returns `unknown`; callers must validate the result with a schema.
 */
export function safeJsonParse(input: string | Uint8Array, options: SafeJsonOptions = {}): unknown {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const label = options.label ?? 'input';

  const byteLength =
    typeof input === 'string' ? Buffer.byteLength(input, 'utf8') : input.byteLength;
  if (byteLength > maxBytes) {
    throw new AdminSecOpsError(
      'JSON_TOO_LARGE',
      `${label} exceeds the maximum allowed size of ${maxBytes} bytes.`,
    );
  }

  let text: string;
  if (typeof input === 'string') {
    text = input;
  } else {
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(input);
    } catch {
      throw new AdminSecOpsError('JSON_INVALID_ENCODING', `${label} is not valid UTF-8.`);
    }
  }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

  let parsed: unknown;
  try {
    parsed = JSON.parse(text, (key, value: unknown) => {
      if (FORBIDDEN_KEYS.has(key)) {
        throw new AdminSecOpsError(
          'JSON_FORBIDDEN_KEY',
          `${label} contains a forbidden property name.`,
        );
      }
      return value;
    });
  } catch (error) {
    if (error instanceof AdminSecOpsError) throw error;
    throw new AdminSecOpsError('JSON_INVALID', `${label} is not valid JSON.`);
  }

  assertDepth(parsed, maxDepth, label);
  return parsed;
}

function assertDepth(root: unknown, maxDepth: number, label: string): void {
  // Iterative traversal so hostile input cannot exhaust the call stack.
  const stack: Array<{ value: unknown; depth: number }> = [{ value: root, depth: 0 }];
  while (stack.length > 0) {
    const item = stack.pop();
    if (item === undefined) break;
    const { value, depth } = item;
    if (value === null || typeof value !== 'object') continue;
    if (depth >= maxDepth) {
      throw new AdminSecOpsError(
        'JSON_TOO_DEEP',
        `${label} exceeds the maximum nesting depth of ${maxDepth}.`,
      );
    }
    const children: unknown[] = Array.isArray(value) ? value : Object.values(value);
    for (const child of children) {
      if (child !== null && typeof child === 'object') stack.push({ value: child, depth: depth + 1 });
    }
  }
}

/** JSON serialisation with sorted object keys, for hashing and deterministic output. */
export function stableStringify(value: unknown, space?: number): string {
  return JSON.stringify(sortKeys(value), null, space);
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      out[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}
