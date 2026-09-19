import { createHash } from 'node:crypto';

/** Lower-case hex SHA-256 of the given bytes or UTF-8 string. */
export function sha256Hex(data: Uint8Array | string): string {
  return createHash('sha256').update(data).digest('hex');
}

const SHA256_PATTERN = /^[a-f0-9]{64}$/;

export function isSha256Hex(value: string): boolean {
  return SHA256_PATTERN.test(value);
}

/**
 * Deterministic identifier derived from the given parts. Used for finding IDs so that
 * the same control evaluated in the same assessment always produces the same ID.
 */
export function deterministicId(prefix: string, ...parts: readonly string[]): string {
  const digest = sha256Hex(parts.join('\u001f'));
  return `${prefix}-${digest.slice(0, 20)}`;
}
