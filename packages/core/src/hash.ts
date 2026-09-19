import { sha256 } from '@noble/hashes/sha2.js';

/*
 * SHA-256 uses @noble/hashes (audited, dependency-free, synchronous) so the same code runs in
 * Node.js and in the browser-hosted application. Evidence verification must stay synchronous and
 * identical in both environments; WebCrypto is asynchronous-only.
 */

const encoder = new TextEncoder();

function toBytes(data: Uint8Array | string): Uint8Array {
  return typeof data === 'string' ? encoder.encode(data) : data;
}

function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Standard base64 (with padding) without relying on Buffer or btoa. */
export function toBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i] ?? 0;
    const b = bytes[i + 1];
    const c = bytes[i + 2];
    const triple = (a << 16) | ((b ?? 0) << 8) | (c ?? 0);
    out += BASE64[(triple >> 18) & 63];
    out += BASE64[(triple >> 12) & 63];
    out += b === undefined ? '=' : BASE64[(triple >> 6) & 63];
    out += c === undefined ? '=' : BASE64[triple & 63];
  }
  return out;
}

/** Lower-case hex SHA-256 of the given bytes or UTF-8 string. */
export function sha256Hex(data: Uint8Array | string): string {
  return toHex(sha256(toBytes(data)));
}

/** Base64 SHA-256 (as used in Content-Security-Policy hash sources). */
export function sha256Base64(data: Uint8Array | string): string {
  return toBase64(sha256(toBytes(data)));
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
