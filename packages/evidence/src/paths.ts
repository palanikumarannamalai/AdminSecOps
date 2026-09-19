import { AdminSecOpsError } from '@adminsecops/core';

/** In-memory package contents keyed by normalised relative path (forward slashes). Node.js Buffers are Uint8Arrays. */
export type PackageFiles = Map<string, Uint8Array>;

export const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
export const MAX_DEPTH = 6;
export const S_IFMT = 0o170000;
export const S_IFLNK = 0o120000;
export const ONE_MIB = 1024 * 1024;

/**
 * Validate and normalise a path from an archive or directory listing. Rejects absolute
 * paths, drive letters, traversal segments, unusual characters and excessive depth.
 * Returns undefined for directory entries.
 */
export function normalizePackagePath(raw: string): string | undefined {
  const unified = raw.replace(/\\/g, '/');
  if (unified.endsWith('/')) return undefined;
  if (unified.startsWith('/') || /^[A-Za-z]:/.test(unified) || unified.includes('\0')) {
    throw new AdminSecOpsError('PACKAGE_UNSAFE_PATH', 'The evidence package contains an unsafe file path.');
  }
  const segments = unified.split('/');
  if (segments.length > MAX_DEPTH) {
    throw new AdminSecOpsError('PACKAGE_UNSAFE_PATH', 'The evidence package contains an overly deep file path.');
  }
  for (const segment of segments) {
    if (segment === '' || segment === '.' || segment === '..' || !SAFE_SEGMENT.test(segment)) {
      throw new AdminSecOpsError('PACKAGE_UNSAFE_PATH', 'The evidence package contains an unsafe file path.');
    }
  }
  return segments.join('/');
}

