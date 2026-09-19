import { lstat, readdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import type { Readable } from 'node:stream';
import yauzl from 'yauzl';
import { AdminSecOpsError } from '@adminsecops/core';
import { DEFAULT_PACKAGE_LIMITS, type PackageLimits } from './limits.js';

/** In-memory package contents keyed by normalised relative path (forward slashes). */
export type PackageFiles = Map<string, Buffer>;

const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const MAX_DEPTH = 6;
const S_IFMT = 0o170000;
const S_IFLNK = 0o120000;
const ONE_MIB = 1024 * 1024;

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

/**
 * Read a ZIP evidence package entirely in memory. Nothing is extracted to disk, so
 * there are no temporary files to protect or clean up. Enforces entry count, size,
 * compression ratio and path rules; rejects encrypted entries and symbolic links.
 */
export async function readZipPackage(archive: Buffer, limits: PackageLimits = DEFAULT_PACKAGE_LIMITS): Promise<PackageFiles> {
  if (archive.byteLength > limits.maxArchiveBytes) {
    throw new AdminSecOpsError('PACKAGE_TOO_LARGE', `The evidence package exceeds the ${limits.maxArchiveBytes} byte limit.`, {
      statusCode: 413,
    });
  }

  let zip: yauzl.ZipFile;
  try {
    zip = await yauzl.fromBufferPromise(archive, {
      lazyEntries: true,
      validateEntrySizes: true,
      decodeStrings: true,
      strictFileNames: false,
    });
  } catch {
    throw new AdminSecOpsError('PACKAGE_NOT_ZIP', 'The uploaded file is not a valid ZIP archive.');
  }

  const files: PackageFiles = new Map();
  let entryCount = 0;
  let totalBytes = 0;

  try {
    if (zip.entryCount > limits.maxEntries) {
      throw new AdminSecOpsError('PACKAGE_TOO_MANY_ENTRIES', `The evidence package has more than ${limits.maxEntries} entries.`);
    }
    for await (const entry of zip.eachEntry()) {
      entryCount += 1;
      if (entryCount > limits.maxEntries) {
        throw new AdminSecOpsError('PACKAGE_TOO_MANY_ENTRIES', `The evidence package has more than ${limits.maxEntries} entries.`);
      }
      const normalized = normalizePackagePath(entry.fileName);
      if (normalized === undefined) continue;

      if (entry.isEncrypted()) {
        throw new AdminSecOpsError('PACKAGE_ENCRYPTED_ENTRY', 'Encrypted ZIP entries are not supported.');
      }
      const unixMode = (entry.externalFileAttributes >>> 16) & S_IFMT;
      if (unixMode === S_IFLNK) {
        throw new AdminSecOpsError('PACKAGE_SYMLINK', 'Symbolic links are not permitted in evidence packages.');
      }
      if (files.has(normalized)) {
        throw new AdminSecOpsError('PACKAGE_DUPLICATE_ENTRY', 'The evidence package contains duplicate file names.');
      }
      if (entry.uncompressedSize > limits.maxFileBytes) {
        throw new AdminSecOpsError('PACKAGE_FILE_TOO_LARGE', `A file in the evidence package exceeds the ${limits.maxFileBytes} byte limit.`);
      }
      if (
        entry.uncompressedSize > ONE_MIB &&
        entry.uncompressedSize / Math.max(entry.compressedSize, 1) > limits.maxCompressionRatio
      ) {
        throw new AdminSecOpsError('PACKAGE_COMPRESSION_RATIO', 'The evidence package has a suspicious compression ratio.');
      }
      if (totalBytes + entry.uncompressedSize > limits.maxTotalBytes) {
        throw new AdminSecOpsError('PACKAGE_TOO_LARGE', `The evidence package exceeds the ${limits.maxTotalBytes} byte uncompressed limit.`, {
          statusCode: 413,
        });
      }

      const stream = await zip.openReadStreamPromise(entry);
      const content = await readBounded(stream, limits.maxFileBytes, limits.maxTotalBytes - totalBytes);
      totalBytes += content.byteLength;
      files.set(normalized, content);
    }
  } catch (error) {
    if (error instanceof AdminSecOpsError) throw error;
    throw new AdminSecOpsError('PACKAGE_CORRUPT', 'The evidence package could not be read (corrupt or unsupported ZIP).');
  } finally {
    zip.close();
  }
  return files;
}

/** Read a stream into memory while enforcing byte limits on the actual (not declared) size. */
async function readBounded(stream: Readable, maxFileBytes: number, remainingTotal: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    size += buffer.byteLength;
    if (size > maxFileBytes || size > remainingTotal) {
      stream.destroy();
      throw new AdminSecOpsError('PACKAGE_FILE_TOO_LARGE', 'A file in the evidence package exceeds the size limit.');
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks, size);
}

/**
 * Read an extracted evidence package from a directory (used for sanitized fixtures and
 * for administrators who prefer not to create a ZIP). Symbolic links and junctions are
 * rejected and every file must resolve inside the root directory.
 */
export async function readDirectoryPackage(root: string, limits: PackageLimits = DEFAULT_PACKAGE_LIMITS): Promise<PackageFiles> {
  const rootReal = await realpath(root);
  const files: PackageFiles = new Map();
  let totalBytes = 0;
  let count = 0;

  const walk = async (dir: string, depth: number): Promise<void> => {
    if (depth > MAX_DEPTH) {
      throw new AdminSecOpsError('PACKAGE_UNSAFE_PATH', 'The evidence directory is too deep.');
    }
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      const info = await lstat(full);
      if (info.isSymbolicLink()) {
        throw new AdminSecOpsError('PACKAGE_SYMLINK', 'Symbolic links are not permitted in evidence packages.');
      }
      const resolved = await realpath(full);
      const relativeToRoot = path.relative(rootReal, resolved);
      if (relativeToRoot.startsWith('..') || path.isAbsolute(relativeToRoot)) {
        throw new AdminSecOpsError('PACKAGE_UNSAFE_PATH', 'The evidence directory contains a path outside its root.');
      }
      if (info.isDirectory()) {
        await walk(full, depth + 1);
        continue;
      }
      if (!info.isFile()) continue;
      count += 1;
      if (count > limits.maxEntries) {
        throw new AdminSecOpsError('PACKAGE_TOO_MANY_ENTRIES', `The evidence directory has more than ${limits.maxEntries} files.`);
      }
      if (info.size > limits.maxFileBytes) {
        throw new AdminSecOpsError('PACKAGE_FILE_TOO_LARGE', `A file in the evidence directory exceeds the ${limits.maxFileBytes} byte limit.`);
      }
      totalBytes += info.size;
      if (totalBytes > limits.maxTotalBytes) {
        throw new AdminSecOpsError('PACKAGE_TOO_LARGE', `The evidence directory exceeds the ${limits.maxTotalBytes} byte limit.`);
      }
      const normalized = normalizePackagePath(relativeToRoot.split(path.sep).join('/'));
      if (normalized !== undefined) files.set(normalized, await readFile(resolved));
    }
  };

  await walk(rootReal, 0);
  return files;
}
