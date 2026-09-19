import { Inflate } from 'fflate';
import { AdminSecOpsError } from '@adminsecops/core';
import { DEFAULT_PACKAGE_LIMITS, type PackageLimits } from './limits.js';
import { ONE_MIB, S_IFLNK, S_IFMT, normalizePackagePath, type PackageFiles } from './paths.js';

/*
 * Platform-independent ZIP reader used by the browser-hosted application. It parses the ZIP
 * central directory itself and inflates entries with fflate (pure JavaScript), applying the same
 * rules as the Node.js reader (package-reader.ts, yauzl):
 *   - archive, entry-count, per-file, total and compression-ratio limits;
 *   - limits enforced on the ACTUAL inflated size while inflating, not only on declared sizes;
 *   - declared sizes and CRC-32 must match the inflated data;
 *   - encrypted entries, symbolic links, duplicate names, unsafe paths, ZIP64 and multi-disk
 *     archives are rejected;
 *   - entry data must lie inside the archive and before the central directory.
 * Nothing is written anywhere; the result is an in-memory map.
 */

const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;
const FLAG_ENCRYPTED = 0x0001;
const FLAG_STRONG_ENCRYPTION = 0x0040;
const FLAG_UTF8 = 0x0800;
const METHOD_STORED = 0;
const METHOD_DEFLATE = 8;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of data) crc = (CRC_TABLE[(crc ^ byte) & 0xff] ?? 0) ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function corrupt(detail: string): AdminSecOpsError {
  return new AdminSecOpsError('PACKAGE_CORRUPT', 'The evidence package could not be read (corrupt or unsupported ZIP).', { internalDetail: detail });
}

class Reader {
  private readonly view: DataView;
  constructor(private readonly bytes: Uint8Array) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  get length(): number {
    return this.bytes.byteLength;
  }
  u16(offset: number): number {
    if (offset < 0 || offset + 2 > this.length) throw corrupt('read beyond archive');
    return this.view.getUint16(offset, true);
  }
  u32(offset: number): number {
    if (offset < 0 || offset + 4 > this.length) throw corrupt('read beyond archive');
    return this.view.getUint32(offset, true);
  }
  slice(start: number, end: number): Uint8Array {
    if (start < 0 || end > this.length || end < start) throw corrupt('slice beyond archive');
    return this.bytes.subarray(start, end);
  }
}

function findEndOfCentralDirectory(r: Reader): number {
  // The EOCD record is 22 bytes plus an optional comment of up to 65,535 bytes.
  const earliest = Math.max(0, r.length - 22 - 0xffff);
  for (let offset = r.length - 22; offset >= earliest; offset--) {
    if (r.u32(offset) === SIG_EOCD && offset + 22 + r.u16(offset + 20) === r.length) return offset;
  }
  throw new AdminSecOpsError('PACKAGE_NOT_ZIP', 'The uploaded file is not a valid ZIP archive.');
}

function inflateBounded(data: Uint8Array, limit: number): Uint8Array {
  const chunks: Uint8Array[] = [];
  let size = 0;
  const inflater = new Inflate((chunk: Uint8Array) => {
    size += chunk.byteLength;
    if (size > limit) {
      throw new AdminSecOpsError('PACKAGE_FILE_TOO_LARGE', 'A file in the evidence package exceeds the size limit.');
    }
    chunks.push(chunk);
  });
  try {
    inflater.push(data, true);
  } catch (error) {
    if (error instanceof AdminSecOpsError) throw error;
    throw corrupt('inflate failed');
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/** Read a ZIP evidence package held in memory (browser and Node.js). */
export function readZipBytes(archive: Uint8Array, limits: PackageLimits = DEFAULT_PACKAGE_LIMITS): PackageFiles {
  if (archive.byteLength > limits.maxArchiveBytes) {
    throw new AdminSecOpsError('PACKAGE_TOO_LARGE', `The evidence package exceeds the ${limits.maxArchiveBytes} byte limit.`, { statusCode: 413 });
  }
  if (archive.byteLength < 22) throw new AdminSecOpsError('PACKAGE_NOT_ZIP', 'The uploaded file is not a valid ZIP archive.');
  const r = new Reader(archive);
  const eocd = findEndOfCentralDirectory(r);

  const diskNumber = r.u16(eocd + 4);
  const centralDisk = r.u16(eocd + 6);
  const entriesOnDisk = r.u16(eocd + 8);
  const totalEntries = r.u16(eocd + 10);
  const centralSize = r.u32(eocd + 12);
  const centralOffset = r.u32(eocd + 16);
  if (diskNumber !== 0 || centralDisk !== 0 || entriesOnDisk !== totalEntries) throw corrupt('multi-disk archive');
  if (totalEntries === 0xffff || centralOffset === 0xffffffff || centralSize === 0xffffffff) throw corrupt('ZIP64 archive');
  if (eocd >= 20 && r.u32(eocd - 20) === SIG_ZIP64_LOCATOR) throw corrupt('ZIP64 archive');
  if (totalEntries > limits.maxEntries) {
    throw new AdminSecOpsError('PACKAGE_TOO_MANY_ENTRIES', `The evidence package has more than ${limits.maxEntries} entries.`);
  }
  if (centralOffset + centralSize > eocd) throw corrupt('central directory out of bounds');

  const files: PackageFiles = new Map();
  const utf8 = new TextDecoder('utf-8', { fatal: false });
  let totalBytes = 0;
  let cursor = centralOffset;

  for (let index = 0; index < totalEntries; index++) {
    if (r.u32(cursor) !== SIG_CENTRAL) throw corrupt('bad central directory signature');
    const flags = r.u16(cursor + 8);
    const method = r.u16(cursor + 10);
    const expectedCrc = r.u32(cursor + 16);
    const compressedSize = r.u32(cursor + 20);
    const uncompressedSize = r.u32(cursor + 24);
    const nameLength = r.u16(cursor + 28);
    const extraLength = r.u16(cursor + 30);
    const commentLength = r.u16(cursor + 32);
    const externalAttributes = r.u32(cursor + 38);
    const localOffset = r.u32(cursor + 42);
    const rawName = r.slice(cursor + 46, cursor + 46 + nameLength);
    cursor += 46 + nameLength + extraLength + commentLength;
    if (cursor > centralOffset + centralSize) throw corrupt('central directory entry out of bounds');

    // Non-UTF-8 names are decoded leniently; normalizePackagePath accepts only safe ASCII.
    const name = (flags & FLAG_UTF8) !== 0 ? utf8.decode(rawName) : Array.from(rawName, (b) => String.fromCharCode(b)).join('');
    const normalized = normalizePackagePath(name);
    if (normalized === undefined) continue;

    if ((flags & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION)) !== 0) {
      throw new AdminSecOpsError('PACKAGE_ENCRYPTED_ENTRY', 'Encrypted ZIP entries are not supported.');
    }
    if (((externalAttributes >>> 16) & S_IFMT) === S_IFLNK) {
      throw new AdminSecOpsError('PACKAGE_SYMLINK', 'Symbolic links are not permitted in evidence packages.');
    }
    if (files.has(normalized)) {
      throw new AdminSecOpsError('PACKAGE_DUPLICATE_ENTRY', 'The evidence package contains duplicate file names.');
    }
    if (uncompressedSize > limits.maxFileBytes) {
      throw new AdminSecOpsError('PACKAGE_FILE_TOO_LARGE', `A file in the evidence package exceeds the ${limits.maxFileBytes} byte limit.`);
    }
    if (uncompressedSize > ONE_MIB && uncompressedSize / Math.max(compressedSize, 1) > limits.maxCompressionRatio) {
      throw new AdminSecOpsError('PACKAGE_COMPRESSION_RATIO', 'The evidence package has a suspicious compression ratio.');
    }
    if (totalBytes + uncompressedSize > limits.maxTotalBytes) {
      throw new AdminSecOpsError('PACKAGE_TOO_LARGE', `The evidence package exceeds the ${limits.maxTotalBytes} byte uncompressed limit.`, { statusCode: 413 });
    }

    if (r.u32(localOffset) !== SIG_LOCAL) throw corrupt('bad local header signature');
    const dataStart = localOffset + 30 + r.u16(localOffset + 26) + r.u16(localOffset + 28);
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > centralOffset) throw corrupt('entry data overlaps the central directory');
    const data = r.slice(dataStart, dataEnd);

    const remaining = Math.min(limits.maxFileBytes, limits.maxTotalBytes - totalBytes);
    let content: Uint8Array;
    if (method === METHOD_STORED) {
      if (compressedSize !== uncompressedSize) throw corrupt('stored entry size mismatch');
      if (compressedSize > remaining) throw new AdminSecOpsError('PACKAGE_FILE_TOO_LARGE', 'A file in the evidence package exceeds the size limit.');
      content = data.slice();
    } else if (method === METHOD_DEFLATE) {
      content = inflateBounded(data, remaining);
    } else {
      throw corrupt(`unsupported compression method ${method}`);
    }
    if (content.byteLength !== uncompressedSize) throw corrupt('declared size does not match data');
    if (crc32(content) !== expectedCrc) throw corrupt('CRC-32 mismatch');

    totalBytes += content.byteLength;
    files.set(normalized, content);
  }
  return files;
}
