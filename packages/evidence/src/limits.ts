/**
 * Resource limits applied when reading an evidence package. They protect the local
 * application (and a future hosted service) from zip bombs and oversized input.
 * Values are deliberately generous for real tenants but bounded.
 */
export interface PackageLimits {
  /** Maximum size of the compressed ZIP file. */
  maxArchiveBytes: number;
  /** Maximum number of entries (files and directories) in the archive. */
  maxEntries: number;
  /** Maximum uncompressed size of a single file. */
  maxFileBytes: number;
  /** Maximum total uncompressed size of all files. */
  maxTotalBytes: number;
  /** Maximum compression ratio for any entry larger than 1 MiB (zip bomb heuristic). */
  maxCompressionRatio: number;
}

export const DEFAULT_PACKAGE_LIMITS: PackageLimits = {
  maxArchiveBytes: 100 * 1024 * 1024,
  maxEntries: 5000,
  maxFileBytes: 64 * 1024 * 1024,
  maxTotalBytes: 256 * 1024 * 1024,
  maxCompressionRatio: 200,
};
