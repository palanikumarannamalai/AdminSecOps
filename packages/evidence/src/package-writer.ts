import { sha256Hex } from '@adminsecops/core';
import { MANIFEST_FILE_NAME, type EvidenceEnvelope, type EvidenceManifest, type ManifestFile } from '@adminsecops/schemas';
import type { PackageFiles } from './paths.js';

const utf8Bytes = (text: string): Uint8Array => new TextEncoder().encode(text);

export interface EvidenceFileInput {
  path: string;
  envelope: EvidenceEnvelope;
}

/**
 * Build an in-memory evidence package (manifest + evidence files) in the same format
 * the PowerShell collector produces. Used for sanitized fixtures and tests; it computes
 * the SHA-256 and size entries of the manifest from the serialised files.
 */
export function buildEvidencePackage(
  manifestBase: Omit<EvidenceManifest, 'files'>,
  inputs: readonly EvidenceFileInput[],
): { files: PackageFiles; manifest: EvidenceManifest } {
  const files: PackageFiles = new Map();
  const entries: ManifestFile[] = [];
  for (const input of inputs) {
    const bytes = utf8Bytes(`${JSON.stringify(input.envelope, null, 2)}\n`);
    files.set(input.path, bytes);
    entries.push({
      path: input.path,
      datasetId: input.envelope.datasetId,
      module: input.envelope.collector.module,
      sha256: sha256Hex(bytes),
      sizeBytes: bytes.byteLength,
      schemaVersion: input.envelope.schemaVersion,
      status: input.envelope.status,
      collectedAt: input.envelope.collectedAt,
    });
  }
  const manifest: EvidenceManifest = { ...manifestBase, files: entries };
  files.set(MANIFEST_FILE_NAME, utf8Bytes(`${JSON.stringify(manifest, null, 2)}\n`));
  return { files, manifest };
}
