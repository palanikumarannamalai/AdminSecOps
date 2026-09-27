import { formatBytes } from './format';

/** Largest evidence package the local API accepts. */
export const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;

export type UploadValidation = { ok: true } | { ok: false; message: string };

/** Client-side checks before a package is sent; the API validates again. */
export function validatePackageFile(file: { name: string; size: number } | null | undefined): UploadValidation {
  if (file === null || file === undefined) return { ok: false, message: 'Select an evidence package (.zip) to upload.' };
  if (!file.name.toLowerCase().endsWith('.zip')) {
    return {
      ok: false,
      message: `"${file.name}" is not a .zip file. Upload the evidence package ZIP produced by the ConfigReview Collector.`,
    };
  }
  if (file.size === 0) return { ok: false, message: `"${file.name}" is empty.` };
  if (file.size > MAX_UPLOAD_BYTES) {
    return {
      ok: false,
      message: `"${file.name}" is ${formatBytes(file.size)}. The maximum package size is ${formatBytes(MAX_UPLOAD_BYTES)}.`,
    };
  }
  return { ok: true };
}
