import yazl from 'yazl';

export interface ZipEntryInput {
  name: string;
  data: Uint8Array | string;
  /** Unix mode, e.g. 0o120777 for a symbolic link. */
  mode?: number;
  compress?: boolean;
}

/** Create a ZIP archive in memory (test helper). */
export function makeZip(entries: readonly ZipEntryInput[]): Promise<Buffer> {
  const zip = new yazl.ZipFile();
  for (const entry of entries) {
    const data = typeof entry.data === 'string' ? Buffer.from(entry.data, 'utf8') : Buffer.from(entry.data);
    zip.addBuffer(data, entry.name, {
      ...(entry.mode !== undefined ? { mode: entry.mode } : {}),
      compress: entry.compress ?? true,
    });
  }
  zip.end();
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    zip.outputStream.on('data', (chunk: Buffer) => chunks.push(chunk));
    zip.outputStream.on('end', () => resolve(Buffer.concat(chunks)));
    zip.outputStream.on('error', reject);
  });
}

/**
 * Replace every occurrence of a file name in a ZIP buffer with another name of the
 * same length. Used to craft hostile archives (traversal, absolute paths) that
 * well-behaved ZIP writers refuse to create.
 */
export function patchName(zip: Buffer, from: string, to: string): Buffer {
  if (from.length !== to.length) throw new Error('Names must have equal length');
  const out = Buffer.from(zip);
  const needle = Buffer.from(from, 'utf8');
  let index = out.indexOf(needle);
  while (index !== -1) {
    out.write(to, index, 'utf8');
    index = out.indexOf(needle, index + needle.length);
  }
  return out;
}
