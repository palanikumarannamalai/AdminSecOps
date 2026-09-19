import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { controlCatalogDoc, dataCollectionDoc } from '../scripts/generate-docs.js';

const docs = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'docs');

describe('generated documentation', () => {
  it('DATA-COLLECTION.md matches the dataset registry (run npm run docs:generate)', () => {
    expect(readFileSync(path.join(docs, 'DATA-COLLECTION.md'), 'utf8').replace(/\r\n/g, '\n')).toBe(dataCollectionDoc());
  });

  it('CONTROL-CATALOG.md matches the control library (run npm run docs:generate)', () => {
    expect(readFileSync(path.join(docs, 'CONTROL-CATALOG.md'), 'utf8').replace(/\r\n/g, '\n')).toBe(controlCatalogDoc());
  });
});
