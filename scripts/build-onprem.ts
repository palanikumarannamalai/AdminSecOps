import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import yazl from 'yazl';
const root = process.cwd();
const out = path.join(root, 'apps/web/public/downloads');
fs.mkdirSync(out, { recursive: true });
const zip = new yazl.ZipFile();
function add(dir: string, prefix: string) {
  for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
    if (item.name === 'tests') continue;
    const full = path.join(dir, item.name);
    if (item.isDirectory()) add(full, `${prefix}${item.name}/`);
    else if (/\.(ps1|psm1|psd1|md|txt)$/.test(item.name))
      zip.addFile(full, `${prefix}${item.name}`);
  }
}
add(path.join(root, 'collectors/powershell'), 'powershell/');
add(path.join(root, 'collectors/onprem'), '');
const target = path.join(out, 'configreview-onprem.zip');
const stream = fs.createWriteStream(target);
zip.outputStream.pipe(stream);
zip.end();
await new Promise<void>((resolve, reject) => {
  stream.on('close', resolve);
  stream.on('error', reject);
  zip.outputStream.on('error', reject);
});
fs.copyFileSync(
  path.join(root, 'collectors/onprem/README.txt'),
  path.join(out, 'configreview-onprem-guide.txt'),
);
fs.writeFileSync(
  path.join(out, 'configreview-onprem.sha256'),
  createHash('sha256').update(fs.readFileSync(target)).digest('hex') +
    '  configreview-onprem.zip\n',
);
console.log('Collector archive, guide and SHA-256 generated.');
