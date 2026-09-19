// Minimal static web server that mimics the Azure Static Web Apps behaviour relevant to the hosted
// application: directory index.html, globalHeaders and ordered route rules (headers and rewrite) from a
// staticwebapp.config.json, and a 404 page. Used only by the browser tests.
//
//   node static-server.ts <siteRoot> <staticwebapp.config.json> <port>
import { createServer } from 'node:http';
import { readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const [rootArg, configPath, portArg] = process.argv.slice(2);
if (!rootArg || !configPath) {
  console.error('usage: node static-server.ts <siteRoot> <staticwebapp.config.json> [port]');
  process.exit(2);
}
const root = path.resolve(rootArg);
const port = Number(portArg ?? 4380);
interface Route {
  route: string;
  headers?: Record<string, string>;
  rewrite?: string;
}
const config = JSON.parse(readFileSync(configPath, 'utf8')) as {
  globalHeaders?: Record<string, string>;
  routes?: Route[];
};
const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json',
  '.jpg': 'image/jpeg',
  '.png': 'image/png',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml',
  '.zip': 'application/zip',
};

function routeMatches(pattern: string, urlPath: string): boolean {
  if (pattern.endsWith('/*')) return urlPath.startsWith(pattern.slice(0, -1));
  return urlPath === pattern;
}

function resolveFile(urlPath: string): string | undefined {
  const decoded = decodeURIComponent(urlPath);
  const full = path.join(root, decoded);
  if (full !== root && !full.startsWith(root + path.sep)) return undefined;
  for (const candidate of [full, path.join(full, 'index.html'), `${full}.html`]) {
    try {
      if (statSync(candidate).isFile()) return candidate;
    } catch {
      /* try next */
    }
  }
  return undefined;
}

createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://127.0.0.1:${port}`);
  const headers: Record<string, string> = { ...(config.globalHeaders ?? {}) };
  const route = (config.routes ?? []).find((r) => routeMatches(r.route, url.pathname));
  if (route?.headers) Object.assign(headers, route.headers);
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, headers).end();
    return;
  }
  if (route?.rewrite !== undefined) {
    const target = resolveFile(route.rewrite);
    if (target !== undefined) {
      res.writeHead(200, { ...headers, 'Content-Type': TYPES[path.extname(target)] ?? 'application/octet-stream' });
      res.end(req.method === 'HEAD' ? undefined : readFileSync(target));
      return;
    }
  }
  // Static Web Apps redirects folder paths without a trailing slash.
  const file = resolveFile(url.pathname);
  if (
    file !== undefined &&
    !url.pathname.endsWith('/') &&
    file.endsWith(`${path.sep}index.html`) &&
    !url.pathname.endsWith('index.html')
  ) {
    res.writeHead(301, { ...headers, Location: `${url.pathname}/${url.search}` }).end();
    return;
  }
  if (file === undefined) {
    const notFound = resolveFile('/404.html');
    res.writeHead(404, { ...headers, 'Content-Type': 'text/html; charset=utf-8' });
    res.end(notFound ? readFileSync(notFound) : 'Not found');
    return;
  }
  res.writeHead(200, {
    ...headers,
    'Content-Type': TYPES[path.extname(file)] ?? 'application/octet-stream',
  });
  res.end(req.method === 'HEAD' ? undefined : readFileSync(file));
}).listen(port, '127.0.0.1', () =>
  console.log(`static server on http://127.0.0.1:${port} serving ${root}`),
);
