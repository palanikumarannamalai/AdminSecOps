// Builds a throw-away site tree for browser tests of the hosted application:
//   .e2e-site/tools/configreview/app/   <- dist-hosted
//   .e2e-site/tools/configreview/       <- stub overview page (the real one lives in palanikumar.net)
//   .e2e-site/staticwebapp.config.json <- route headers from hosted-headers.json
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const site = path.join(web, '.e2e-site');
const dist = path.join(web, 'dist-hosted');

rmSync(site, { recursive: true, force: true });
mkdirSync(path.join(site, 'tools', 'adminsecops'), { recursive: true });
cpSync(dist, path.join(site, 'tools', 'adminsecops', 'app'), { recursive: true });
writeFileSync(
  path.join(site, 'tools', 'adminsecops', 'index.html'),
  '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ConfigReview overview (test stub)</title></head><body><h1>ConfigReview overview</h1></body></html>',
);
writeFileSync(
  path.join(site, 'favicon.svg'),
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>',
);
writeFileSync(
  path.join(site, '404.html'),
  '<!doctype html><title>Not found</title><h1>Not found</h1>',
);

const hosted = JSON.parse(readFileSync(path.join(web, 'hosted-headers.json'), 'utf8')) as {
  csp: string;
  routes: Array<{ route: string; rewrite?: string; headers: Record<string, string> }>;
};
// The test server speaks plain HTTP on 127.0.0.1; WebKit would upgrade its asset requests to
// HTTPS. Production (HTTPS) keeps upgrade-insecure-requests.
const testCsp = hosted.csp.replace(/;\s*upgrade-insecure-requests/, '');
const routes = hosted.routes.map((r) => ({
  route: r.route,
  ...(r.rewrite !== undefined ? { rewrite: r.rewrite } : {}),
  headers: Object.fromEntries(
    Object.entries(r.headers).map(([k, v]) => [k, v === '@csp' ? testCsp : v]),
  ),
}));
writeFileSync(
  path.join(site, 'staticwebapp.config.json'),
  JSON.stringify(
    {
      globalHeaders: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Content-Security-Policy': "default-src 'self'",
      },
      routes,
    },
    null,
    2,
  ),
);
console.log(`prepared ${site}`);
