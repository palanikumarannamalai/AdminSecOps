import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig, type AliasOptions, type Plugin } from 'vite';

const src = (path: string) => fileURLToPath(new URL(`../../packages/${path}`, import.meta.url));

/**
 * Workspace packages are resolved to their TypeScript sources. Only browser-safe entry points
 * are aliased: '@adminsecops/engine/browser' and '@adminsecops/evidence/browser' exclude the
 * Node.js file-system/ZIP reader (see packages/evidence/src/zip-reader.test.ts, which enforces
 * that the browser import graph contains no Node.js built-ins).
 */
export const webAliases: AliasOptions = [
  { find: /^@adminsecops\/core\/vocabulary$/, replacement: src('core/src/vocabulary.ts') },
  { find: /^@adminsecops\/core\/version$/, replacement: src('core/src/version.ts') },
  { find: /^@adminsecops\/core$/, replacement: src('core/src/index.ts') },
  { find: /^@adminsecops\/schemas$/, replacement: src('schemas/src/index.ts') },
  { find: /^@adminsecops\/inventory$/, replacement: src('inventory/src/index.ts') },
  { find: /^@adminsecops\/controls$/, replacement: src('controls/src/index.ts') },
  { find: /^@adminsecops\/reporting$/, replacement: src('reporting/src/index.ts') },
  { find: /^@adminsecops\/evidence\/browser$/, replacement: src('evidence/src/browser.ts') },
  { find: /^@adminsecops\/engine\/browser$/, replacement: src('engine/src/browser.ts') },
];

/** Public path of the hosted application on www.palanikumar.net. */
export const HOSTED_BASE = '/tools/adminsecops/app/';
export const HOSTED_CANONICAL = 'https://www.palanikumar.net/tools/adminsecops/app';

/** AdminSecOps shield as an inline icon: no extra request, allowed by img-src data:. */
const HOSTED_ICON =
  'data:image/svg+xml,' +
  encodeURIComponent(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="#1d4e89"/><path d="m8.5 12 2.5 2.5 4.5-5" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg>',
  );

const HOSTED_NOSCRIPT = [
  '<noscript>',
  '<h1>AdminSecOps Browser Assessment</h1>',
  '<p>This application needs JavaScript. Evidence is processed in your browser and is not uploaded to palanikumar.net.</p>',
  '<p><a href="/tools/adminsecops">Return to the AdminSecOps overview</a></p>',
  '</noscript>',
].join('');

/**
 * Hosted page metadata. The application shows visitor-specific assessment state, so it is
 * excluded from search indexing (noindex); the public landing page remains indexable.
 */
function hostedHtml(): Plugin {
  const meta = [
    '<meta name="description" content="Explore a free Microsoft security assessment in your browser using fictional samples or locally processed AdminSecOps evidence." />',
    '<meta name="robots" content="noindex" />',
    `<link rel="canonical" href="${HOSTED_CANONICAL}" />`,
    `<link rel="icon" href="${HOSTED_ICON}" type="image/svg+xml" />`,
  ].join('\n    ');
  return {
    name: 'adminsecops-hosted-html',
    transformIndexHtml(html) {
      return html
        .replace('<title>AdminSecOps</title>', `<title>AdminSecOps Browser Assessment | Palanikumar Annamalai</title>\n    ${meta}`)
        .replace('<html lang="en">', '<html lang="en-GB">')
        .replace(/<noscript>.*?<\/noscript>/s, HOSTED_NOSCRIPT);
    },
  };
}

export default defineConfig(({ mode }) => {
  const hosted = mode === 'hosted';
  const online = mode === 'online';
  return {
    plugins: hosted ? [react(), hostedHtml()] : [react()],
    resolve: { alias: webAliases },
    base: hosted ? HOSTED_BASE : '/',
    define: {
      'import.meta.env.VITE_ADMINSECOPS_MODE': JSON.stringify(online ? 'online' : hosted ? 'hosted' : 'local'),
    },
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      proxy: hosted ? undefined : { '/api': { target: 'http://127.0.0.1:4310', changeOrigin: false } },
    },
    preview: { host: '127.0.0.1', port: 4173 },
    build: {
      outDir: online ? 'dist-online' : hosted ? 'dist-hosted' : 'dist',
      emptyOutDir: true,
      // No source maps: they would expose local build paths and are not needed to run the app.
      sourcemap: false,
      target: 'es2022',
      chunkSizeWarningLimit: 1500,
    },
  };
});
