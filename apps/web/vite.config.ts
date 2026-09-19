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

/**
 * Hosted page metadata. The application shows visitor-specific assessment state, so it is
 * excluded from search indexing (noindex); the public landing page remains indexable.
 */
function hostedHtml(): Plugin {
  const meta = [
    '<meta name="description" content="Explore a free Microsoft security assessment in your browser using fictional samples or locally processed AdminSecOps evidence." />',
    '<meta name="robots" content="noindex" />',
    `<link rel="canonical" href="${HOSTED_CANONICAL}" />`,
    '<link rel="icon" href="/favicon.svg" type="image/svg+xml" />',
  ].join('\n    ');
  return {
    name: 'adminsecops-hosted-html',
    transformIndexHtml(html) {
      return html
        .replace('<title>AdminSecOps</title>', `<title>AdminSecOps Browser Assessment | Palanikumar Annamalai</title>\n    ${meta}`)
        .replace('<html lang="en">', '<html lang="en-GB">');
    },
  };
}

export default defineConfig(({ mode }) => {
  const hosted = mode === 'hosted';
  return {
    plugins: hosted ? [react(), hostedHtml()] : [react()],
    resolve: { alias: webAliases },
    base: hosted ? HOSTED_BASE : '/',
    define: {
      'import.meta.env.VITE_ADMINSECOPS_MODE': JSON.stringify(hosted ? 'hosted' : 'local'),
    },
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: true,
      proxy: hosted ? undefined : { '/api': { target: 'http://127.0.0.1:4310', changeOrigin: false } },
    },
    preview: { host: '127.0.0.1', port: 4173 },
    build: {
      outDir: hosted ? 'dist-hosted' : 'dist',
      emptyOutDir: true,
      // No source maps: they would expose local build paths and are not needed to run the app.
      sourcemap: false,
      target: 'es2022',
      chunkSizeWarningLimit: 1500,
    },
  };
});
