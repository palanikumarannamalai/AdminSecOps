import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig, type AliasOptions } from 'vite';

const src = (path: string) => fileURLToPath(new URL(`../../packages/${path}`, import.meta.url));

/**
 * The browser bundle may only use types and small pure constants from these two
 * packages. Runtime constants are imported through the explicit sub-path aliases
 * (vocabulary/version) so node-only modules (hashing, logging) are never bundled.
 */
export const webAliases: AliasOptions = [
  { find: /^@adminsecops\/core\/vocabulary$/, replacement: src('core/src/vocabulary.ts') },
  { find: /^@adminsecops\/core\/version$/, replacement: src('core/src/version.ts') },
  { find: /^@adminsecops\/core$/, replacement: src('core/src/index.ts') },
  { find: /^@adminsecops\/schemas$/, replacement: src('schemas/src/index.ts') },
];

export default defineConfig({
  plugins: [react()],
  resolve: { alias: webAliases },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: 'http://127.0.0.1:4310', changeOrigin: false },
    },
  },
  preview: { host: '127.0.0.1', port: 4173 },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
  },
});
