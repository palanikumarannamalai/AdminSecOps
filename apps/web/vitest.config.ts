import react from '@vitejs/plugin-react';
import { defineProject } from 'vitest/config';
import { webAliases } from './vite.config.ts';

export default defineProject({
  plugins: [react()],
  resolve: { alias: webAliases },
  test: {
    name: 'web',
    root: import.meta.dirname,
    environment: 'jsdom',
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
    exclude: ['**/node_modules/**', '**/dist/**'],
    setupFiles: ['./src/test/setup.ts'],
  },
});
