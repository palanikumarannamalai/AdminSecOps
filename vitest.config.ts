import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const pkg = (name: string) => fileURLToPath(new URL(`./packages/${name}/src/index.ts`, import.meta.url));

/** Resolve workspace packages to their TypeScript sources so tests never need a build. */
export const workspaceAliases = {
  '@adminsecops/core': pkg('core'),
  '@adminsecops/schemas': pkg('schemas'),
  '@adminsecops/evidence': pkg('evidence'),
  '@adminsecops/inventory': pkg('inventory'),
  '@adminsecops/controls': pkg('controls'),
  '@adminsecops/engine': pkg('engine'),
  '@adminsecops/reporting': pkg('reporting'),
};

export default defineConfig({
  resolve: { alias: workspaceAliases },
  test: {
    projects: [
      {
        resolve: { alias: workspaceAliases },
        test: {
          name: 'node',
          environment: 'node',
          include: ['packages/**/*.test.ts', 'apps/api/**/*.test.ts', 'apps/cli/**/*.test.ts', 'tests/**/*.test.ts'],
          exclude: ['**/node_modules/**', '**/dist/**'],
          testTimeout: 30000,
        },
      },
    ],
  },
});
