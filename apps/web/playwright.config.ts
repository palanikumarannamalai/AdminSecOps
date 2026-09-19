import { defineConfig, devices } from '@playwright/test';

/**
 * Browser tests for the hosted (browser-only) application.
 * - Default: builds a local test site from dist-hosted and serves it with the same route
 *   headers (including the strict CSP) used on www.palanikumar.net.
 * - E2E_BASE_URL=https://www.palanikumar.net runs the same tests against a deployed site.
 * Run `npm run build:hosted -w @adminsecops/web` first.
 */
const external = process.env.E2E_BASE_URL;
const baseURL = external ?? 'http://127.0.0.1:4380';

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  // Sample processing runs on the page's main thread; slower engines (WebKit) and production
  // over the network need more than the 5 s default.
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL,
    trace: 'off',
    acceptDownloads: true,
  },
  projects: [
    { name: 'desktop-chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 1366, height: 900 } } },
    { name: 'mobile-chromium', use: { ...devices['Pixel 7'] } },
    // Cross-engine runs: E2E_ALL_BROWSERS=1 (needs `npx playwright install firefox webkit`).
    ...(process.env.E2E_ALL_BROWSERS === '1'
      ? [
          { name: 'desktop-firefox', use: { ...devices['Desktop Firefox'], viewport: { width: 1366, height: 900 } } },
          { name: 'desktop-webkit', use: { ...devices['Desktop Safari'], viewport: { width: 1366, height: 900 } } },
          { name: 'mobile-webkit', use: { ...devices['iPhone 13'] } },
        ]
      : []),
  ],
  webServer: external
    ? undefined
    : {
        command:
          'node e2e/prepare-site.ts && node e2e/static-server.ts .e2e-site .e2e-site/staticwebapp.config.json 4380',
        url: 'http://127.0.0.1:4380/tools/adminsecops/app/',
        reuseExistingServer: false,
        timeout: 60_000,
      },
});
