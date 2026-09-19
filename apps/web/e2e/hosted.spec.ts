import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page, type Request } from '@playwright/test';
import yazl from 'yazl';

const APP = '/tools/adminsecops/app/';
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const IMPORT_WARNING =
  'Evidence is processed locally in your browser. Do not use a shared or untrusted computer. Assessment evidence can contain account identifiers, security settings and weaknesses.';

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

function zip(entries: Array<{ name: string; data: Buffer; mode?: number }>): Promise<Buffer> {
  const z = new yazl.ZipFile();
  for (const e of entries)
    z.addBuffer(e.data, e.name, e.mode !== undefined ? { mode: e.mode } : {});
  z.end();
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    z.outputStream
      .on('data', (c: Buffer) => chunks.push(c))
      .on('end', () => resolve(Buffer.concat(chunks)))
      .on('error', reject);
  });
}

function fixtureEntries(name: string): Array<{ name: string; data: Buffer }> {
  const base = path.join(repo, 'fixtures', 'assessments', name);
  const out: Array<{ name: string; data: Buffer }> = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir)) {
      const full = path.join(dir, e);
      if (statSync(full).isDirectory()) walk(full);
      else
        out.push({
          name: path.relative(base, full).split(path.sep).join('/'),
          data: readFileSync(full),
        });
    }
  };
  walk(base);
  return out;
}

interface Traffic {
  requests: Request[];
  problems: string[];
}

/**
 * Records every request and console/page error. Evidence must never leave the browser: every
 * request must be a same-origin GET for the application's own static files, without a body.
 */
function watch(page: Page): Traffic {
  const traffic: Traffic = { requests: [], problems: [] };
  page.on('request', (r) => traffic.requests.push(r));
  page.on('pageerror', (e) => traffic.problems.push(`page error: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error' || /Content Security Policy|Refused to/i.test(m.text()))
      traffic.problems.push(`console: ${m.text()}`);
  });
  return traffic;
}

function assertNoEgress(traffic: Traffic, baseURL: string): void {
  const origin = new URL(baseURL).origin;
  for (const r of traffic.requests) {
    const url = new URL(r.url());
    if (url.protocol === 'blob:' || url.protocol === 'data:') continue;
    expect(url.origin, `request to ${r.url()}`).toBe(origin);
    expect(['GET', 'HEAD'], `${r.method()} ${r.url()}`).toContain(r.method());
    expect(r.postData(), `request body sent to ${r.url()}`).toBeNull();
    expect(
      url.pathname === '/favicon.svg' || url.pathname.startsWith('/tools/adminsecops'),
      url.pathname,
    ).toBe(true);
  }
  expect(traffic.problems).toEqual([]);
}

async function start(page: Page): Promise<void> {
  await page.goto(APP);
  await expect(
    page.getByRole('heading', { name: 'Microsoft security assessment in your browser' }),
  ).toBeVisible();
}

async function loadSample(page: Page, name: 'Contoso' | 'Fabrikam'): Promise<void> {
  await page.getByRole('button', { name: `Load ${name} sample` }).click();
  await expect(page).toHaveURL(/#\/assessments\/[0-9a-f-]{36}$/);
  await expect(page.getByRole('note').filter({ hasText: 'Fictional sample data' })).toBeVisible();
}

async function importFile(
  page: Page,
  file: { name: string; buffer: Buffer } | string,
): Promise<void> {
  const input = page.locator('#import input[type="file"]');
  await input.setInputFiles(
    typeof file === 'string'
      ? file
      : { name: file.name, mimeType: 'application/zip', buffer: file.buffer },
  );
}

async function axe(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  const summary = results.violations.map(
    (v) => `${v.id}: ${v.nodes.length} node(s) - ${v.nodes[0]?.target.join(' ')}`,
  );
  expect(summary).toEqual([]);
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

test.describe('hosted AdminSecOps application', () => {
  test('first screen offers samples, import and guidance, with the import warning and metadata', async ({
    page,
    baseURL,
  }) => {
    const traffic = watch(page);
    await start(page);
    await expect(page).toHaveTitle('AdminSecOps Browser Assessment | Palanikumar Annamalai');
    await expect(page.locator('meta[name="robots"]')).toHaveAttribute('content', 'noindex');
    await expect(page.locator('link[rel="canonical"]')).toHaveAttribute(
      'href',
      'https://www.palanikumar.net/tools/adminsecops/app',
    );
    for (const name of [
      'Explore Contoso sample',
      'Explore Fabrikam sample',
      'Import an evidence package',
      'Read privacy and safety guidance',
    ]) {
      await expect(
        page.locator('.start').getByRole('heading', { name, exact: true }),
      ).toBeVisible();
    }
    await expect(page.getByText(IMPORT_WARNING).first()).toBeVisible();
    await expect(
      page.getByRole('link', { name: 'Return to AdminSecOps overview' }),
    ).toHaveAttribute('href', '/tools/adminsecops');
    await expect(page.getByRole('button', { name: 'Delete local data' })).toBeVisible();
    assertNoEgress(traffic, baseURL!);
  });

  test('serves a strict Content-Security-Policy that blocks network connections', async ({
    page,
  }) => {
    const response = await page.goto(APP);
    const csp = response?.headers()['content-security-policy'] ?? '';
    expect(csp).toContain("connect-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain('unsafe-inline');
    expect(response?.headers()['x-robots-tag']).toBe('noindex');
    const blocked = await page.evaluate(async () => {
      try {
        await fetch('/tools/adminsecops/', { method: 'POST', body: 'evidence' });
        return false;
      } catch {
        return true;
      }
    });
    expect(blocked).toBe(true);
  });

  test('Contoso sample: overview, findings, finding detail and reports', async ({
    page,
    baseURL,
  }) => {
    const traffic = watch(page);
    await start(page);
    await loadSample(page, 'Contoso');
    await expect(page.getByRole('heading', { name: /What should I fix first\?/ })).toBeVisible();
    await page
      .getByRole('navigation', { name: 'Main' })
      .getByRole('link', { name: 'Findings' })
      .click();
    const firstFinding = page.getByRole('table').getByRole('link').first();
    await expect(firstFinding).toBeVisible();
    await firstFinding.click();
    for (const heading of [
      'WHAT DID YOU FIND?',
      'HOW DO I FIX IT?',
      'HOW DO I ROLL IT BACK?',
      'HOW DO I VERIFY THE FIX?',
    ]) {
      await expect(page.getByRole('heading', { name: heading, exact: false })).toBeVisible();
    }

    const [json] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('link', { name: 'Export JSON report' }).click(),
    ]);
    expect(json.suggestedFilename()).toMatch(/^adminsecops-report-.*\.json$/);
    const report = JSON.parse(readFileSync(await json.path(), 'utf8')) as {
      reportType: string;
      assessment: { findings: unknown[] };
    };
    expect(report.reportType).toBe('adminsecops.assessment');
    expect(report.assessment.findings.length).toBeGreaterThan(10);

    const [htmlReport] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('link', { name: 'Export HTML report' }).click(),
    ]);
    expect(htmlReport.suggestedFilename()).toMatch(/\.html$/);
    const html = readFileSync(await htmlReport.path(), 'utf8');
    expect(html).toContain('What should I fix first?');
    expect(html).not.toMatch(/<script/i);
    assertNoEgress(traffic, baseURL!);
  });

  test('Fabrikam sample: on-premises modules assessed, cloud modules not collected', async ({
    page,
    baseURL,
  }) => {
    const traffic = watch(page);
    await start(page);
    await loadSample(page, 'Fabrikam');
    await expect(page.getByText(/not collected/i).first()).toBeVisible();
    await page
      .getByRole('navigation', { name: 'Main' })
      .getByRole('link', { name: 'Evidence' })
      .click();
    await expect(page.getByText(/integrity/i).first()).toBeVisible();
    assertNoEgress(traffic, baseURL!);
  });

  test('imports a valid evidence package in the browser without any network request', async ({
    page,
    baseURL,
  }) => {
    const traffic = watch(page);
    await start(page);
    const before = traffic.requests.length;
    await importFile(page, {
      name: 'contoso-evidence.zip',
      buffer: await zip(fixtureEntries('contoso')),
    });
    await expect(page).toHaveURL(/#\/assessments\/[0-9a-f-]{36}$/);
    await expect(page.getByRole('heading', { name: /What should I fix first\?/ })).toBeVisible();
    // Importing and assessing evidence must not trigger a single request.
    expect(traffic.requests.slice(before).map((r) => r.url())).toEqual([]);
    // Imported evidence is not labelled as sample data.
    await expect(page.getByRole('note').filter({ hasText: 'Fictional sample data' })).toHaveCount(
      0,
    );
    assertNoEgress(traffic, baseURL!);
  });

  test('rejects malformed, hostile and oversized packages with clear messages', async ({
    page,
    baseURL,
  }) => {
    const traffic = watch(page);
    await start(page);
    const status = page.locator('#import [role="status"]');

    await importFile(page, {
      name: 'broken.zip',
      buffer: Buffer.from('this is not a zip archive at all'),
    });
    await expect(status).toContainText('not a valid ZIP archive');

    await importFile(page, {
      name: 'bomb.zip',
      buffer: await zip([{ name: 'bomb.json', data: Buffer.alloc(8 * 1024 * 1024, 0x20) }]),
    });
    await expect(status).toContainText('suspicious compression ratio');

    const traversal = await zip([{ name: 'aa/evil.json', data: Buffer.from('{}') }]);
    const patched = Buffer.from(
      traversal.toString('latin1').split('aa/evil.json').join('../evil.json'),
      'latin1',
    );
    await importFile(page, { name: 'traversal.zip', buffer: patched });
    await expect(status).toContainText('unsafe file path');

    await importFile(page, {
      name: 'no-manifest.zip',
      buffer: await zip([{ name: 'evidence/x.json', data: Buffer.from('{}') }]),
    });
    await expect(status).toContainText('evidence-manifest.json');

    await importFile(page, { name: 'notes.txt', buffer: Buffer.from('hello') });
    await expect(page.locator('#import').getByText(/\.zip/).last()).toBeVisible();

    const dir = mkdtempSync(path.join(tmpdir(), 'aso-e2e-'));
    try {
      const big = path.join(dir, 'oversized.zip');
      writeFileSync(big, Buffer.alloc(100 * 1024 * 1024 + 1));
      await importFile(page, big);
      await expect(status).toContainText(/too large|exceeds|100/i);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    await expect(page).toHaveURL(new RegExp(`${APP}#?/?$`));
    assertNoEgress(traffic, baseURL!);
  });

  test('rejects evidence whose integrity was tampered with after collection', async ({ page }) => {
    await start(page);
    const entries = fixtureEntries('fabrikam');
    const target = entries.find((e) => e.name.endsWith('.json') && e.name.startsWith('evidence/'))!;
    target.data = Buffer.from(target.data.toString('utf8').replace('"Success"', '"Partial"'));
    await importFile(page, { name: 'tampered.zip', buffer: await zip(entries) });
    await expect(page).toHaveURL(/#\/assessments\//);
    await page
      .getByRole('navigation', { name: 'Main' })
      .getByRole('link', { name: 'Evidence' })
      .click();
    await expect(
      page.getByText(/hash-mismatch|SHA-256 does not match|failed integrity/i).first(),
    ).toBeVisible();
  });

  test('direct refresh works and memory-only data is cleared on reload', async ({ page }) => {
    await page.goto(`${APP}#/about`);
    await expect(page.getByRole('heading', { name: 'Privacy and safety guidance' })).toBeVisible();
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Privacy and safety guidance' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'How to collect evidence' })).toBeVisible();

    await page.goto(APP);
    await loadSample(page, 'Fabrikam');
    await page.reload();
    await expect(page.getByText(/not held in this browser/)).toBeVisible();
  });

  test('the canonical URL without a trailing slash serves the application with its strict headers', async ({
    page,
  }) => {
    const response = await page.goto(APP.slice(0, -1));
    expect(response?.status()).toBe(200);
    expect(response?.headers()['content-security-policy']).toContain("connect-src 'none'");
    expect(response?.headers()['x-robots-tag']).toBe('noindex');
    await expect(page.getByRole('heading', { name: 'Microsoft security assessment in your browser' })).toBeVisible();
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Microsoft security assessment in your browser' })).toBeVisible();
  });

  test('explicit on-device persistence survives reload and Delete local data removes it', async ({
    page,
  }) => {
    await start(page);
    await page.getByLabel('Keep assessments on this device').check();
    await loadSample(page, 'Fabrikam');
    await page.reload();
    await expect(page.getByRole('note').filter({ hasText: 'Fictional sample data' })).toBeVisible();

    await page.goto(APP);
    await page.getByRole('button', { name: 'Delete local data' }).click();
    await page.getByRole('button', { name: 'Confirm: delete local data' }).click();
    await expect(page.getByText('All assessments were cleared from this browser')).toBeVisible();
    expect(
      await page.evaluate(() => localStorage.getItem('adminsecops.keepAssessments')),
    ).toBeNull();
    const databases = await page.evaluate(async () =>
      (await indexedDB.databases()).map((d) => d.name),
    );
    expect(databases).not.toContain('adminsecops-hosted');
    await page.reload();
    await expect(
      page.getByText('Load a sample or import an evidence package to create an assessment.'),
    ).toBeVisible();
  });

  test('clear assessment removes it from the browser', async ({ page }) => {
    await start(page);
    await loadSample(page, 'Fabrikam');
    await page.getByRole('button', { name: 'Clear assessment' }).click();
    await page.getByRole('button', { name: 'Confirm clear assessment' }).click();
    await expect(
      page.getByRole('heading', { name: 'Microsoft security assessment in your browser' }),
    ).toBeVisible();
    await expect(
      page.getByText('Load a sample or import an evidence package to create an assessment.'),
    ).toBeVisible();
  });

  test('light and dark themes follow the system and the shared site preference', async ({
    page,
  }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await start(page);
    const bg = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    const dark = await bg();
    await page.emulateMedia({ colorScheme: 'light' });
    const light = await bg();
    expect(dark).not.toBe(light);

    await page.getByRole('button', { name: 'Switch to dark theme' }).click();
    expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
    expect(await page.evaluate(() => localStorage.getItem('theme'))).toBe('dark');
    expect(await bg()).toBe(dark);
    await page.reload();
    expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
  });

  for (const scheme of ['light', 'dark'] as const) {
    test(`meets WCAG 2.1 AA automated checks (${scheme} theme)`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme });
      await start(page);
      await axe(page);
      await loadSample(page, 'Contoso');
      await axe(page);
      await page
        .getByRole('navigation', { name: 'Main' })
        .getByRole('link', { name: 'Findings' })
        .click();
      await axe(page);
      await page.getByRole('table').getByRole('link').first().click();
      await axe(page);
      await page.goto(`${APP}#/about`);
      await axe(page);
    });
  }

  test('keyboard: skip link, focus order and activation', async ({ page, isMobile, browserName }) => {
    test.skip(isMobile, 'keyboard navigation is tested on desktop');
    // Safari's Tab key skips links unless "Press Tab to highlight each item" is enabled, and
    // Playwright's WebKit build cannot emulate Option+Tab; Chromium and Firefox cover this.
    test.skip(browserName === 'webkit', 'Safari Tab order depends on a user preference');
    await start(page);
    await page.keyboard.press('Tab');
    await expect(page.getByRole('link', { name: 'Skip to main content' })).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.locator('#main')).toBeFocused();
    await expect(page).toHaveURL(new RegExp(`${APP}$`));
    let reached = false;
    for (let i = 0; i < 40 && !reached; i++) {
      await page.keyboard.press('Tab');
      reached = await page
        .getByRole('button', { name: 'Load Contoso sample' })
        .evaluate((el) => el === document.activeElement);
    }
    expect(reached).toBe(true);
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/#\/assessments\//);
  });

  test('layout fits the viewport without horizontal scrolling', async ({ page }) => {
    await start(page);
    const overflow = () =>
      page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      );
    expect(await overflow()).toBeLessThanOrEqual(1);
    await loadSample(page, 'Contoso');
    expect(await overflow()).toBeLessThanOrEqual(1);
    for (const path of ['findings', 'controls', 'evidence', 'inventory', 'frameworks', 'reports']) {
      await page
        .getByRole('navigation', { name: 'Main' })
        .getByRole('link', { name: new RegExp(`^${path}$`, 'i') })
        .click();
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
      expect(await overflow(), path).toBeLessThanOrEqual(1);
    }
    // The start page with a listed assessment (its table has a visually hidden column label).
    await page
      .getByRole('navigation', { name: 'Main' })
      .getByRole('link', { name: 'Start' })
      .click();
    await expect(page.getByRole('heading', { name: 'Assessments in this browser' })).toBeVisible();
    expect(await overflow()).toBeLessThanOrEqual(1);
  });
});
