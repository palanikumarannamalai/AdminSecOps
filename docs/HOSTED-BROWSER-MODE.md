# Hosted browser mode

AdminSecOps has two ways to run the same assessment engine:

| Mode | Where | Who | Evidence processing |
|---|---|---|---|
| **Local mode** | `npm start` / CLI on your machine; API bound to `127.0.0.1` | Administrators and developers | Node.js process on the machine that holds the evidence |
| **Hosted browser mode** | <https://www.palanikumar.net/tools/adminsecops/app> (static files) | Anyone with a browser | JavaScript in the visitor's browser tab |

Hosted mode is a static single-page application. It has **no server-side API**. The web
server only delivers HTML, JavaScript and CSS; it never receives evidence, reports, tenant
identifiers or configuration data.

It is a point-in-time configuration assessment, not a penetration test, a compliance
certification or a guarantee of security.

## Architecture

```
www.palanikumar.net (Azure Static Web Apps, static files only)
  /tools/adminsecops            Astro landing and documentation page (indexable)
  /tools/adminsecops/app/       hosted build of apps/web (noindex, strict CSP)
        index.html + assets/*.js/*.css
                 |
                 v  (download of static files only)
Visitor's browser tab
  apps/web (React)  --- ApiClient interface --->  browser-client.ts (no network)
                                                      |
        @adminsecops/evidence/browser: zip-reader (fflate), limits, integrity (SHA-256),
                                        secret-content scan, schema validation (Zod)
        @adminsecops/engine/browser:   inventory -> controls -> findings -> prioritisation
        @adminsecops/reporting:        JSON + HTML reports -> blob: downloads
        samples (Contoso, Fabrikam):   bundled fictional fixtures, lazily loaded chunks
```

- `apps/web` talks to an `ApiClient`. Local mode uses the HTTP client for the loopback
  API; hosted mode swaps in `src/api/browser-client.ts`, which implements the same
  interface in memory. Pages and components are shared.
- The build mode is chosen at build time (`vite build --mode hosted`), which sets
  `VITE_ADMINSECOPS_MODE=hosted`, the `/tools/adminsecops/app/` base path, the page
  metadata and hash routing. The local build does not contain the in-browser engine or the
  sample chunks.
- Hash routing (`/tools/adminsecops/app/#/assessments/<id>`) means every view is served by
  the same `index.html`, so a direct refresh always works, and assessment identifiers in
  the fragment are never sent to the web server.
- The `./browser` entry points of `@adminsecops/evidence` and `@adminsecops/engine` contain
  no Node.js imports. A unit test (`packages/evidence/src/zip-reader.test.ts`) walks their
  import graph and fails if `node:*`, `fs`, `yauzl` or similar modules appear.

### Browser-safe equivalents of Node-only code

| Local mode (Node.js) | Hosted mode (browser) | Parity |
|---|---|---|
| `yauzl` streaming ZIP reader | `zip-reader.ts` (central directory parser + `fflate` bounded inflate) | Same limits and rejections; parity test against yauzl on the fixtures |
| `node:crypto` SHA-256 | `@noble/hashes` SHA-256 (used by both modes now) | Identical digests |
| `Buffer` | `Uint8Array` / `TextEncoder` | Identical bytes |
| Results stored as JSON in the user profile | In-memory `Map`; optional IndexedDB (opt-in) | See data handling |
| Report download from the API | `Blob` + `URL.createObjectURL` | Same report generators |

No part of evidence processing was moved to a server. There was no browser-incompatible
dependency that required a limitation beyond those listed below.

## Browser data handling

- **Memory by default.** Imported packages are read with `File.arrayBuffer()` and
  processed in the tab. Results live in a JavaScript `Map` and are discarded when the tab
  is closed or refreshed.
- **Raw evidence is never stored.** Only processed assessment results are kept, and only
  when the visitor turns on persistence.
- **Optional persistence.** "Keep assessments on this device" (off by default) stores
  processed results in the browser's IndexedDB database `adminsecops-hosted` for this site
  and records the preference in `localStorage` (`adminsecops.keepAssessments`).
  "Delete local data" deletes the database and the preference and clears memory.
  "Clear assessment" removes one assessment from memory and from IndexedDB.
- **No network use.** The page's Content-Security-Policy sets `connect-src 'none'`
  (blocks `fetch`, XHR, WebSocket, EventSource and `sendBeacon`), `form-action 'none'`,
  `frame-src 'none'` and `worker-src 'none'`. The browser tests assert that importing a
  package produces no request at all and that a scripted `fetch` POST is blocked.
- **No analytics, telemetry, cookies or remote logging in this browser edition.** The only
  `localStorage` keys are `theme` (shared with the rest of palanikumar.net) and the persistence
  preference. The separate online service at app.adminsecops.com keeps anonymous aggregate
  usage counts on its server; see [PRIVACY.md](PRIVACY.md#online-service).
- **Reports** are generated in the tab and downloaded through `blob:` URLs, which are
  revoked when an assessment is cleared.
- **No credentials.** The hosted build contains no client IDs, secrets, tenant IDs,
  tokens or production data. The bundled samples are fictional (Contoso, Fabrikam) and
  labelled as sample data wherever they appear.

## Threat model (hosted browser mode)

See also [THREAT-MODEL.md](THREAT-MODEL.md).

| Threat | Mitigation |
|---|---|
| Evidence sent to palanikumar.net or a third party | No API; `connect-src 'none'`; no third-party scripts, fonts or images; tests assert no egress |
| Malicious ZIP (bomb, traversal, symlinks, encrypted, ZIP64, CRC tampering) | Same `DEFAULT_PACKAGE_LIMITS` and path rules as local mode; bounded inflate stops at the declared limit; CRC-32 and declared-size checks; rejected before any file is parsed |
| Tampered evidence | SHA-256 of every file verified against `evidence-manifest.json`; mismatches reported as failed integrity, never as Pass |
| Secrets inside evidence | Same secret-content detection as local mode rejects the package |
| Script injection through evidence content | React text rendering only (`dangerouslySetInnerHTML` forbidden by lint); `script-src 'self'` without `unsafe-inline`; HTML report has a hash-pinned stylesheet and no scripts |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY` |
| Data left on a shared computer | Memory-only by default; explicit opt-in to persistence; visible "Delete local data"; warning next to import |
| Search engines indexing the app | `<meta name="robots" content="noindex">` and `X-Robots-Tag: noindex`; excluded from the sitemap |
| Supply chain of the static bundle | Built from the pinned lockfile; deployed through the existing GitHub Actions workflow; `npm audit` and the secret scan run before publishing |
| Compromise of the hosting account | Out of scope of the page; it would allow serving modified JavaScript. Run the local mode for sensitive work if this risk is unacceptable. |

## Supported evidence packages

| Item | Supported |
|---|---|
| Container | ZIP, stored or deflate entries, no encryption, no ZIP64, single disk |
| `evidence-manifest.json` `manifestVersion` | `1.0` |
| Evidence file `schemaVersion` | `1.0` |
| Producer | AdminSecOps Collector 0.1.x and the AdminSecOps sample fixtures |
| Size limits | 100 MB archive, 5,000 entries, 64 MB per file, 256 MB uncompressed total, 200:1 ratio for entries over 1 MiB |

Packages from other versions are rejected with a clear error, as in local mode.

## Browser compatibility

Requires a current evergreen browser with ES2022, `TextEncoder`, `File.arrayBuffer()`,
`Blob`/object URLs and (optionally) IndexedDB. JavaScript must be enabled.

Automated browser tests (`apps/web/e2e`) run on Chromium desktop and mobile (Pixel 7
emulation) by default, and on Firefox and WebKit (desktop Safari and iPhone emulation)
with `E2E_ALL_BROWSERS=1`. The keyboard-navigation test is skipped on WebKit because
Safari's Tab key reaches links only when "Press Tab to highlight each item" is enabled.
Internet Explorer and legacy Edge are not supported.

If IndexedDB is unavailable (some private windows), persistence is not offered and the
app keeps working in memory.

## Hosted-mode limitations

- **Main-thread processing.** Parsing and evaluation run on the page's main thread
  (`worker-src 'none'` keeps the policy minimal). Large packages may make the tab
  unresponsive for a few seconds.
- **Memory.** The archive, its inflated files and the results are held in memory at once.
  A package near the 256 MB uncompressed limit needs roughly 0.5-1 GB of browser memory;
  mobile browsers may fail on very large tenants. Use local mode for those.
- **No collection.** Browsers cannot run PowerShell or reach Active Directory, AD CS,
  Group Policy, Windows hosts or Microsoft cloud APIs from this page. Evidence must be
  collected separately with the read-only collector.
- **Single tab.** Memory-only assessments are not shared between tabs. Persisted
  assessments are shared between tabs of the same site after a reload.
- **Not encrypted at rest.** Opt-in IndexedDB data is protected only by the browser
  profile and operating system.
- **Integrity of the page itself** depends on the hosting account and TLS, as for any
  website.

## Local-mode development

Nothing about local mode changed for users:

```bash
npm ci
npm run dev:api          # API on 127.0.0.1:4310
npm run dev:web          # dashboard with /api proxy
npm run build && npm start
```

Hosted mode during development:

```bash
npm run dev -w @adminsecops/web -- --mode hosted     # hosted UI with the in-browser engine
npm run build:hosted -w @adminsecops/web             # -> apps/web/dist-hosted
cd apps/web && npx playwright test                    # browser tests (build first)
E2E_ALL_BROWSERS=1 npx playwright test                # plus Firefox and WebKit
```

The browser tests build a throw-away site tree (`apps/web/.e2e-site`) and serve it with a
small server that applies the same route headers (`apps/web/hosted-headers.json`) as
production, including the strict CSP.

## Production deployment

The hosted app is published by the palanikumar.net repository, which vendors this source
under `tools/adminsecops/`:

1. `node scripts/build-adminsecops-app.mjs` (in palanikumar.net) runs `npm ci` and
   `npm run build:hosted -w @adminsecops/web` inside `tools/adminsecops`, copies
   `apps/web/dist-hosted` to `public/tools/adminsecops/app/`, checks the output for
   forbidden content (source maps, environment files, tokens, live-tenant markers), and
   merges the route rules from `apps/web/hosted-headers.json` into
   `staticwebapp.config.json`.
2. The built files are committed. The existing Azure Static Web Apps workflow builds the
   Astro site, which copies `public/` into `dist/`, and deploys on push to `main`.
3. Verify production with
   `E2E_BASE_URL=https://www.palanikumar.net npx playwright test` from `apps/web`.

The build output is committed instead of built in CI so that the site workflow does not
depend on the AdminSecOps toolchain and the published bytes are reviewable in the commit.

## Updating the embedded AdminSecOps version

1. Merge and tag the change in the AdminSecOps repository; all checks green
   (`npm run verify`, Pester, PSScriptAnalyzer, browser tests).
2. In palanikumar.net, replace `tools/adminsecops/` with the tracked files of that commit
   (for example `git -C <AdminSecOps> archive <tag> | tar -x -C tools/adminsecops`,
   after emptying the folder but keeping `node_modules` out of Git).
3. Run `node scripts/build-adminsecops-app.mjs`, then `npm run verify` and
   `npm run audit:content`.
4. Review the diff of `public/tools/adminsecops/app/` and `staticwebapp.config.json`,
   commit, push to `main`, wait for the workflow, and run the production browser tests.
5. Roll back by reverting the commit; the workflow redeploys the previous build.
