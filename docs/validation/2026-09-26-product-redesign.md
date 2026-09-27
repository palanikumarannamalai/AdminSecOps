# Product redesign — 2026-09-26

Figma source: https://www.figma.com/design/GM4PRHCrFcknELUjACFfp0

Design frames: desktop landing 2:129, assessment workspace 2:130, finding detail 2:131, mobile landing 2:132. Figma compositions use auto-layout and the Simple Design System button component. The existing application button styles supply the implementation (no matching Code Connect package exists in this repository). Screens use fictional example data only.

Implemented a public signed-out landing page on the app origin, responsive navigation, product introduction, example assessment preview, workload coverage, workflow, trust information and customer tenant entry. All sign-in links remain on the existing Microsoft authentication routes. The landing page explicitly labels illustrative data, test-release status and coverage limitations.

Applied Manrope typography, navy navigation, teal interactions, new spacing and surfaces across the app. Added dynamic assessment summary cards, collapsible environment details, connector cards with expandable permission requirements, mobile navigation, light/dark themes, and refreshed shared table, finding and reporting-page styles. Existing assessment, connector, report and privacy functions remain available. Finding section links now scroll without overwriting the hash-router route; script blocks are keyboard-focusable.

Implementation extends the compact Figma concepts with the existing required consent/licensing disclosures, customer tenant form, complete report content and real API states. No security evaluation rules, app registration permissions, customer consent, DNS records, paid resources or billing settings were changed. The main adminsecops.com domain is outside this frontend deployment; the public app landing page is served at app.adminsecops.com.

Font: self-hosted Google Fonts Manrope variable TTF, SIL Open Font License included in apps/web/public/fonts/OFL.txt. No external font request is required.

Validation:
- 78 frontend tests across 10 files passed.
- Frontend typecheck, focused ESLint and online production build passed.
- Playwright rendered desktop 1440px and mobile 390px using fictional fixtures: landing, workspace, overview and finding details. No horizontal overflow or page errors.
- Axe WCAG 2 A/AA checks: zero violations across those six views and the mobile dark-mode workspace after corrections.
- Mobile menu and theme toggle verified in the browser.
- Manual screenshot review of landing, workspace, finding and mobile layouts.

Build assets: index-CCqMZXoE.js and index-BQXCOon4.css.
Rollback package: out/adminsecops-before-redesign-20260926.zip.
Authenticated live customer collection is not part of visual verification; no customer tenant was connected or assessed during this task.

Azure deployment `<deployment-id>` completed and became active. Live browser verified the new landing heading, self-hosted Manrope, no horizontal overflow or page errors, the unchanged /auth/login link, and API health HTTP 200. Live screenshot saved in the local review artifacts.
