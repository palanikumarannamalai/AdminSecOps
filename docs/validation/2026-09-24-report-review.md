# Report review validation — 2026-09-24

Added M365-SPO-005 (invitation account matching) and M365-SPO-006 (domain restriction configuration). Both use existing SharePoint Graph fields and require no new permission. Missing evidence stays not assessed; partial evidence cannot establish a pass; unknown settings require review. Business choices are not automatic failures. No customer fixture or report is checked into source control.

Corrected ENTRA-CA-006/007 wording so broad MFA/block policies are not automatically described as risk-targeted. Evaluation conditions are unchanged. Control versions 1.0.3; library version 0.4.0, 105 controls.

Validation:
- 69 test files, 1,414 tests passed, including the Exchange runner test with ADMINSECOPS_TEST_PWSH configured.
- Package build and root TypeScript checks passed.
- Control-plane build, online frontend build and frontend typecheck passed.
- Generated control catalog verified.
- Focused lint completed after replacing a loose null comparison with explicit null/undefined checks.

No deployment, new consent, tenant remediation or live customer collection occurred in this task. The pending connector release from 2026-09-22 remains a separate integration/deployment step. Existing reports are immutable; new controls require a new assessment after release.
