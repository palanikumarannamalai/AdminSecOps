# Workspace redesign

Figma concepts: https://www.figma.com/design/ZnbNkopiWvHtkoN5InZhiP

Implemented: workload selection (tenant identity always verified), connector readiness guidance, dataset progress, retries of incomplete workloads, separate confirmed/review/unknown outcomes, evidence dates, finding quick view with Escape and focus restoration, collapsible technical detail, tenant-shared owner/date/notes/exception tracking, verified resolution, observed-value comparison and lost coverage, executive HTML download, and a privacy-conscious incorrect-finding issue template and contribution guide.

The landing page uses an actual application screenshot with fictional test data. Existing portfolio links, themes and header sign-out remain. No customer evidence was sent to Figma; the file contains fictional layout concepts only.

Tracking is scoped by authenticated tenant and control ID, audited, and retained for 90 days after its last update. Exceptions do not alter control verdicts. Resolution requires PASS in the latest stored tenant assessment; old reports and historical findings are not rewritten. A subsequent assessment can still report a new failure, so a historical resolved tracking record does not override evidence. Concurrent edits currently use last-save-wins; no approval workflow is implied.

Selection uses existing permissions and does not grant new roles. A retry creates a new snapshot for the selected incomplete workloads; it does not merge old evidence. Progress is real dataset state rather than an invented time estimate. Observed-value comparisons are limited to comparable facts with the same control version, not arbitrary raw configuration differences.

Database migration adds modules/progress to aso_jobs and creates aso_remediations. Apply with the table owner before deploying where the application role cannot ALTER existing tables. Existing job rows keep default full scope. No customer configuration or mail/DNS setting changes are required.

Validation: automated regression suite, tenant isolation and resolution checks, collector selection/progress test, executive-report escaping, and synthetic browser submission/quick-view/tracking/download checks. Browser accessibility scan found no serious or critical issues on the overview. This does not replace a complete accessibility audit or live connector validation.

Remaining external dependencies: an authorised domain-joined host for on-premises validation and a supported SharePoint administrative collection path for the omitted invitation setting. Those collection gaps remain untested.

The additive migration completed on the test database. Temporary-table integration checks passed for persisted tracking, cross-tenant isolation, selected job scope and dataset progress; no customer evidence was used.
