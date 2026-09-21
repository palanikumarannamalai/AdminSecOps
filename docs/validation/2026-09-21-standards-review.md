# Control standards review � 21 September 2026

Scope: every implemented AdminSecOps control, its evidence requirements, decision logic,
remediation wording and cited guidance. This is a source-and-code comparison, not a certification
of a customer tenant. Customer configurations were not changed during the review.

## Review matrices

- [Entra ID and hybrid identity](2026-09-21-entra-hybrid.md)
- [Microsoft 365, Azure and Intune](2026-09-21-cloud.md)
- [Active Directory, AD CS, Group Policy and Windows](2026-09-21-onprem.md)

Each matrix identifies the control, source and remaining evidence limitations. Aligned means the
check's limited claim is supported; it does not mean the entire product or framework requirement
has been assessed. Changed means a confirmed mismatch was corrected. Needs-evidence items
must not be promoted to a confirmed failure or pass without the missing context.

## Result interpretation

- PASS: the collected evidence satisfies this specific check, within its documented scope.
- FAIL: the collected evidence does not meet this check. Organizational applicability and
  documented compensating controls still matter.
- REVIEW: verification is unresolved. Severity means potential impact if confirmed, not a proven
  vulnerability. Result confidence is capped at medium; the interface explains the uncertainty.
- NOT_ASSESSED: required evidence is absent or unusable. This is never equivalent to PASS.

Engine and library version 0.2.0 rank FAIL before REVIEW, then severity and confidence within
those groups. Finding details lead with observed evidence rather than a generic control description.
The review does not rewrite saved assessment results; run a new assessment for revised decisions.

## Standards and applicability

Microsoft product documentation is used for current product behavior and recommended configuration.
CISA SCuBA policy mappings must be interpreted within the named policy scope and prerequisites.
NIST mappings indicate relevant security objectives; a configuration observation cannot establish
full implementation of a NIST control. No complete CIS or ISO conformance claim is made.

Sources checked for assessment methodology:
- [NIST SP 800-53A Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/a/r5/final): assessment procedures are tailored to the system and assessment objectives.
- [CISA SCuBA Security Suite baseline](https://cisagov.github.io/ScubaGear/PowerShell/ScubaGear/baselines/securitysuite.html): distinguishes automatic checks and manual verification and does not supersede legal or regulatory obligations.
- [CISA ScubaGear](https://github.com/cisagov/ScubaGear): evaluates the named Microsoft 365 baselines; AdminSecOps is not ScubaGear and does not claim equivalent full coverage.

## Hosted coverage

The online collector currently supplies ten Entra datasets. The broader control library also covers
on-premises and other cloud workloads, but those controls require their own evidence and remain
unassessed in an Entra-only online run. Conditional Access group membership, custom strengths and
other context not collected must be stated as unresolved rather than inferred.

Reference availability: all 167 pre-review catalog URLs returned HTTP200 on 21 September2026.
This checks reachability only; substantive comparison is recorded in the control matrices.

## Validation

All 99 control IDs appear exactly once across the three matrices. The complete TypeScript test suite passed: 1,266 tests in 62 files. Type checking, package/backend/online production builds and nine PowerShell live-wrapper tests passed.
