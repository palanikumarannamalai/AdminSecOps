# Entra and hybrid control standards review

Checked 2026-09-21. Scope: all 23 Entra controls and all four hybrid controls, their metadata, evaluators and tests. This is an evidence-semantics review against current primary documentation, not certification of a tenant or complete NIST/SCuBA coverage. No customer evidence was accessed.

`Aligned` means the implemented, explicitly bounded observation agrees with the cited guidance. `Changed` means a confirmed misleading result or assertion was corrected. `Needs evidence` means a broader conclusion needs information outside the current contract; it is not proof of a security failure.

| Control | Verdict | Primary source checked 2026-09-21 | Finding, correction and limits |
|---|---|---|---|
| ENTRA-CA-001 | Changed | [Microsoft baseline][mfa], [security defaults][sd] | Explicit user/group targets and unknown strengths require REVIEW rather than claiming absent MFA. Complete baseline still passes. Per-user MFA and actual sessions are outside evidence. |
| ENTRA-CA-002 | Changed | [Administrator MFA][admins] | Review names discovered policies, states the coverage gap and lowers confidence. Group membership is never inferred. No qualifying template is not proof of MFA bypass. |
| ENTRA-CA-003 | Changed | [Legacy protocols][legacy] | Blocking every client type also blocks legacy clients. Scoped blocking is REVIEW. Exchange-specific protocol settings are not collected by this check. |
| ENTRA-CA-004 | Changed | [Authentication strengths][strength] | Explicit-user/group authentication-strength targeting is unresolved coverage, not automatic failure. Custom strength method combinations remain evidence-dependent. |
| ENTRA-CA-005 | Changed | [Device-code guidance][flow], [security defaults][sd] | Security defaults now provide a possible alternative. REVIEW avoids recommending duplicate CA without validating rollout/effective behavior. Otherwise checks complete CA flow blocking. |
| ENTRA-CA-006 | Changed | [Sign-in risk][signinrisk], [grant semantics][grant] | Unconditional coverage can cover high risk. MFA requires evidence of Every time session frequency for this current baseline; missing frequency/scope becomes REVIEW. Block remains valid. |
| ENTRA-CA-007 | Changed | [User risk][userrisk], [grant semantics][grant] | Accepts riskRemediation AND strength with Every time; legacy passwordChange requires AND MFA. Unknown future enum values require REVIEW. |
| ENTRA-PRIV-001 | Changed | [Role practices][roles] | Within-threshold counts with unavailable eligibility or unexpanded groups require REVIEW. Confirmed excess still fails. Principal counts are not human membership counts. |
| ENTRA-PRIV-002 | Changed | [Role practices][roles] | Eligible/group/non-user/unknown-state principals cannot alone establish two usable active users. REVIEW when needed; account purpose and tested emergency access remain unverified. |
| ENTRA-PRIV-003 | Changed | [Hybrid isolation][isolation] | Unresolved groups cannot establish cloud-only privileged users. Synchronized direct users fail; unexpanded membership is REVIEW. Federated-domain and custom-role coverage remains limited. |
| ENTRA-PRIV-004 | Needs evidence | [PIM][pim] | Selected permanent built-in assignments are correctly detected. A clean result does not prove activation approval, actual JIT usage, custom-role risk or third-party PAM equivalence. |
| ENTRA-PRIV-005 | Aligned | [Registration report][registration], [Administrator MFA][admins] | Existing evaluator reviews unresolved groups, eligible users and missing registration. Registration never establishes MFA enforcement. Selected role catalog is explicit. |
| ENTRA-AUTH-001 | Changed | [Registration report][registration] | Empty member coverage or unknown user types cannot pass. Confirmed unregistered members still fail configured threshold; disabled-account state is not in this evidence. |
| ENTRA-AUTH-002 | Changed | [Method policies][methods], [NIST authentication][nist] | Absent method entries/migration status cannot prove telephony disabled. REVIEW unless migrated policy explicitly disables both. This is stronger hygiene guidance, not a universal NIST ban. |
| ENTRA-APP-001 | Aligned | [Default permissions][defaults] | Evaluates default app-registration permission; delegated developer/admin roles are legitimate alternatives and intentionally outside the default-user flag. |
| ENTRA-APP-002 | Aligned | [User consent][consent] | Known low-impact publisher policy or disabled consent accepted; custom policies require REVIEW. Existing grants and admin-consent workflow are not validated. |
| ENTRA-APP-003 | Changed | [App credential guidance][credentials], [SCuBA][scuba] | Default lifetime tightened to 180 days; undated secrets REVIEW. Existing credential lifetime is checked, not enforcement of application management policy. |
| ENTRA-APP-004 | Needs evidence | [App security and least privilege][credentials] | Known high-impact grants correctly require owner review. The permission catalog is finite, not every privilege path; unresolved role names and workload authorization restrictions need richer evidence. |
| ENTRA-APP-005 | Needs evidence | [App security and least privilege][credentials] | Known broad data permissions correctly require REVIEW, not automatic compromise. Exchange application RBAC and resource-specific restrictions are not resolved. |
| ENTRA-EXT-001 | Aligned | [External collaboration][external] | Recognizes documented member-equivalent, limited and restricted guest settings. Unknown role IDs require REVIEW. This is directory access, not all resource permissions. |
| ENTRA-EXT-002 | Aligned | [External collaboration][external], [SCuBA][scuba] | Existing broader all-member invitation baseline is preserved but the SCuBA mapping now explicitly states non-equivalence. Domain restrictions and access packages are separate checks. |
| ENTRA-EXT-003 | Changed | [Sign-in activity semantics][activity] | Failed attempts can update timestamps. Enabled guests now require successful-use/business-owner evidence; old or absent attempts produce REVIEW, not a claim of never signing in. |
| ENTRA-TEN-001 | Aligned | [Default permissions][defaults] | True/false/null default tenant-creation flag is handled distinctly. Custom/delegated creator roles remain outside the default permission check. |
| HYB-SYNC-001 | Changed | [Matching protections][matching] | Removed assertion that false flag permits takeover of privileged cloud administrators: current service-side hard-match protections apply. Flag remains a separate additional hardening baseline. |
| HYB-SYNC-002 | Aligned | [Matching protections][matching] | Tenant soft-match blocking remains a defensible post-migration baseline. Planned migration exceptions require administrator review, not blind remediation. |
| HYB-SYNC-003 | Changed | [Organization semantics][organization], [Sync health][synchealth] | Missing/future timestamp REVIEW; confirmed old timestamp fails configurable 24-hour operational baseline. Documented null sync-enabled semantics remain not applicable. |
| HYB-PWD-001 | Changed | [Password Protection][password] | PASS is limited to tenant Enforce configuration; title/reason no longer claim agent deployment or DC enforcement was verified. Agent health/logs require on-premises evidence. |

## Standards differences and evidence boundaries

- CISA's current Entra baseline requires blocking high-risk users/sign-ins; Microsoft also documents self-remediation/MFA alternatives. CA006/007 mappings now explicitly identify that distinction. An AdminSecOps PASS is not SCuBA conformance.
- SCuBA permits two to eight Global Administrators; Microsoft recommends fewer than five. The configurable maximum of four is intentionally the stricter Microsoft threshold. No group is assumed to contain one person.
- SCuBA's April 2026 application-secret guidance uses 180 days; APP003 now uses that default. The check does not prove the tenant configured the policy preventing future longer secrets.
- NIST SP800-63B-4 provides assurance-level requirements and restricts PSTN authentication; it does not make every enabled SMS method an automatic universal failure. AUTH002 remains REVIEW when telephony exists.
- Complete user/group expansion, custom authentication-strength combinations, custom-role privilege analysis, PIM activation settings, actual successful sign-ins and on-premises agent health are not inferred. Missing evidence cannot establish those claims.
- Microsoft now documents security-default device-code blocking, with new-tenant rollout from July 2026. The collector's boolean alone cannot prove tenant-specific effective behavior; CA005 reports REVIEW for this alternative.
- Read-only static configuration is not a Conditional Access execution simulator. Use Microsoft's What If and sign-in logs for effective combinations, exclusions and session behavior.

## Validation

Targeted command: `npx vitest run packages/controls/src/library/entra packages/controls/src/library/hybrid packages/inventory/src/derived/conditional-access.test.ts`.
Regression cases cover discovered group-targeted administrator policies, confidence, unresolved targeted strengths, block-all legacy coverage, risk remediation, unknown grants, fresh challenge requirements, unconditional alternative coverage, security defaults, group administrator counts, undated secrets, incomplete registration and guest activity limitations. Final targeted run with `--maxWorkers=2`: 9 test files and 137 tests passed. Scoped ESLint and diff whitespace checks were also run; integration-wide checks remain with the integrating agent.

## Primary sources

All links below were retrieved or searched from primary publishers on 2026-09-21. Checked date records this review, not each publisher's update date. CISA's PDF endpoint returned 403; the current publisher-owned GitHub baseline was read instead.

[mfa]: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-mfa-strength
[sd]: https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults
[admins]: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-old-require-mfa-admin
[legacy]: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-legacy-authentication
[strength]: https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-strengths
[flow]: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows
[signinrisk]: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-sign-in
[userrisk]: https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-risk-based-user
[grant]: https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0
[roles]: https://learn.microsoft.com/nb-no/entra/identity/role-based-access-control/best-practices
[isolation]: https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks
[pim]: https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure
[registration]: https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails?view=graph-rest-1.0
[methods]: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods-manage
[nist]: https://pages.nist.gov/800-63-4/sp800-63b.html
[defaults]: https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions
[consent]: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent
[credentials]: https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration
[external]: https://learn.microsoft.com/en-us/entra/external-id/external-collaboration-settings-configure
[activity]: https://learn.microsoft.com/en-us/graph/api/resources/signinactivity?view=graph-rest-1.0
[matching]: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-existing-tenant
[organization]: https://learn.microsoft.com/en-us/graph/api/resources/organization?view=graph-rest-1.0
[synchealth]: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-health-sync
[password]: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-on-premises
[scuba]: https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md
