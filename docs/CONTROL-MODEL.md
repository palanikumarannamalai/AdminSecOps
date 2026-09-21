# Control model

A control is a versioned, deterministic rule that evaluates normalized evidence and
produces a result. Controls live in `packages/controls/src/library/<technology>/` and
are defined with `defineControl` (`packages/controls/src/define.ts`).

## Definition

Every control has validated metadata (`ControlMetadataSchema` in
`packages/schemas/src/control.ts`) and code:

| Field | Meaning |
|---|---|
| `id` | Stable identifier, e.g. `ENTRA-CA-001`. Never reused. |
| `version` | Semantic version of the control. Bump the minor version when logic changes, the major version when meaning changes. |
| `lifecycle` | `stable`, `preview` or `deprecated`. |
| `title`, `description` | What is checked, in administrator language. |
| `technology`, `category`, `subcategory` | Classification; technology drives dashboard modules. |
| `rationale` | Why it matters (becomes the finding's risk explanation). |
| `severity` | `critical`, `high`, `medium`, `low`, `informational` - impact if the control fails. |
| `confidence` | How directly the evidence supports the result (`high`/`medium`/`low`). |
| `applicability` | Human description of when the control applies; logic in `applies()`. |
| `requiredEvidence` / `optionalEvidence` | Dataset IDs. Validated against the dataset registry at load time. |
| `evaluation.logic` | Plain-language description of exactly what the code does. |
| `evaluation.parameters` | Thresholds (e.g. `maxGlobalAdmins: 4`), visible in reports and tests. |
| `expectedState` | What good looks like. |
| `remediation` | Summary, numbered steps, optional script example (administrators run it; AdminSecOps never does), effort. |
| `implementationConsiderations`, `impact` | What to check before changing and what users will notice. |
| `rollback`, `validation` | How to undo and how to verify. |
| `references` | Authoritative https URLs (Microsoft Learn, NIST, CISA, MITRE). |
| `frameworkMappings` | Identifiers in NIST SP 800-53 r5, CISA SCuBA, MITRE ATT&CK, Microsoft cloud security benchmark. |
| `tags` | Free tags; some drive prioritization (see below). |

Invalid metadata (missing rollback, unknown dataset, non-https reference, etc.) throws
when the library loads, so it fails the test suite rather than producing an incomplete
finding.

## Result statuses

| Status | Meaning |
|---|---|
| `PASS` | Evidence shows the expected state. |
| `FAIL` | Evidence shows the configuration does not meet the expected state. |
| `REVIEW` | Evidence shows a state that needs administrator judgement (e.g. an application with high-impact permissions that may be legitimate), or a PASS that was computed from partial evidence. The reason always says why. |
| `NOT_APPLICABLE` | The control does not apply (licence absent, feature not used, no objects of that type). |
| `NOT_ASSESSED` | Evidence was missing, failed, unauthorized or invalid. Unknown, not compliant. |
| `ERROR` | The control itself failed to evaluate - a defect in AdminSecOps. |

**Missing evidence never becomes PASS.** This is enforced in one place
(`packages/engine/src/evaluate.ts`) and verified for every control by
`packages/controls/src/library/library.test.ts`, which evaluates each control against
empty, failed and not-applicable evidence.

## Findings

Every `FAIL` or `REVIEW` result becomes a finding (`FindingSchema`) that combines the
result with the control metadata: finding ID (deterministic from assessment ID and
control ID), finding key (control ID, stable across assessments for comparison),
status, severity, confidence, observed and expected state, affected objects (up to 500
stored, full count kept), evidence references (dataset, file, SHA-256, collection time,
status, source operations), risk, remediation, implementation considerations, impact,
rollback, validation, references, framework mappings and priority.

## Prioritization ("What should I fix first?")

`packages/engine/src/prioritize.ts` orders findings deterministically. The sort key is
lexicographic:

1. status (FAIL before REVIEW - evidenced findings before judgement calls)
2. severity (critical > high > medium > low > informational)
3. confidence (high > medium > low)
4. exposure tags present (max 3): `privileged-access`, `internet-exposure`,
   `credential-exposure`, `legacy-authentication`, `mfa`, `data-exfiltration`
5. effort (low effort first so quick wins surface within equal risk)

Ties are broken by control ID. Tiers: **Fix now** (FAIL, critical/high, confidence not
low), **Fix next** (other FAIL critical/high/medium), **Plan** (FAIL low/informational),
**Review** (all REVIEW). The ordering is a recommendation, not a score, and is covered by
`packages/engine/src/engine.test.ts`.

## No composite score

AdminSecOps does not compute a security score (see ADR-0006). The dashboard and
reports show counts by status and severity, and **assessment coverage** =
assessed controls (PASS+FAIL+REVIEW) / applicable controls (all minus NOT_APPLICABLE),
explicitly labelled as coverage.

## References and framework mappings

References store only titles and URLs; no third-party text is copied. CIS Benchmark
content is not used. Framework mappings store identifiers only and indicate a related
requirement, not compliance. CISA SCuBA identifiers are versioned (e.g. `MS.AAD.3.6v1`)
and should be re-checked when ScubaGear baselines are updated.

## Versioning

- `CONTROL_LIBRARY_VERSION` (packages/controls) versions the library as a whole.
- Each control has its own `version`, recorded in every result and finding, so a
  comparison can tell whether a status change came from the environment or from the rule.

REVIEW indicates unresolved verification, not a confirmed violation. Its result confidence is capped
at medium. Displayed severity is potential impact if confirmed. All FAIL findings sort before REVIEW;
framework mappings indicate relevance and do not constitute certification or full benchmark coverage.
