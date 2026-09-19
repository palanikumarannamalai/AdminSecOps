# Adding a control

Controls must be accurate, deterministic, tested and backed by authoritative guidance.
Quality matters more than count: do not add shallow controls.

## 1. Confirm the evidence exists

Find the dataset(s) in `packages/schemas/src/datasets/`. If the data you need is not
collected, first extend the dataset schema **and** the collector (see ADDING-A-COLLECTOR.md),
including permissions and privacy classification, then regenerate docs
(`npm run docs:generate`).

If the evidence needs parsing or joining (for example resolving role names or parsing a
DNS record), add a pure helper in `packages/inventory/src/derived/`. Helpers normalize
facts; they never decide whether something is secure.

## 2. Research the requirement

Use Microsoft Learn first, then NIST, CISA (SCuBA) and MITRE ATT&CK. Record URLs only;
paraphrase, never copy text; do not use CIS Benchmark content. Decide:

- expected state and thresholds (make thresholds `evaluation.parameters`);
- what `null`/absent values mean - only treat them as a known state when an authoritative
  default is documented, and cite it;
- when the control is not applicable (licence, feature not in use);
- which situations need `REVIEW` (genuine judgement) and why.

## 3. Write the control

Create or extend `packages/controls/src/library/<technology>/<topic>.ts`:

```ts
export const exampleControl = defineControl({
  id: 'ENTRA-XYZ-001',              // never reuse IDs
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Short statement of the secure state',
  technology: 'entra',
  category: 'Authentication',
  subcategory: 'Multifactor authentication',
  description: 'What is checked.',
  rationale: 'Why it matters (becomes the finding risk).',
  severity: 'high',
  confidence: 'high',
  applicability: { description: 'When it applies.' },
  requiredEvidence: ['entra.authorizationPolicy'],
  optionalEvidence: [],
  evaluation: { logic: 'Exactly what the code does.', parameters: { maxThing: 4 } },
  expectedState: 'What good looks like.',
  remediation: { summary: '...', steps: ['...'], scriptExample: '...', effort: 'low' },
  implementationConsiderations: ['What to check before changing.'],
  impact: 'What users will notice.',
  rollback: ['How to undo.'],
  validation: ['How to verify, including re-running AdminSecOps.'],
  references: [REF.someMicrosoftPage],
  frameworkMappings: [{ framework: 'NIST-800-53r5', id: 'IA-2(1)' }],
  tags: ['identity'],
  applies: (ctx) => ({ applicable: true }),         // optional
  evaluate: (ctx) => {
    const policy = ctx.data('entra.authorizationPolicy');   // typed, throws -> NOT_ASSESSED
    // use ctx.assessedAt for any time comparison, never Date.now()
    return policy.x ? pass({ reason: '...', summary: '...' }) : fail({ reason: '...', summary: '...', affectedObjects: [...] });
  },
});
```

Register it in the technology's `index.ts`. Use shared references from
`packages/controls/src/references.ts` or the technology's `references.ts`.

Rules:
- Evaluate every object; list affected objects with a useful `detail`.
- Never return PASS when evidence is missing, partial knowledge is unknown, or the
  relevant objects could not be evaluated.
- Keep remediation defensive and practical; script examples are for administrators to
  review and run - AdminSecOps never executes them.
- Use tags from `PRIORITY_TAGS` (`privileged-access`, `internet-exposure`,
  `credential-exposure`, `legacy-authentication`, `mfa`, `data-exfiltration`) when they
  genuinely apply, because they affect prioritization.

## 4. Test it

Add `<topic>.test.ts` next to the control, using builders in `packages/controls/test/builders/`
and `run()` from `packages/controls/test/run.ts` (real schemas and engine semantics). Cover
PASS, FAIL, REVIEW, applicability, special NOT_ASSESSED handling, partial evidence and edge
cases (nulls, case differences, empty lists, multiple objects/domains/subscriptions).

`library.test.ts` automatically checks every control against empty, failed and
not-applicable evidence and fails if a control ID is not referenced by a test.

## 5. Finish

`npm run docs:generate`, then `npm run verify`. Bump `CONTROL_LIBRARY_VERSION` for a release.
When changing an existing control, bump its `version` so comparisons can tell rule changes
from environment changes.
