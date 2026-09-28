# Contribute a control

Start with an issue describing a gap, the supported workload, the exact baseline version and an authoritative source. Use fictional tenants and identifiers only. Never upload customer reports or tokens.

Copy a neighbouring defineControl implementation and its test. Supply a unique ID, version, lifecycle, required evidence, supported scope, rationale, expected state, remediation impact, rollback and verification. Prefer the smallest permissions needed and fixed read operations. New permissions need explicit review.

Tests must demonstrate pass, fail where justified, review for ambiguous configurations, missing evidence, denied access, partial collection and alternative controls. Missing evidence must never pass. Add dataset schema and collector contract tests for new sources; do not silently expand evidence collection.

Run npm run typecheck, npm test, npm run lint, npm run docs:generate and npm run scan:secrets. Include synthetic evidence, source dates, collection limits and live validation status in the PR. The forwarding-rules.test.ts file provides examples of review-only controls and partial evidence.

Template checklist:
- [ ] Control ID, version and authoritative reference
- [ ] Applicability, exclusions and supported licences
- [ ] Dataset schema and minimal read operation
- [ ] Pass/fail/review/unknown cases with fictional evidence
- [ ] Impact, rollback and verification guidance
- [ ] Generated catalogue and limitations updated

## Starter control

Copy a neighbouring control so imports and metadata match the current library. Replace every placeholder before registration. This deliberately returns review; implement only decisions supported by collected evidence.

```ts
export const newControl = defineControl({
  // Copy the neighbouring control's required metadata and replace its ID,
  // source references, applicability, remediation and verification guidance.
  ...reviewedMetadata,
  id: 'WORKLOAD-CATEGORY-000',
  version: '1.0.0',
  lifecycle: 'preview',
  requiredEvidence: ['workload.dataset'],
  evaluate: ctx => {
    const data = ctx.data('workload.dataset');
    return review({
      reason: 'Describe the uncertainty that still requires administrator review.',
      summary: 'Review the observed configuration.',
      facts: [fact('Observed setting', data.setting)],
    });
  },
});
```

Test matrix: enabled + complete; disabled + complete; unknown property; denied dataset; partial listing; explicit exclusions; supported alternative policy. Start with synthetic values from the schema and assert the resulting status and evidence explanation.
