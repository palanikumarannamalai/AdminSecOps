# Assessment coverage fixes — 28 September 2026

This release addresses specific gaps found in the exported assessment:

- The online home page explains connector readiness, licence uncertainty, unsupported on-premises checks and partial assessments before the run button.
- Not-applicable evidence preserves the collector's warning (for example LICENSE_NOT_PRESENT), and the engine carries the reason into each affected control. Existing saved assessments are immutable; run a new assessment to obtain the improved explanation.
- ENTRA-PRIV-005 version 1.0.2 joins PIM-eligible principals to the user registration report and deduplicates active/eligible users. Missing eligible principals and group membership remain REVIEW. Registration is not proof of MFA enforcement.
- SharePoint collection records SETTING_NOT_RETURNED when invitation account matching is absent. This does not manufacture a value or mark the control as passed.
- Exchange's permission disclosure explains management scope despite fixed read operations. The deployment enablement and live validation are still separate outstanding work.
- The product page's blanket no-live-validation statement is replaced with the more limited authorised-lab validation statement.

Remaining work from the product review: group membership resolution and effective Conditional Access evaluation; hosted Exchange runtime and opt-in validation; successful retrieval/manual verification of the omitted SharePoint property; workload selection and machine-readable gap categories; broader Teams/Intune/Defender/site-level controls; remediation/exception workflow; on-premises agent.

No new permission or tenant configuration change is introduced by these fixes. Customer reports are not used as test fixtures.
