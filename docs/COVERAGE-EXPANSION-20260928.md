# Coverage expansion — 28 September 2026

Implemented in control library 0.5.0 (107 controls):

- Hosted Entra collection reads bounded, paged membership of groups assigned active or eligible administrator roles. Unknown, denied, incomplete or non-user membership remains unresolved and the dataset is partial. Existing permissions are used; no new Graph consent is added.
- Administrator MFA registration includes complete role-group membership as well as direct active and resolved PIM-eligible users. Disabled members are excluded when known. Other administrator controls do not yet expand groups.
- All-user and administrator MFA policy checks combine finite exclusions across otherwise qualifying broad policies. They can resolve exclusions using complete role-group evidence; arbitrary included groups, unknown exclusions and complex condition unions remain review cases. A policy configuration result is not proof of actual sign-in outcomes.
- Missing SharePoint invitation-account matching triggers one targeted v1.0 select request. Missing/denied results remain unknown, with existing tenant settings preserved. Live recovery of this field is not yet confirmed.
- Exports contain optional backward-compatible dataset gapCategory values: not-connected, permission, licence, failed, not-collected, unsupported and partial. Old reports still load; no saved result is rewritten.
- INTUNE-CMP-004 and INTUNE-CMP-005 assess Secure Boot and code integrity requirements in assigned Windows compliance policies. Missing settings remain unassessed. Group-only coverage and exclusions require review. These are policy checks, not proof of effective device health.
- Reports includes a CSV remediation tracker for failures, reviews and evidence gaps. Columns support owner, due date, tracking status, exception expiry and verification evidence. Spreadsheet formula cells are neutralised. The downloaded tracker is edited externally; it is not a hosted exception/approval workflow.

## Exchange deployment

The existing runtime probe passed: PowerShell 7.6.4 and ExchangeOnlineManagement 3.10.1. The owner authorised continuing the remaining connector work; the deployment now enables the optional Exchange connection using previously approved Exchange.Manage permission. A separate user Connect action and Microsoft consent remain necessary. Tokens may carry user write authority; the runner permits only fixed read operations. Palani Lab live sign-in/consent and assessment validation are pending user action. No customer assessment has been run for this change.

## Still outstanding

- Exchange live validation and validation of SharePoint property recovery.
- Arbitrary CA group targeting and complex condition combinations, full effective assignment evaluation and custom role coverage.
- Teams tenant-wide policies, additional Defender and Intune configuration/endpoint-security modules, site-level SharePoint controls.
- Workload selection, persistent remediation ownership/approved exceptions, schedules and value-level drift.
- The optional on-premises agent remains a separate unimplemented component, not a downloadable working connector.

Microsoft references: group-list-members, rbacapplication-list-roleeligibilityschedules and intune-deviceconfig-windows10compliancepolicy in Microsoft Graph v1.0, and sharepointsettings-get. No licence purchase, new resource, mail/DNS change or automated tenant remediation is part of this release.
