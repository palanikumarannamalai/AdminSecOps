# Roadmap

Updated 26 September 2026. These are priorities, not promised release dates.

## Available in the test release

- Browser-based Microsoft sign-in and tenant-bound hosted assessments.
- Entra, Intune, SharePoint/OneDrive and limited Teams collection through Graph.
- Separate Azure and Exchange connectors; public mail DNS collection.
- Evidence-based findings, coverage, guidance and report export.
- Local and static browser editions, with fictional sample environments.

## Before promoting the hosted release for wider use

1. Complete live tenant validation of the new Azure and Exchange connectors, including
   consent failures, limited roles, missing licences and partial collection.
2. Check observed results against portal configuration and current Microsoft guidance.
3. Keep collection limitations visible and distinguish untested data from passing checks.
4. Expand automated accessibility and browser regression coverage.
5. Review deployment documentation, dependency updates and release packaging.

## Community contributions wanted

- Reproducible defects using fictional fixtures.
- Documented control corrections with authoritative references and tests.
- Connector response fixtures that are synthetic, never copied from customer tenants.
- Accessibility improvements, clearer guidance and contributor documentation.

## Later proposals

- Broader Teams policy and Intune configuration coverage.
- Configuration drift, expiring risk acceptance and richer reports.
- Signed local evidence packages and signed collector distribution.
- An optional on-premises agent: design only, not implemented or available for install.
- Scheduled assessments and additional collaboration features, subject to a separate design.

The source uses the MIT licence. Potential commercial hosting or support does not change
the licence of code already released. No commercial features or service levels are promised.
