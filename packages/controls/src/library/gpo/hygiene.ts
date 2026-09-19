import { enabledGpoLinks } from '@adminsecops/inventory';
import { defineControl } from '../../define.js';
import { eqi } from '../../helpers.js';
import { aggregateVerdicts, pass_, review_ } from '../shared/verdicts.js';
import { GPO_REF } from './references.js';

export const gpoUnusedObjects = defineControl({
  id: 'GPO-HYG-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Group Policy objects that are unlinked or fully disabled are reviewed',
  technology: 'gpo',
  category: 'Configuration hygiene',
  subcategory: 'Group Policy objects',
  description:
    'Lists Group Policy objects that have no links, whose links are all disabled, or whose settings are all disabled, so the administrator can decide whether to delete them.',
  rationale:
    'Unused GPOs accumulate over time. They make the effective configuration harder to understand, may contain outdated or insecure settings that take effect the moment someone links or re-enables them, and can hold sensitive data such as scripts or preference items. Removing or documenting them keeps Group Policy auditable.',
  severity: 'low',
  confidence: 'high',
  applicability: { description: 'Active Directory domains whose Group Policy objects were collected.' },
  requiredEvidence: ['gpo.groupPolicyObjects'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For each GPO: marked for review when it has no links, when every link is disabled, or when its status is AllSettingsDisabled. Otherwise it is compliant. The result is REVIEW (never FAIL) when any GPO is marked, because an unused GPO can be intentional (for example a prepared baseline awaiting rollout or a documented break-glass policy). PASS when every GPO is linked and enabled. An empty GPO list is NOT_ASSESSED because every domain contains at least the Default Domain Policy.',
    parameters: {},
  },
  expectedState: 'Every GPO is linked with at least one enabled link and has settings enabled, or is documented as intentionally unused.',
  remediation: {
    summary: 'Back up and delete GPOs that are no longer needed, and document the ones you intend to keep unused.',
    steps: [
      'In the Group Policy Management Console (GPMC) back up all GPOs (Group Policy Objects > Back Up All).',
      'For each GPO in the finding, check its Settings tab and Details (owner, modified date, comments) and ask its owner whether it is still needed.',
      'Delete GPOs that are no longer required (right-click > Delete under Group Policy Objects). Deleting a GPO also removes its SYSVOL folder.',
      'For GPOs you keep, record the reason in the GPO comment (Details tab > Comment).',
    ],
    scriptExample:
      '# Review only: list GPOs without any link (GroupPolicy module)\nGet-GPO -All | ForEach-Object {\n  [xml]$r = Get-GPOReport -Guid $_.Id -ReportType Xml\n  if (-not $r.GPO.LinksTo) { [pscustomobject]@{ Name = $_.DisplayName; Modified = $_.ModificationTime } }\n}\n# Backup-GPO -All -Path "C:\\GPOBackups"   # before deleting anything',
    effort: 'low',
  },
  implementationConsiderations: [
    'A GPO can be linked to sites, domains or OUs in other domains of the forest; the collector reports links it found in the collected domain.',
    'Keep backups of deleted GPOs for a period in case a dependency is discovered later.',
  ],
  impact: 'Deleting an unlinked GPO has no effect on computers or users; deleting a GPO whose links were only temporarily disabled removes it permanently.',
  rollback: ['Restore the GPO from the GPMC backup (Group Policy Objects > Manage Backups > Restore).'],
  validation: ['Re-run the AdminSecOps Group Policy collector and confirm GPO-HYG-001 is PASS or lists only documented exceptions.'],
  references: [GPO_REF.gpmc, GPO_REF.groupPolicyProcessing, GPO_REF.attackGroupPolicyModification],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'CM-2' },
    { framework: 'NIST-800-53r5', id: 'CM-6' },
  ],
  tags: ['group-policy', 'hygiene', 'configuration-management'],
  evaluate: (ctx) =>
    aggregateVerdicts({
      items: ctx.data('gpo.groupPolicyObjects'),
      subject: (g) => ({ type: 'groupPolicyObject', id: g.id, name: g.displayName }),
      noun: ['GPO', 'GPOs'],
      requirement: 'every GPO is linked and has settings enabled',
      empty: {
        status: 'NOT_ASSESSED',
        reason: 'The evidence contains no Group Policy objects, although every domain has at least the Default Domain Policy. Confirm the collector could read Group Policy.',
      },
      reviewGuidance:
        'Unlinked or disabled GPOs are listed for review rather than failed because some are kept intentionally; delete the ones that are no longer needed and document the rest.',
      classify: (g) => {
        const modified = g.modifiedTime !== null ? ` Last modified ${g.modifiedTime.slice(0, 10)}.` : '';
        if (g.links.length === 0) return review_(`Not linked to any site, domain or OU (${g.domain}).${modified}`);
        if (enabledGpoLinks(g).length === 0) return review_(`All ${g.links.length} link(s) are disabled: ${g.links.map((l) => l.somPath).join('; ')}.${modified}`);
        if (eqi(g.gpoStatus, 'AllSettingsDisabled')) return review_(`Linked, but all settings are disabled (GPO status AllSettingsDisabled).${modified}`);
        return pass_('Linked and enabled.');
      },
    }),
});
