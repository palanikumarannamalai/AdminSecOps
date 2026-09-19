import { daysBetween, parseTimestamp } from '@adminsecops/core';
import { defineControl, type Applicability, type ControlContext } from '../../define.js';
import { affected, eqi, fact, fail, pass, review } from '../../helpers.js';
import { REF } from '../../references.js';

function syncEnabled(ctx: ControlContext): Applicability {
  return ctx.data('entra.organization').onPremisesSyncEnabled === true
    ? { applicable: true }
    : { applicable: false, reason: 'Directory synchronization from on-premises Active Directory is not enabled for this tenant.' };
}

function syncFeatureControl(feature: 'hardMatch' | 'softMatch') {
  const hard = feature === 'hardMatch';
  return defineControl({
    id: hard ? 'HYB-SYNC-001' : 'HYB-SYNC-002',
    version: '1.0.0',
    lifecycle: 'stable',
    title: hard ? 'Cloud object takeover through hard match is blocked' : 'Soft matching of synchronized objects is blocked',
    technology: 'hybrid',
    category: 'Hybrid identity',
    subcategory: 'Directory synchronization',
    description: hard
      ? 'Checks the tenant synchronization feature that prevents on-premises objects from taking over existing cloud accounts by matching their immutable ID (hard match).'
      : 'Checks the tenant synchronization feature that prevents on-premises objects from being joined to existing cloud accounts by matching SMTP address or UPN (soft match).',
    rationale: hard
      ? 'If hard match takeover is allowed, anyone who can create or modify objects in the synchronized Active Directory scope can set a matching immutable ID and take control of an existing cloud-only account, including a cloud-only administrator.'
      : 'Soft matching links an on-premises object to a cloud account with the same e-mail address or UPN. An attacker with write access to on-premises AD can use it to take over cloud accounts. After the initial synchronization, soft matching is rarely needed.',
    severity: hard ? 'high' : 'medium',
    confidence: 'high',
    applicability: { description: 'Tenants that synchronize identities from on-premises Active Directory.' },
    requiredEvidence: ['entra.organization', 'entra.onPremisesSynchronization'],
    evaluation: {
      logic: hard
        ? 'NOT_APPLICABLE when onPremisesSyncEnabled is not true. PASS when features.blockCloudObjectTakeoverThroughHardMatchEnabled is true for every synchronization configuration; FAIL when false; REVIEW when not reported.'
        : 'NOT_APPLICABLE when onPremisesSyncEnabled is not true. PASS when features.blockSoftMatchEnabled is true; FAIL when false; REVIEW when not reported.',
      parameters: {},
    },
    expectedState: hard ? 'blockCloudObjectTakeoverThroughHardMatchEnabled = true.' : 'blockSoftMatchEnabled = true (except temporarily during planned migrations).',
    remediation: {
      summary: hard ? 'Enable blocking of cloud object takeover through hard match.' : 'Enable blocking of soft match.',
      steps: [
        'Connect to Microsoft Graph with OnPremDirectorySynchronization.ReadWrite.All as a Hybrid Identity Administrator.',
        `Update the onPremisesSynchronization features to set ${hard ? 'blockCloudObjectTakeoverThroughHardMatchEnabled' : 'blockSoftMatchEnabled'} to true (see the script example).`,
        'Re-run a synchronization cycle and confirm no unexpected errors.',
      ],
      scriptExample: `Connect-MgGraph -Scopes 'OnPremDirectorySynchronization.ReadWrite.All'\n$sync = Get-MgDirectoryOnPremiseSynchronization\nUpdate-MgDirectoryOnPremiseSynchronization -OnPremisesDirectorySynchronizationId $sync.Id -Features @{ ${hard ? 'BlockCloudObjectTakeoverThroughHardMatchEnabled' : 'BlockSoftMatchEnabled'} = $true }`,
      effort: 'low',
    },
    implementationConsiderations: hard
      ? ['Legitimate re-matching (for example after a forest migration) will require temporarily disabling the block.']
      : ['Onboarding of existing cloud accounts to synchronization relies on soft match; disable the block temporarily during such migrations.'],
    impact: hard ? 'On-premises objects can no longer take over existing cloud accounts by immutable ID.' : 'New on-premises objects no longer merge with existing cloud accounts by address.',
    rollback: ['Set the same feature back to false with Update-MgDirectoryOnPremiseSynchronization.'],
    validation: [`Re-run the AdminSecOps Entra collector and confirm ${hard ? 'HYB-SYNC-001' : 'HYB-SYNC-002'} is PASS.`],
    references: [REF.syncHardMatchSoftMatch, REF.onPremisesSyncResource, REF.protectM365FromOnPrem],
    frameworkMappings: [
      { framework: 'NIST-800-53r5', id: 'AC-2' },
      { framework: 'MCSB', id: 'IM-2' },
      { framework: 'MITRE-ATTACK', id: 'T1098' },
    ],
    tags: ['hybrid', 'identity', ...(hard ? ['privileged-access'] : [])],
    applies: syncEnabled,
    evaluate: (ctx) => {
      const configs = ctx.data('entra.onPremisesSynchronization');
      const values = configs.map((c) => (hard ? c.features.blockCloudObjectTakeoverThroughHardMatchEnabled : c.features.blockSoftMatchEnabled));
      const facts = [fact(hard ? 'Hard match takeover blocked' : 'Soft match blocked', values.length === 1 ? (values[0] ?? null) : values.map(String).join(', '))];
      if (values.length === 0 || values.some((v) => v === null)) {
        return review({ reason: 'The synchronization feature flag was not reported.', summary: 'Setting could not be determined.', facts });
      }
      if (values.some((v) => v === false)) {
        return fail({
          reason: hard ? 'Cloud object takeover through hard match is allowed.' : 'Soft matching is allowed.',
          summary: hard ? 'On-premises objects can take over cloud accounts by immutable ID.' : 'On-premises objects can be soft-matched to existing cloud accounts.',
          facts,
          affectedObjects: configs.map((c) => affected('directorySynchronization', c.id, 'Tenant synchronization settings')),
        });
      }
      return pass({ reason: hard ? 'Hard match takeover is blocked.' : 'Soft matching is blocked.', summary: 'Synchronization matching is restricted.', facts });
    },
  });
}

export const hybridBlockHardMatch = syncFeatureControl('hardMatch');
export const hybridBlockSoftMatch = syncFeatureControl('softMatch');

export const hybridSyncRecent = defineControl({
  id: 'HYB-SYNC-003',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Directory synchronization completed recently',
  technology: 'hybrid',
  category: 'Hybrid identity',
  subcategory: 'Directory synchronization',
  description: 'Checks that the last directory synchronization reported by the tenant is recent relative to the assessment time.',
  rationale:
    'When synchronization stops, disabled or deleted on-premises accounts stay active in the cloud, password changes are not reflected, and group-based access is not updated. A stalled sync is therefore a security issue, not only an operational one.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Tenants that synchronize identities from on-premises Active Directory.' },
  requiredEvidence: ['entra.organization'],
  evaluation: {
    logic: 'NOT_APPLICABLE when onPremisesSyncEnabled is not true. FAIL when onPremisesLastSyncDateTime is more than maxHoursSinceSync hours before the assessment time or missing.',
    parameters: { maxHoursSinceSync: 24 },
  },
  expectedState: 'The last successful synchronization occurred within the last 24 hours (Microsoft Entra Connect syncs every 30 minutes by default).',
  remediation: {
    summary: 'Restore directory synchronization.',
    steps: [
      'On the Microsoft Entra Connect (or Cloud Sync agent) server check the synchronization service and scheduler (Get-ADSyncScheduler).',
      'Review Microsoft Entra Connect Health and the sync errors report in the admin center.',
      'Resolve the error, then run Start-ADSyncSyncCycle -PolicyType Delta and confirm success.',
    ],
    effort: 'medium',
  },
  implementationConsiderations: ['Keep the Entra Connect server patched and treat it as a Tier 0 asset.'],
  impact: 'None; restores expected identity lifecycle behaviour.',
  rollback: ['Not applicable.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm HYB-SYNC-003 is PASS.'],
  references: [REF.syncHealth, REF.syncTroubleshooting],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-2' },
    { framework: 'MCSB', id: 'IM-1' },
  ],
  tags: ['hybrid', 'identity'],
  applies: syncEnabled,
  evaluate: (ctx) => {
    const org = ctx.data('entra.organization');
    const maxHours = ctx.num('maxHoursSinceSync');
    const last = parseTimestamp(org.onPremisesLastSyncDateTime);
    if (last === undefined) {
      return fail({ reason: 'Synchronization is enabled but no last synchronization time is reported.', summary: 'Directory synchronization state is unknown.', facts: [fact('Last sync', null)] });
    }
    const hours = Math.floor((ctx.assessedAt.getTime() - last.getTime()) / 3_600_000);
    const facts = [fact('Last sync', last.toISOString()), fact('Hours since last sync', hours), fact('Days since last sync', daysBetween(last, ctx.assessedAt))];
    if (hours > maxHours) {
      return fail({ reason: `The last synchronization was ${hours} hours before the assessment.`, summary: 'Directory synchronization appears to have stopped.', facts });
    }
    return pass({ reason: `The last synchronization was ${hours} hours before the assessment.`, summary: 'Directory synchronization is current.', facts });
  },
});

export const hybridPasswordProtectionEnforced = defineControl({
  id: 'HYB-PWD-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Microsoft Entra Password Protection is enforced for Active Directory',
  technology: 'hybrid',
  category: 'Hybrid identity',
  subcategory: 'Password protection',
  description: 'Checks the tenant Password Rule Settings that control Microsoft Entra Password Protection for on-premises Active Directory.',
  rationale:
    'Password Protection blocks weak and commonly attacked passwords (plus your custom banned terms) when users change passwords in Active Directory. In Audit mode it only logs, so weak passwords that password spraying targets remain in use.',
  severity: 'medium',
  confidence: 'medium',
  applicability: { description: 'Tenants that synchronize from on-premises Active Directory. The DC agent must also be deployed, which is not visible in cloud evidence.' },
  requiredEvidence: ['entra.organization', 'entra.groupSettings'],
  evaluation: {
    logic:
      'NOT_APPLICABLE when onPremisesSyncEnabled is not true. Read the "Password Rule Settings" directory setting; if absent, Microsoft defaults apply (enabled, Audit mode). PASS when EnableBannedPasswordCheckOnPremises is True and BannedPasswordCheckOnPremisesMode is Enforce. FAIL otherwise. Confidence is medium because DC agent deployment cannot be verified from tenant evidence.',
    parameters: {},
  },
  expectedState: 'Password protection for Windows Server Active Directory is enabled in Enforce mode, with the DC agent deployed on all domain controllers.',
  remediation: {
    summary: 'Deploy the Password Protection agents and switch the mode to Enforce.',
    steps: [
      'Install the Microsoft Entra Password Protection proxy service on two member servers and the DC agent on every domain controller.',
      'Review Audit-mode event logs (Microsoft-AzureADPasswordProtection-DCAgent/Admin) to understand impact.',
      'In Entra ID > Authentication methods > Password protection set "Enable password protection on Windows Server Active Directory" to Yes and Mode to Enforced.',
    ],
    effort: 'medium',
  },
  implementationConsiderations: [
    'Enforcement applies only to password changes and resets, not existing passwords.',
    'Users will be rejected when choosing banned passwords; update help desk guidance.',
  ],
  impact: 'Weak passwords are rejected when users change or reset them in Active Directory.',
  rollback: ['Set the mode back to Audit in Authentication methods > Password protection.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm HYB-PWD-001 is PASS.', 'After a test password change with a banned password, confirm the DC agent Admin event log (Microsoft-AzureADPasswordProtection-DCAgent/Admin) records the rejection.'],
  references: [REF.passwordProtectionOnPrem],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5(1)' },
    { framework: 'MCSB', id: 'IM-6' },
    { framework: 'MITRE-ATTACK', id: 'T1110.003' },
  ],
  tags: ['hybrid', 'identity', 'credential-exposure'],
  applies: syncEnabled,
  evaluate: (ctx) => {
    const settings = ctx.data('entra.groupSettings').find((s) => eqi(s.displayName, 'Password Rule Settings'));
    const value = (name: string, fallback: string) => settings?.values.find((v) => eqi(v.name, name))?.value ?? fallback;
    const enabled = value('EnableBannedPasswordCheckOnPremises', 'True');
    const mode = value('BannedPasswordCheckOnPremisesMode', 'Audit');
    const facts = [
      fact('Settings object present', settings !== undefined),
      fact('Enabled on-premises', enabled),
      fact('Mode', mode),
    ];
    const notes = settings === undefined ? ['No Password Rule Settings object exists, so Microsoft defaults apply (enabled, Audit mode).'] : [];
    if (eqi(enabled, 'true') && eqi(mode, 'enforce')) {
      return pass({ reason: 'Password protection for Active Directory is enabled in Enforce mode.', summary: 'On-premises password protection is enforced.', facts, notes });
    }
    return fail({
      reason: eqi(enabled, 'true') ? `Password protection for Active Directory is in ${mode} mode.` : 'Password protection for Active Directory is disabled.',
      summary: 'Weak passwords are not blocked in Active Directory.',
      facts,
      notes,
    });
  },
});
