import { defineControl } from '../../define.js';
import { affected, fact, fail, pass, plural } from '../../helpers.js';
import { GPO_REF } from './references.js';

export const gpoNoPreferencePasswords = defineControl({
  id: 'GPO-PWD-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'No Group Policy Preferences passwords (cpassword) are stored in SYSVOL',
  technology: 'gpo',
  category: 'Credential exposure',
  subcategory: 'Group Policy Preferences',
  description:
    'Checks that no Group Policy Preferences XML file in SYSVOL (Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Drives.xml, Printers.xml) contains a non-empty cpassword attribute.',
  rationale:
    'Group Policy Preferences used to let administrators embed passwords (for example to set local administrator passwords or run scheduled tasks). The password is encrypted with an AES key that Microsoft published, and SYSVOL is readable by every authenticated user, so any domain user can decrypt these passwords within seconds (MS14-025). Such passwords are frequently for local administrator or service accounts reused across many machines, giving an attacker immediate privilege escalation and lateral movement.',
  severity: 'critical',
  confidence: 'high',
  applicability: { description: 'Active Directory domains whose SYSVOL Policies folder was scanned by the collector.' },
  requiredEvidence: ['gpo.sysvolPasswordArtifacts'],
  optionalEvidence: ['gpo.groupPolicyObjects'],
  evaluation: {
    logic:
      'FAIL when the collector found one or more Group Policy Preferences XML files with a non-empty cpassword attribute; each file is listed with its domain, relative path and owning GPO (name resolved from gpo.groupPolicyObjects when available). PASS when no such file was found. The password value is never read into evidence.',
    parameters: {},
  },
  expectedState: 'No SYSVOL file contains a cpassword value; local administrator passwords are managed with Windows LAPS and service credentials with group Managed Service Accounts.',
  remediation: {
    summary: 'Treat every exposed password as compromised: change it everywhere it is used, then delete the preference items that contain it.',
    steps: [
      'For each file in the finding, identify the account whose password is embedded (open the GPO in Group Policy Management Editor > Preferences and find the item; the XML shows userName/runAs).',
      'Immediately change the password of that account on every system where it is used (for local accounts this usually means every computer the GPO applied to). Deploy Windows LAPS for local administrator accounts.',
      'In Group Policy Management Editor delete the preference item (Local Users and Groups, Services, Scheduled Tasks, Data Sources, Drives or Printers) that contains the password. After MS14-025 the editor no longer allows saving new passwords.',
      'Confirm the XML file no longer contains cpassword in \\\\<domain>\\SYSVOL\\<domain>\\Policies\\{GPO-GUID}\\...; also delete stale copies or backups of those files in SYSVOL.',
      'Review domain controller and endpoint logs for use of the exposed account since the file was created.',
    ],
    scriptExample:
      '# Review only: find preference files that still contain cpassword (run as a domain user)\n$policies = "\\\\$env:USERDNSDOMAIN\\SYSVOL\\$env:USERDNSDOMAIN\\Policies"\nGet-ChildItem $policies -Recurse -Include Groups.xml,Services.xml,ScheduledTasks.xml,DataSources.xml,Drives.xml,Printers.xml |\n  Select-String -Pattern \'cpassword="[^"]+"\' -List | Select-Object Path',
    effort: 'medium',
  },
  implementationConsiderations: [
    'Deleting the preference item does not change the password; the old password remains valid (and known) until you change it.',
    'Local administrator passwords set through Group Policy Preferences are usually identical on every machine; rotate them with Windows LAPS rather than another shared password.',
    'Scheduled tasks or services that used the embedded credential will stop working once the password changes; reconfigure them with a group Managed Service Account where possible.',
  ],
  impact: 'Removing the preference items stops Group Policy from re-applying the embedded credential; tasks and services configured with it must be reconfigured.',
  rollback: ['Restore the GPO from a GPMC backup if a non-password setting was removed by mistake. Do not re-introduce passwords in Group Policy Preferences.'],
  validation: [
    'Re-run the AdminSecOps Group Policy collector and confirm GPO-PWD-001 is PASS.',
    'Run the review script above and confirm it returns no files.',
  ],
  references: [GPO_REF.ms14025, GPO_REF.attackGppPasswords],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5(7)' },
    { framework: 'NIST-800-53r5', id: 'IA-5(1)' },
    { framework: 'MCSB', id: 'IM-8' },
    { framework: 'MITRE-ATTACK', id: 'T1552.006' },
  ],
  tags: ['credential-exposure', 'group-policy', 'sysvol', 'active-directory'],
  evaluate: (ctx) => {
    const scan = ctx.data('gpo.sysvolPasswordArtifacts');
    const gpos = ctx.fact('gpo.groupPolicyObjects');
    const gpoName = (id: string | null): string | null => {
      if (id === null || !gpos.available) return null;
      const bare = id.replace(/[{}]/g, '').toLowerCase();
      return gpos.data.find((g) => g.id.replace(/[{}]/g, '').toLowerCase() === bare)?.displayName ?? null;
    };
    const facts = [fact('Preference files scanned', scan.filesScanned), fact('Files containing cpassword', scan.artifacts.length)];
    if (scan.artifacts.length > 0) {
      return fail({
        reason: `${plural(scan.artifacts.length, 'Group Policy Preferences file')} in SYSVOL contain an embedded password that any domain user can decrypt.`,
        summary: `Passwords are exposed in SYSVOL in ${[...new Set(scan.artifacts.map((a) => a.domain))].join(', ')}.`,
        facts,
        affectedObjects: scan.artifacts.map((a) => {
          const name = gpoName(a.gpoId);
          return affected(
            'gppFile',
            `${a.domain}\\${a.relativePath}`,
            a.fileName,
            `GPO ${name !== null ? `"${name}" ` : ''}${a.gpoId ?? '(unknown GPO)'}; path Policies\\${a.relativePath}. Treat the embedded password as compromised.`,
          );
        }),
      });
    }
    return pass({
      reason: `No Group Policy Preferences file with a cpassword value was found (${plural(scan.filesScanned, 'file')} scanned).`,
      summary: 'No Group Policy Preferences passwords were found in SYSVOL.',
      facts,
      notes:
        scan.filesScanned === 0
          ? ['No Group Policy Preferences XML files were found in SYSVOL. Confirm the collector could read \\\\<domain>\\SYSVOL\\<domain>\\Policies.']
          : [],
    });
  },
});
