import type { Reference } from '@adminsecops/schemas';

/**
 * Group Policy references. Every URL was checked on Microsoft Learn / the publisher's
 * site when added. Titles are paraphrased.
 */
const ms = (title: string, url: string): Reference => ({ title, url, publisher: 'Microsoft' });
const mitre = (title: string, url: string): Reference => ({ title, url, publisher: 'MITRE' });
const LEARN = 'https://learn.microsoft.com/en-us';

export const GPO_REF = {
  ms14025: ms(
    'Microsoft Security Bulletin MS14-025: vulnerability in Group Policy Preferences could allow elevation of privilege',
    `${LEARN}/security-updates/securitybulletins/2014/ms14-025`,
  ),
  groupPolicyOverview: ms('Group Policy overview for Windows Server', `${LEARN}/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview`),
  groupPolicyProcessing: ms('Group Policy processing', `${LEARN}/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing`),
  gpmc: ms('Group Policy Management Console', `${LEARN}/windows-server/identity/ad-ds/manage/group-policy/group-policy-management-console`),

  attackGppPasswords: mitre(
    'MITRE ATT&CK T1552.006: Unsecured Credentials: Group Policy Preferences',
    'https://attack.mitre.org/techniques/T1552/006/',
  ),
  attackGroupPolicyModification: mitre(
    'MITRE ATT&CK T1484.001: Domain or Tenant Policy Modification: Group Policy Modification',
    'https://attack.mitre.org/techniques/T1484/001/',
  ),
} as const satisfies Record<string, Reference>;
