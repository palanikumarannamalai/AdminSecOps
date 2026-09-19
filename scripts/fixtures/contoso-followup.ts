/**
 * Contoso follow-up assessment, ~30 days after the initial one, after partial
 * remediation. Starts from the initial Contoso data and applies the changes the
 * administrators made, so the comparison/drift demo has resolved, unchanged and
 * new findings.
 *
 * Fixed: MFA for all users enforced (CA001 switched from report-only to On, which
 * also covers every administrator role); user consent restricted to low-risk
 * permissions from verified publishers; the admin without MFA registered;
 * external mailbox forwarding removed; one SMTP AUTH exception removed; anonymous
 * blob access disabled on the production web storage account; the Internet RDP NSG
 * rule removed; KRBTGT password reset; manager approval required on the ESC1
 * template.
 * New issue: the legacy authentication block policy (CA003) was switched to
 * report-only while troubleshooting a line-of-business application.
 * Newly collected: entra.onPremisesSynchronization (the collecting account was
 * granted Hybrid Identity Administrator), which reveals that soft matching is not
 * blocked. The service principal listing completed this time.
 */
import { Clock, type EnvironmentFixture, guid } from './common.js';
import { CA_POLICY } from './contoso/entra.js';
import { USERS } from './contoso/identity.js';
import { contosoData, contosoEnvironment } from './contoso/index.js';
import { ESC1_TEMPLATE } from './contoso/onprem.js';

export const CONTOSO_FOLLOWUP_ASSESSMENT_ID = guid('contoso:assessment:2026-09');

export function contosoFollowupEnvironment(): EnvironmentFixture {
  const clock = Clock.of('2026-09-09T09:40:00Z');
  const data = contosoData(clock);
  const { entra, m365, azure, onPrem } = data;

  for (const policy of entra.conditionalAccessPolicies) {
    if (policy.id === CA_POLICY.mfaAllUsers) {
      policy.state = 'enabled';
      policy.modifiedDateTime = '2026-08-19T07:02:41Z';
    }
    if (policy.id === CA_POLICY.blockLegacy) {
      policy.state = 'enabledForReportingButNotEnforced';
      policy.modifiedDateTime = '2026-09-02T16:48:05Z';
    }
  }

  entra.authorizationPolicy.permissionGrantPolicyIdsAssignedToDefaultUserRole = [
    'ManagePermissionGrantsForSelf.microsoft-user-default-low',
  ];

  for (const row of entra.userRegistrationDetails) {
    if (row.id === USERS.rileyMail.id) {
      row.isMfaRegistered = true;
      row.isMfaCapable = true;
      row.isSsprRegistered = true;
      row.methodsRegistered = ['microsoftAuthenticatorPush', 'softwareOneTimePasscode'];
    }
  }

  m365.mailboxForwarding = m365.mailboxForwarding.filter((m) => m.userPrincipalName !== USERS.robinSales.userPrincipalName);
  m365.smtpAuthMailboxes = m365.smtpAuthMailboxes.filter((m) => !m.userPrincipalName.startsWith('crm-notifications@'));

  for (const account of azure.storageAccounts) {
    if (account.name === 'stcontosowebprod') account.allowBlobPublicAccess = false;
  }
  for (const nsg of azure.networkSecurityGroups) {
    nsg.securityRules = (nsg.securityRules ?? []).filter((rule) => rule.name !== 'Allow-RDP-Temp');
  }

  onPrem.krbtgt = onPrem.krbtgt.map((k) => ({ ...k, pwdLastSet: '2026-08-24T19:02:11Z' }));
  for (const template of onPrem.certificateTemplates) {
    if (template.name === ESC1_TEMPLATE) template.enrollmentFlag = template.enrollmentFlag | 0x2;
  }

  return contosoEnvironment(data, {
    directory: 'contoso-followup',
    assessmentId: CONTOSO_FOLLOWUP_ASSESSMENT_ID,
    clock,
    label: 'Contoso (sample) - follow-up after remediation',
    onPremisesSynchronizationCollected: true,
    servicePrincipalsPartial: false,
  });
}
