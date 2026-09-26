import { daysBetween, parseTimestamp } from '@adminsecops/core';
import type { DatasetData } from '@adminsecops/schemas';
import { defineControl, type ControlContext } from '../../define.js';
import { affected, fact, fail, pass, plural, review } from '../../helpers.js';
import { REF } from '../../references.js';

const MICROSOFT_GRAPH_APP_ID = '00000003-0000-0000-c000-000000000000';
const EXCHANGE_ONLINE_APP_ID = '00000002-0000-0ff1-ce00-000000000000';

/**
 * Application permissions that allow taking control of the tenant (directory, roles,
 * applications, authentication policies). Values are Microsoft Graph app role names.
 */
export const CONTROL_PLANE_PERMISSIONS: ReadonlySet<string> = new Set(
  [
    'RoleManagement.ReadWrite.Directory',
    'AppRoleAssignment.ReadWrite.All',
    'Application.ReadWrite.All',
    'Directory.ReadWrite.All',
    'Domain.ReadWrite.All',
    'Policy.ReadWrite.ConditionalAccess',
    'Policy.ReadWrite.AuthenticationMethod',
    'UserAuthenticationMethod.ReadWrite.All',
    'PrivilegedAccess.ReadWrite.AzureAD',
    'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup',
    'Organization.ReadWrite.All',
    'User.ReadWrite.All',
    'Group.ReadWrite.All',
  ].map((p) => p.toLowerCase()),
);

/** Application permissions that grant tenant-wide access to content. */
export const DATA_ACCESS_PERMISSIONS: ReadonlySet<string> = new Set(
  [
    'Mail.Read',
    'Mail.ReadWrite',
    'Mail.Send',
    'MailboxSettings.ReadWrite',
    'Files.Read.All',
    'Files.ReadWrite.All',
    'Sites.Read.All',
    'Sites.ReadWrite.All',
    'Sites.FullControl.All',
    'Chat.Read.All',
    'ChannelMessage.Read.All',
    'Notes.Read.All',
    'full_access_as_app',
  ].map((p) => p.toLowerCase()),
);

interface Grant {
  principalId: string;
  principalName: string;
  permission: string;
  resource: string;
}

function grants(data: DatasetData<'entra.apiPermissionGrants'>, allowed: ReadonlySet<string>): Grant[] {
  const out: Grant[] = [];
  for (const resource of data) {
    const appId = resource.resourceAppId.toLowerCase();
    if (appId !== MICROSOFT_GRAPH_APP_ID && appId !== EXCHANGE_ONLINE_APP_ID) continue;
    const roles = new Map(resource.appRoles.map((r) => [r.id.toLowerCase(), r.value ?? r.id]));
    for (const a of resource.assignments) {
      const permission = roles.get(a.appRoleId.toLowerCase());
      if (permission === undefined || !allowed.has(permission.toLowerCase())) continue;
      out.push({ principalId: a.principalId, principalName: a.principalDisplayName ?? a.principalId, permission, resource: resource.resourceDisplayName });
    }
  }
  return out;
}

function groupByPrincipal(list: readonly Grant[]) {
  const map = new Map<string, { name: string; permissions: string[] }>();
  for (const g of list) {
    const entry = map.get(g.principalId) ?? { name: g.principalName, permissions: [] };
    entry.permissions.push(`${g.permission} (${g.resource})`);
    map.set(g.principalId, entry);
  }
  return [...map.entries()].map(([id, v]) => affected('servicePrincipal', id, v.name, v.permissions.sort().join(', ')));
}

function permissionControl(kind: 'control-plane' | 'data') {
  const controlPlane = kind === 'control-plane';
  return defineControl({
    id: controlPlane ? 'ENTRA-APP-004' : 'ENTRA-APP-005',
    version: '1.0.0',
    lifecycle: 'stable',
    title: controlPlane
      ? 'Applications with tenant-takeover application permissions are reviewed'
      : 'Applications with tenant-wide data access permissions are reviewed',
    technology: 'entra',
    category: 'Applications',
    subcategory: 'Application permissions',
    description: controlPlane
      ? 'Lists service principals granted Microsoft Graph application permissions that allow changing roles, applications, authentication policies or the directory itself.'
      : 'Lists service principals granted application permissions that read or write all mailboxes, files, sites or chats in the tenant.',
    rationale: controlPlane
      ? 'Application permissions work without a signed-in user and are not constrained by Conditional Access for users. An application holding, for example, RoleManagement.ReadWrite.Directory can grant itself Global Administrator. Attackers who obtain such an app\'s credentials control the tenant, so every such grant must be justified and its credentials tightly protected.'
      : 'Tenant-wide data permissions let an application read or change every user\'s mail, files or chats without their involvement. A compromised credential for such an app is equivalent to a mass data breach.',
    severity: controlPlane ? 'high' : 'medium',
    confidence: 'high',
    applicability: { description: 'All Microsoft Entra tenants.' },
    requiredEvidence: ['entra.apiPermissionGrants'],
    evaluation: {
      logic: `List service principals holding any of these application permissions on Microsoft Graph or Office 365 Exchange Online: ${[...(controlPlane ? CONTROL_PLANE_PERMISSIONS : DATA_ACCESS_PERMISSIONS)].join(', ')}. REVIEW when any exist (legitimate tools may need them; only the owner can judge), PASS when none exist.`,
      parameters: {},
    },
    expectedState: 'Only approved, documented applications hold these permissions, with certificate or managed identity credentials and a named owner.',
    remediation: {
      summary: 'Review each listed application, remove unnecessary permissions and protect the credentials of those that remain.',
      steps: [
        'For each application listed, identify the owner and the business need for each permission.',
        'Remove unneeded permissions in Entra ID > Enterprise apps > <app> > Permissions (revoke admin consent) and in the app registration API permissions.',
        controlPlane
          ? 'Prefer least-privileged permissions (for example User.Read.All instead of Directory.ReadWrite.All).'
          : 'Scope mailbox access with Exchange RBAC for Applications, and SharePoint access with Sites.Selected, instead of tenant-wide permissions.',
        'Replace client secrets with certificates or managed identities, and restrict who can manage the app (owners).',
      ],
      effort: 'medium',
    },
    implementationConsiderations: [
      'Removing a permission breaks the application functions that rely on it; coordinate with the application owner.',
      'Also check who owns these applications: application owners can add credentials and act as the app.',
    ],
    impact: 'Applications lose the removed permissions immediately after consent is revoked.',
    rollback: ['Grant admin consent for the permission again from the app registration API permissions page.'],
    validation: [`Re-run the AdminSecOps Entra collector and confirm ${controlPlane ? 'ENTRA-APP-004' : 'ENTRA-APP-005'} lists only approved applications.`],
    references: [REF.appPermissionRisk, REF.graphPermissionsReference],
    frameworkMappings: [
      { framework: 'NIST-800-53r5', id: 'AC-6' },
      { framework: 'NIST-800-53r5', id: 'AC-6(7)' },
      { framework: 'MCSB', id: 'IM-3' },
      { framework: 'MCSB', id: 'PA-7' },
      { framework: 'MITRE-ATTACK', id: controlPlane ? 'T1098' : 'T1528' },
    ],
    tags: controlPlane ? ['applications', 'privileged-access', 'identity'] : ['applications', 'data-exfiltration', 'identity'],
    evaluate: (ctx: ControlContext) => {
      const found = grants(ctx.data('entra.apiPermissionGrants'), controlPlane ? CONTROL_PLANE_PERMISSIONS : DATA_ACCESS_PERMISSIONS);
      const objects = groupByPrincipal(found);
      const facts = [fact('Applications with these permissions', objects.length), fact('Permission grants', found.length)];
      if (objects.length === 0) {
        return pass({ reason: 'No service principal holds these application permissions.', summary: 'No high-impact application permissions found.', facts });
      }
      return review({
        reason: `${plural(objects.length, 'application')} hold ${controlPlane ? 'tenant-takeover' : 'tenant-wide data'} application permissions; confirm each is approved.`,
        summary: `${plural(objects.length, 'application')} require review.`,
        facts,
        affectedObjects: objects,
      });
    },
  });
}

export const entraControlPlaneAppPermissions = permissionControl('control-plane');
export const entraDataAccessAppPermissions = permissionControl('data');

export const entraAppSecretLifetime = defineControl({
  id: 'ENTRA-APP-003',
  version: '1.0.2',
  lifecycle: 'stable',
  title: 'Application client secrets are short-lived',
  technology: 'entra',
  category: 'Applications',
  subcategory: 'Application credentials',
  description: 'Finds unexpired client secrets on app registrations whose total validity period exceeds the maximum lifetime.',
  rationale:
    'Client secrets are passwords for applications. Long-lived secrets are more likely to leak (in code, scripts or configuration files) and remain usable for years. Microsoft recommends certificates or managed identities and, where secrets are unavoidable, short lifetimes enforced by an application management policy.',
  severity: 'medium',
  confidence: 'high',
  applicability: { description: 'Tenants with application registrations.' },
  requiredEvidence: ['entra.applications'],
  evaluation: {
    logic:
      'For each unexpired password credential, compare its total validity to maxSecretLifetimeDays (default 180, aligned to CISA SCuBA MS.AAD.5.6v1). FAIL when exceeded; REVIEW for missing dates. This checks existing credentials, not enforcement of application management policies.',
    parameters: { maxSecretLifetimeDays: 180 },
  },
  expectedState: 'No active client secret is valid for more than 180 days; managed identity or federated/certificate credentials are preferred.',
  remediation: {
    summary: 'Rotate long-lived secrets to short-lived ones (or certificates) and enforce a maximum lifetime.',
    steps: [
      'For each listed application, add a new credential - preferably a certificate, or a secret valid for 6 months or less.',
      'Update the application configuration to use the new credential and confirm it works.',
      'Delete the long-lived secret from the app registration (Certificates & secrets).',
      'Configure an application management policy (Entra ID Workload ID) to enforce a maximum secret lifetime.',
    ],
    effort: 'medium',
  },
  implementationConsiderations: ['Removing a secret that is still in use breaks the application; confirm the new credential is deployed first.'],
  impact: 'Applications must be updated with new credentials before the old ones are removed.',
  rollback: ['Credentials cannot be restored once deleted; keep the old secret until the new one is proven.'],
  validation: ['Re-run the AdminSecOps Entra collector and confirm ENTRA-APP-003 is PASS.'],
  references: [REF.appCredentialBestPractices, REF.secretStandards],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5(1)' },
    { framework: 'MCSB', id: 'IM-3' },
    { framework: 'MITRE-ATTACK', id: 'T1552' },
  ],
  tags: ['applications', 'credential-exposure', 'identity'],
  evaluate: (ctx) => {
    const max = ctx.num('maxSecretLifetimeDays');
    const apps = ctx.data('entra.applications');
    const offenders: ReturnType<typeof affected>[] = [];
    let undated = 0;
    let activeSecrets = 0;
    for (const app of apps) {
      for (const secret of app.passwordCredentials) {
        const start = parseTimestamp(secret.startDateTime);
        const end = parseTimestamp(secret.endDateTime);
        if (end === undefined || start === undefined) {
          undated += 1;
          continue;
        }
        if (end.getTime() <= ctx.assessedAt.getTime()) continue;
        activeSecrets += 1;
        const lifetime = daysBetween(start, end);
        if (lifetime > max) {
          offenders.push(affected('application', app.appId, app.displayName, `Secret ${secret.displayName ?? secret.keyId} valid for ${lifetime} days (expires ${end.toISOString().slice(0, 10)})`));
        }
      }
    }
    const facts = [fact('Active client secrets', activeSecrets), fact('Exceeding maximum lifetime', offenders.length), fact('Maximum lifetime (days)', max)];
    const notes = undated > 0 ? [`${plural(undated, 'client secret')} had no validity dates in the evidence and were not evaluated.`] : [];
    if (offenders.length > 0) {
      return fail({ reason: `${plural(offenders.length, 'client secret')} are valid for more than ${max} days.`, summary: 'Long-lived application secrets exist.', facts, affectedObjects: offenders, notes });
    }
    if (undated > 0) return review({ reason: 'Some client secret validity dates are missing; their lifetimes cannot be established.', summary: 'Secret lifetime coverage is incomplete.', confidence: 'medium', facts, notes });
    return pass({ reason: `No active client secret is valid for more than ${max} days.`, summary: 'Application secrets are short-lived.', facts, notes });
  },
});
