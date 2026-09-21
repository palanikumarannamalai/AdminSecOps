import { ca } from '@adminsecops/inventory';
import type { ConditionalAccessPolicy } from '@adminsecops/schemas';
import { defineControl } from '../../define.js';
import { affected, fact, pass, plural, review } from '../../helpers.js';
import { REF } from '../../references.js';
import { INTUNE_REF } from './references.js';

type Policy = ConditionalAccessPolicy;

const DEVICE_CONTROLS = ['compliantdevice', 'domainjoineddevice'];

/**
 * How a Conditional Access policy requires a managed device:
 * - 'required': a compliant or hybrid joined device is always needed (AND, or OR
 *   between the two device controls only);
 * - 'alternative': a device control is OR-ed with a non-device control such as MFA,
 *   so unmanaged devices can still get access;
 * - 'none': the policy does not use a device control.
 */
export function deviceRequirement(policy: Policy): 'required' | 'alternative' | 'none' {
  const grant = policy.grantControls;
  if (grant === null) return 'none';
  const controls = grant.builtInControls.map((c) => c.toLowerCase());
  if (!controls.some((c) => DEVICE_CONTROLS.includes(c))) return 'none';
  if (grant.operator.toUpperCase() === 'AND') return 'required';
  if (grant.operator.toUpperCase() !== 'OR') return 'alternative';
  const others =
    controls.filter((c) => !DEVICE_CONTROLS.includes(c)).length +
    grant.customAuthenticationFactors.length +
    grant.termsOfUse.length;
  return others === 0 ? 'required' : 'alternative';
}

function targetsAllOrOffice365(policy: Policy): boolean {
  return (
    ca.includesAllApps(policy) ||
    (policy.conditions.applications.excludeApplications.length === 0 && policy.conditions.applications.includeApplications.some((a) => a.toLowerCase() === 'office365'))
  );
}

export const intuneCaRequireCompliantDevice = defineControl({
  id: 'INTUNE-CA-001',
  version: '1.0.1',
  lifecycle: 'stable',
  title: 'Conditional Access requires a compliant or hybrid joined device',
  technology: 'intune',
  category: 'Device management',
  subcategory: 'Conditional Access',
  description:
    'When devices are enrolled in Intune, checks whether an enabled Conditional Access policy uses the device compliance result, requiring a compliant (or Microsoft Entra hybrid joined) device for all users to access all resources or Office 365.',
  rationale:
    'Intune compliance policies only report whether a device meets your requirements; they do not by themselves stop a noncompliant or unmanaged device from reaching company data. Conditional Access is what enforces the result. Without it, a stolen password can be used from any device, and compliance findings such as missing encryption have no effect on access.',
  severity: 'medium',
  confidence: 'high',
  applicability: {
    description:
      'Tenants with devices enrolled in Intune. NOT_APPLICABLE when no devices are enrolled or the collector reports Intune as not available.',
  },
  requiredEvidence: ['intune.deviceOverview'],
  optionalEvidence: ['entra.conditionalAccessPolicies', 'intune.settings'],
  evaluation: {
    logic:
      'NOT_APPLICABLE when no devices are enrolled. Reads Conditional Access policies (NOT_ASSESSED if they could not be collected for a reason other than licensing). PASS when an enabled policy includes all users, targets all resources or Office 365, has no platform, location or risk conditions that narrow it, and always requires a compliant or hybrid joined device (AND, or OR only between those two device controls). REVIEW in every other case - device-based policies that are report-only, scoped, narrowed, or that allow MFA as an alternative; no device-based policy at all; or Conditional Access not licensed - because requiring managed devices for everyone is a deliberate design decision (for example organizations with personal devices often use app protection policies or MFA instead), which AdminSecOps cannot make for you.',
    parameters: {},
  },
  expectedState:
    'An enabled Conditional Access policy requires a compliant or hybrid joined device for all users (emergency access accounts excluded) and all resources, or the organization has documented why a different approach (for example app protection policies for personal devices) is used.',
  remediation: {
    summary:
      'Create a Conditional Access policy that requires a compliant or hybrid joined device, starting in report-only mode.',
    steps: [
      'Assign compliance policies to every platform (INTUNE-CMP-002) and set devices without a policy to Not compliant (INTUNE-CMP-001).',
      'In the Microsoft Entra admin center go to Entra ID > Conditional Access > Policies > New policy.',
      'Users: include All users and exclude your emergency access accounts. Target resources: All resources (or Office 365 as a first step).',
      'Grant: select "Require device to be marked as compliant" (and optionally "Require Microsoft Entra hybrid joined device" with "Require one of the selected controls").',
      'Set the policy to Report-only, review the impact with the Conditional Access insights, then set it to On.',
    ],
    effort: 'high',
  },
  implementationConsiderations: [
    'Users on personal or unenrolled devices lose access unless you provide an alternative (for example a separate policy using app protection policies for mobile apps, or browser-only access).',
    'Device registration and Intune enrollment are not blocked by a compliant-device requirement, so new devices can still be enrolled.',
    'Linux and unsupported platforms cannot be marked compliant through Intune in every scenario; consider blocking unknown platforms explicitly.',
    'Always exclude emergency access accounts and test with report-only mode first.',
  ],
  impact:
    'Only compliant (or hybrid joined) devices can access the targeted resources; other devices are blocked.',
  rollback: ['Set the Conditional Access policy to Report-only or Off.'],
  validation: [
    'Re-run the AdminSecOps collectors and confirm INTUNE-CA-001 is PASS, or that the REVIEW finding reflects a documented decision.',
    'Use the Conditional Access What If tool for a standard user and confirm the policy applies with the compliant-device grant.',
  ],
  references: [
    INTUNE_REF.caAllUsersDeviceCompliance,
    INTUNE_REF.caRequireCompliantDevice,
    INTUNE_REF.complianceOverview,
    REF.emergencyAccess,
    REF.attackValidAccounts,
  ],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-19' },
    { framework: 'MCSB', id: 'IM-7' },
    { framework: 'MITRE-ATTACK', id: 'T1078.004' },
  ],
  tags: ['conditional-access', 'device-compliance', 'intune', 'identity'],
  applies: (ctx) =>
    ctx.data('intune.deviceOverview').enrolledDeviceCount > 0
      ? { applicable: true }
      : { applicable: false, reason: 'No devices are enrolled in Intune.' },
  evaluate: (ctx) => {
    const overview = ctx.data('intune.deviceOverview');
    const settings = ctx.fact('intune.settings');
    const notes: string[] = [];
    if (settings.available && !settings.data.secureByDefault) {
      notes.push(
        'Devices without a compliance policy are currently marked Compliant (INTUNE-CMP-001), so a compliant-device requirement does not stop devices that no compliance policy targets.',
      );
    }
    const caFact = ctx.fact('entra.conditionalAccessPolicies');
    if (!caFact.available && caFact.collectionStatus === 'NotApplicable') {
      return review({
        reason:
          'Devices are enrolled in Intune, but the collector reported that Conditional Access is not available (no Microsoft Entra ID P1 licence), so device compliance cannot be enforced at sign-in. Decide whether device-based access control is required and license Conditional Access if so.',
        summary: 'Device compliance is not enforced by Conditional Access.',
        facts: [
          fact('Enrolled devices', overview.enrolledDeviceCount),
          fact('Conditional Access available', false),
        ],
        notes,
      });
    }
    const policies = ctx.data('entra.conditionalAccessPolicies');
    const candidates = policies.filter((p) => deviceRequirement(p) !== 'none');
    const enforcing = candidates.filter(
      (p) =>
        ca.isEnabled(p) &&
        deviceRequirement(p) === 'required' &&
        ca.includesAllUsers(p) &&
        targetsAllOrOffice365(p) &&
        ca.hasNoNarrowingConditions(p),
    );
    const facts = [
      fact('Enrolled devices', overview.enrolledDeviceCount),
      fact('Conditional Access policies', policies.length),
      fact('Policies using a device grant control', candidates.length),
      fact('Enabled all-user policies requiring a managed device', enforcing.length),
    ];
    if (enforcing.length > 0) {
      for (const p of enforcing) {
        const ex = ca.exclusions(p);
        if (ex.total > 0) {
          notes.push(
            `Policy "${p.displayName}" excludes ${plural(ex.users, 'user')}, ${plural(ex.groups, 'group')} and ${plural(ex.roles, 'role')}${ex.guestsOrExternal ? ' plus guest/external user types' : ''}. Confirm the exclusions are intended.`,
          );
        }
      }
      return pass({
        reason: `An enabled Conditional Access policy requires a compliant or hybrid joined device for included users (${enforcing.map((p) => `"${p.displayName}"`).join(', ')}).`,
        summary: 'A compliant or hybrid joined device is required for the policy targets, subject to its exclusions.',
        facts,
        notes: [...notes, 'Hybrid joined status does not prove Intune compliance. A hybrid-joined alternative can admit a noncompliant device; Office 365 scope does not cover every resource.'],
      });
    }
    if (candidates.length > 0) {
      return review({
        reason: `${plural(candidates.length, 'Conditional Access policy', 'Conditional Access policies')} use device compliance, but none requires a compliant or hybrid joined device for all users and resources without exceptions (report-only, scoped to some users, apps or platforms, or MFA allowed as an alternative). Confirm this matches your intended design.`,
        summary: 'Device compliance is only partly enforced by Conditional Access.',
        facts,
        affectedObjects: candidates
          .sort((a, b) => a.displayName.localeCompare(b.displayName))
          .map((p) =>
            affected(
              'conditionalAccessPolicy',
              p.id,
              p.displayName,
              `state=${p.state}; device requirement=${deviceRequirement(p)}; all users=${ca.includesAllUsers(p)}; all resources or Office 365=${targetsAllOrOffice365(p)}; narrowed=${!ca.hasNoNarrowingConditions(p)}`,
            ),
          ),
        notes,
      });
    }
    return review({
      reason:
        'Devices are enrolled in Intune but no Conditional Access policy requires a compliant or hybrid joined device, so compliance results do not affect access. Requiring managed devices is a design decision (organizations with personal devices may rely on app protection policies or MFA instead); confirm and document the approach.',
      summary: 'No Conditional Access policy uses device compliance.',
      facts,
      notes,
    });
  },
});
