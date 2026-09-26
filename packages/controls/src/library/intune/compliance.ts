import type { AffectedObject } from '@adminsecops/schemas';
import { defineControl } from '../../define.js';
import { affected, fact, fail, notAssessed, pass, plural, review } from '../../helpers.js';
import { INTUNE_REF } from './references.js';
import {
  deviceCount,
  isAssigned,
  isAssignedBroadly,
  isWindows10Policy,
  PLATFORM_LABELS,
  PLATFORMS,
  policyPlatform,
  type CompliancePolicy,
  type Platform,
} from './platforms.js';

function policyObject(policy: CompliancePolicy, detail: string): AffectedObject {
  return affected('compliancePolicy', policy.id, policy.displayName, detail);
}

const byName = (a: CompliancePolicy, b: CompliancePolicy) =>
  a.displayName.localeCompare(b.displayName);

export const intuneNoPolicyNoncompliant = defineControl({
  id: 'INTUNE-CMP-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Devices without a compliance policy are marked not compliant',
  technology: 'intune',
  category: 'Device management',
  subcategory: 'Compliance',
  description:
    'Checks the tenant-wide Intune compliance setting "Mark devices with no compliance policy assigned as" (secureByDefault). When it is set to Compliant, enrolled devices that receive no compliance policy are reported as compliant.',
  rationale:
    'Conditional Access policies that require a compliant device trust the compliance state that Intune reports. With the default value (Compliant), any device that is not targeted by a compliance policy - for example because of a gap in group assignments or a new platform - is treated as compliant without any checks and can access company resources. Setting it to Not compliant makes coverage gaps fail closed and visible in the "Devices without compliance policy" report.',
  severity: 'medium',
  confidence: 'high',
  applicability: {
    description:
      'Tenants using Microsoft Intune. The control is NOT_APPLICABLE when the collector reports Intune as not available.',
  },
  requiredEvidence: ['intune.settings'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'PASS when secureByDefault is true (devices with no compliance policy are marked Not compliant). FAIL when it is false (the default: such devices are marked Compliant).',
    parameters: {},
  },
  expectedState: '"Mark devices with no compliance policy assigned as" is set to Not compliant.',
  remediation: {
    summary:
      'Change the tenant-wide compliance policy setting so devices without a compliance policy are marked Not compliant.',
    steps: [
      'Before changing the setting, check the "Devices without compliance policy" report (Intune admin center > Reports > Device compliance) and assign compliance policies to every platform in use (see INTUNE-CMP-002).',
      'In the Microsoft Intune admin center go to Endpoint security > Device compliance > Compliance policy settings.',
      'Set "Mark devices with no compliance policy assigned as" to Not compliant and select Save.',
    ],
    effort: 'low',
  },
  implementationConsiderations: [
    'Devices that currently have no compliance policy become noncompliant. If Conditional Access requires compliant devices, those users lose access until a policy is assigned, so close the assignment gaps first.',
    'Microsoft recommends Not compliant whenever compliance is used with Conditional Access.',
  ],
  impact:
    'Enrolled devices without an assigned compliance policy show as Not compliant and are blocked by Conditional Access policies that require compliance.',
  rollback: [
    'Set "Mark devices with no compliance policy assigned as" back to Compliant in Endpoint security > Device compliance > Compliance policy settings.',
  ],
  validation: [
    'Re-run the AdminSecOps Intune collector and confirm INTUNE-CMP-001 is PASS.',
    'Check the Devices without compliance policy report and confirm it lists no unexpected devices.',
  ],
  references: [INTUNE_REF.complianceOverview, INTUNE_REF.caAllUsersDeviceCompliance],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'CM-6' },
    { framework: 'NIST-800-53r5', id: 'AC-19' },
  ],
  tags: ['device-compliance', 'intune', 'conditional-access'],
  evaluate: (ctx) => {
    const settings = ctx.data('intune.settings');
    const facts = [
      fact(
        'Devices with no compliance policy marked Not compliant (secureByDefault)',
        settings.secureByDefault,
      ),
      fact(
        'Compliance status validity period (days)',
        settings.deviceComplianceCheckinThresholdDays,
      ),
    ];
    if (settings.secureByDefault) {
      return pass({
        reason: 'Devices without an assigned compliance policy are marked Not compliant.',
        summary: 'Compliance coverage gaps fail closed.',
        facts,
      });
    }
    return fail({
      reason:
        'Devices without an assigned compliance policy are marked Compliant (the default), so they pass device-compliance checks without being evaluated.',
      summary: 'Devices that receive no compliance policy are treated as compliant.',
      facts,
    });
  },
});

export const intunePlatformCoverage = defineControl({
  id: 'INTUNE-CMP-002',
  version: '1.0.1',
  lifecycle: 'stable',
  title: 'Every platform with enrolled devices has an assigned compliance policy',
  technology: 'intune',
  category: 'Device management',
  subcategory: 'Compliance',
  description:
    'Compares the enrolled device counts per platform (Windows, macOS, iOS/iPadOS, Android) with the device compliance policies that are assigned, and identifies platforms whose devices are not covered by any assigned compliance policy.',
  rationale:
    'A compliance policy defines the minimum security state (encryption, OS version, password, threat level) a device must meet to be trusted. Enrolled devices on a platform without an assigned compliance policy are never evaluated; depending on the tenant setting they are either treated as compliant without any checks or blocked unexpectedly.',
  severity: 'high',
  confidence: 'high',
  applicability: {
    description: 'Tenants using Microsoft Intune with at least one enrolled device.',
  },
  requiredEvidence: ['intune.deviceOverview', 'intune.compliancePolicies'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'NOT_APPLICABLE when no devices are enrolled. Each compliance policy is mapped to a platform from its OData type (windows10/windows81 -> Windows; macOS; iOS; android, androidWorkProfile, androidDeviceOwner, aospDeviceOwner -> Android). A policy counts as assigned only with a recognized include target (group, all devices or all licensed users). Enrolled devices with no supported platform counts are NOT_ASSESSED. FAIL when a platform with enrolled devices has no assigned policy, listing each platform and its device count. PASS otherwise. Notes identify platforms covered only through group assignments (coverage of every device cannot be confirmed from assignments alone), policies with no assignments, and enrolled Linux devices (Linux compliance is configured in the settings catalog and is not evaluated).',
    parameters: {},
  },
  expectedState:
    'Every platform with enrolled devices has at least one compliance policy assigned to all its users or devices.',
  remediation: {
    summary: 'Create and assign a compliance policy for each listed platform.',
    steps: [
      'In the Microsoft Intune admin center go to Devices > Manage devices > Compliance and select Create policy.',
      'Choose the platform listed in the finding and configure at least the baseline requirements (for example encryption, minimum OS version, password or device lock, and threat level if Microsoft Defender for Endpoint is integrated).',
      'Under Assignments, assign the policy to All users or All devices (or to groups that include every user or device of that platform).',
      'Monitor the policy status and the Devices without compliance policy report.',
    ],
    effort: 'medium',
  },
  implementationConsiderations: [
    'New requirements can make devices noncompliant; use the "Actions for noncompliance" grace period and communicate with users before Conditional Access enforces compliance.',
    'When several compliance policies apply to a device, Intune uses the most restrictive setting.',
    'Android has several management modes (device administrator, work profile, fully managed, AOSP); each needs a policy of the matching type.',
  ],
  impact:
    'Devices on the listed platforms are evaluated against the new policy and may become noncompliant until they meet it.',
  rollback: ['Unassign or delete the compliance policy in Devices > Compliance.'],
  validation: [
    'Re-run the AdminSecOps Intune collector and confirm INTUNE-CMP-002 is PASS.',
    'In Devices > Compliance, confirm each platform has an assigned policy and check its device status report.',
  ],
  references: [
    INTUNE_REF.complianceOverview,
    INTUNE_REF.createCompliancePolicy,
    INTUNE_REF.graphCompliancePolicy,
  ],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'CM-6' },
    { framework: 'NIST-800-53r5', id: 'AC-19' },
  ],
  tags: ['device-compliance', 'intune'],
  applies: (ctx) =>
    ctx.data('intune.deviceOverview').enrolledDeviceCount > 0
      ? { applicable: true }
      : { applicable: false, reason: 'No devices are enrolled in Intune.' },
  evaluate: (ctx) => {
    const overview = ctx.data('intune.deviceOverview');
    const policies = ctx.data('intune.compliancePolicies');
    const assignedByPlatform = new Map<Platform, CompliancePolicy[]>();
    for (const policy of policies) {
      const platform = policyPlatform(policy);
      if (platform === null || !isAssigned(policy)) continue;
      assignedByPlatform.set(platform, [...(assignedByPlatform.get(platform) ?? []), policy]);
    }
    const inUse = PLATFORMS.filter((p) => deviceCount(overview, p) > 0);
    if (inUse.length === 0) return notAssessed({ reason: 'Devices are enrolled but no supported platform counts were reported; platform coverage cannot be established.', summary: 'Device platform coverage is unknown.' });
    const uncovered = inUse.filter((p) => (assignedByPlatform.get(p) ?? []).length === 0);
    const groupOnly = inUse.filter((p) => {
      const assigned = assignedByPlatform.get(p) ?? [];
      return assigned.length > 0 && !assigned.some(isAssignedBroadly);
    });
    const unassigned = policies.filter((p) => !isAssigned(p)).sort(byName);
    const facts = [
      fact('Enrolled devices', overview.enrolledDeviceCount),
      ...inUse.map((p) => fact(`${PLATFORM_LABELS[p]} devices`, deviceCount(overview, p))),
      fact('Compliance policies', policies.length),
      fact('Platforms in use without an assigned policy', uncovered.length),
    ];
    const notes: string[] = [];
    if (groupOnly.length > 0) {
      notes.push(
        `${groupOnly.map((p) => PLATFORM_LABELS[p]).join(', ')} ${groupOnly.length === 1 ? 'is' : 'are'} covered only by group-assigned policies; confirm the groups include every user or device on that platform (see the Devices without compliance policy report).`,
      );
    }
    if (unassigned.length > 0) {
      notes.push(
        `${plural(unassigned.length, 'compliance policy', 'compliance policies')} have no assignments: ${unassigned.map((p) => p.displayName).join(', ')}.`,
      );
    }
    notes.push(
      'Linux devices are not counted by the Intune managed device overview and Linux compliance policies (settings catalog) are not evaluated by this control.',
    );
    if (uncovered.length > 0) {
      return fail({
        reason: `${plural(uncovered.length, 'platform')} with enrolled devices ${uncovered.length === 1 ? 'has' : 'have'} no assigned compliance policy: ${uncovered.map((p) => PLATFORM_LABELS[p]).join(', ')}.`,
        summary: `Enrolled devices on ${uncovered.map((p) => PLATFORM_LABELS[p]).join(', ')} are not evaluated by any compliance policy.`,
        facts,
        affectedObjects: uncovered.map((p) =>
          affected(
            'devicePlatform',
            p,
            PLATFORM_LABELS[p],
            `${plural(deviceCount(overview, p), 'enrolled device')}; no assigned compliance policy`,
          ),
        ),
        notes,
      });
    }
    return pass({
      reason: `Every counted platform with enrolled devices (${inUse.map((p) => PLATFORM_LABELS[p]).join(', ')}) has at least one assigned compliance policy.`,
      summary: 'Policy assignments exist for the counted platforms; per-device applicability is not verified.',
      facts,
      notes,
    });
  },
});

export const intuneWindowsBitLocker = defineControl({
  id: 'INTUNE-CMP-003',
  version: '1.0.1',
  lifecycle: 'stable',
  title: 'An assigned Windows compliance policy requires BitLocker',
  technology: 'intune',
  category: 'Device management',
  subcategory: 'Compliance',
  description:
    'Checks that at least one assigned Windows 10/11 compliance policy has "Require BitLocker" enabled, so that Windows devices without BitLocker drive encryption are reported as noncompliant.',
  rationale:
    'A lost or stolen laptop without drive encryption exposes cached email, files and credentials to anyone with physical access. Requiring BitLocker in a compliance policy makes unencrypted Windows devices noncompliant, which lets Conditional Access keep them away from company data until they are encrypted.',
  severity: 'medium',
  confidence: 'high',
  applicability: {
    description:
      'Tenants using Microsoft Intune. NOT_APPLICABLE when the device overview shows no enrolled Windows devices.',
  },
  requiredEvidence: ['intune.compliancePolicies'],
  optionalEvidence: ['intune.deviceOverview'],
  evaluation: {
    logic:
      'NOT_APPLICABLE when the optional device overview is available and reports zero Windows devices. Considers Windows 10/11 compliance policies (windows10CompliancePolicy) with at least one recognized include assignment. PASS when any of them has bitLockerEnabled = true ("Require BitLocker", validated through device health attestation). REVIEW when none does but one requires "Encryption of data storage on device" (storageRequireEncryption): that setting checks for encryption without health attestation, and whether it is sufficient is an administrator decision. FAIL when no assigned Windows policy requires either.',
    parameters: {},
  },
  expectedState:
    'A Windows compliance policy assigned to all Windows devices (or their users) has Device Health > Require BitLocker set to Require.',
  remediation: {
    summary:
      'Enable "Require BitLocker" in the Windows compliance policy assigned to your Windows devices, after BitLocker is deployed.',
    steps: [
      'Deploy BitLocker first, for example with an Endpoint security > Disk encryption policy, and confirm devices report as encrypted.',
      'In the Microsoft Intune admin center go to Devices > Manage devices > Compliance and open the Windows 10 and later policy assigned to your devices (or create one).',
      'Under Device Health > Windows Health Attestation Service evaluation rules, set Require BitLocker to Require. Save.',
      'Confirm the policy is assigned to all Windows users or devices.',
    ],
    effort: 'medium',
  },
  implementationConsiderations: [
    'BitLocker status is measured at boot through device health attestation; after encryption completes, a restart is needed before the device reports compliant.',
    'Devices that cannot reach the Microsoft attestation service endpoints become noncompliant; check network and TLS-inspection exclusions.',
    'Enable a grace period in the actions for noncompliance so users have time to restart before Conditional Access blocks them.',
  ],
  impact:
    'Windows devices without BitLocker are marked noncompliant and, with Conditional Access, lose access to company resources until encrypted.',
  rollback: ['Set Require BitLocker back to Not configured in the Windows compliance policy.'],
  validation: [
    'Re-run the AdminSecOps Intune collector and confirm INTUNE-CMP-003 is PASS.',
    'In the policy device status report, confirm the BitLocker setting reports compliant for encrypted devices.',
  ],
  references: [
    INTUNE_REF.windowsComplianceSettings,
    INTUNE_REF.createCompliancePolicy,
    INTUNE_REF.complianceOverview,
  ],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'SC-28' },
    { framework: 'NIST-800-53r5', id: 'SC-28(1)' },
    { framework: 'NIST-800-53r5', id: 'AC-19(5)' },
  ],
  tags: ['device-compliance', 'intune', 'encryption', 'bitlocker', 'windows'],
  applies: (ctx) => {
    const overview = ctx.fact('intune.deviceOverview');
    if (overview.available && overview.data.windowsCount === 0) {
      return { applicable: false, reason: 'No Windows devices are enrolled in Intune.' };
    }
    return { applicable: true };
  },
  evaluate: (ctx) => {
    const policies = ctx.data('intune.compliancePolicies');
    const windows = policies.filter(isWindows10Policy);
    const assigned = windows.filter(isAssigned).sort(byName);
    const bitLocker = assigned.filter((p) => p.settings.bitLockerEnabled === true);
    const storageOnly = assigned.filter(
      (p) => p.settings.bitLockerEnabled !== true && p.settings.storageRequireEncryption === true,
    );
    const facts = [
      fact('Windows 10/11 compliance policies', windows.length),
      fact('Assigned Windows 10/11 compliance policies', assigned.length),
      fact('Assigned policies requiring BitLocker', bitLocker.length),
      fact('Assigned policies requiring storage encryption only', storageOnly.length),
    ];
    if (bitLocker.length > 0) {
      const notes = bitLocker.some(isAssignedBroadly)
        ? []
        : [
            'The policies that require BitLocker are assigned to specific groups only; confirm the groups include every Windows device or user.',
          ];
      return pass({
        reason: `BitLocker is required by ${bitLocker.map((p) => `"${p.displayName}"`).join(', ')}.`,
        summary: 'An assigned Windows compliance policy requires BitLocker.',
        facts,
        notes,
      });
    }
    if (storageOnly.length > 0) {
      return review({
        reason:
          'No assigned Windows policy uses "Require BitLocker", but encryption of data storage is required. That setting checks for encryption without device health attestation; decide whether it meets your requirement or switch to Require BitLocker.',
        summary: 'Windows encryption is required, but not through the attested BitLocker check.',
        facts,
        affectedObjects: storageOnly.map((p) =>
          policyObject(p, 'storageRequireEncryption=true; bitLockerEnabled not required'),
        ),
      });
    }
    if (assigned.length === 0) {
      return fail({
        reason:
          'No Windows 10/11 compliance policy is assigned, so BitLocker is not required on any Windows device.',
        summary: 'Windows devices are not evaluated for BitLocker encryption.',
        facts,
        affectedObjects: windows
          .sort(byName)
          .map((p) => policyObject(p, 'Windows compliance policy with no include assignment')),
      });
    }
    return fail({
      reason: `None of the ${plural(assigned.length, 'assigned Windows compliance policy', 'assigned Windows compliance policies')} requires BitLocker or storage encryption.`,
      summary: 'Unencrypted Windows devices can be reported as compliant.',
      facts,
      affectedObjects: assigned.map((p) => policyObject(p, 'Require BitLocker is not configured')),
    });
  },
});
