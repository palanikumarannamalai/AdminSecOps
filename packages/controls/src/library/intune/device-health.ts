import { defineControl } from '../../define.js';
import { affected, fact, fail, notAssessed, pass, review } from '../../helpers.js';
import { INTUNE_REF } from './references.js';
import { isAssigned, isAssignedBroadly, isWindows10Policy } from './platforms.js';

function healthControl(id: string, label: string, field: 'secureBootEnabled' | 'codeIntegrityEnabled') {
  return defineControl({
    id, version: '1.0.0', lifecycle: 'stable',
    title: `Assigned Windows compliance policies require ${label}`,
    technology: 'intune', category: 'Device management', subcategory: 'Device health',
    description: `Checks ${label} in assigned Windows compliance policies. This assesses policy requirements, not the actual health or effective assignment of every device.`,
    rationale: `${label} helps protect the Windows boot and execution environment. Requiring its attestation in compliance policies can prevent affected devices being accepted as compliant without that protection.`,
    severity: 'medium', confidence: 'high',
    applicability: { description: 'Intune tenants with enrolled Windows devices.' },
    requiredEvidence: ['intune.compliancePolicies', 'intune.deviceOverview'], optionalEvidence: [],
    evaluation: { logic: `Assess ${field} only on assigned Windows policies; missing settings remain unknown and group-only coverage requires review.`, parameters: {} },
    expectedState: `Assigned Windows compliance policies require ${label}, with assignment coverage reviewed.`,
    remediation: { summary: `Review Windows device readiness and require ${label} in compliance.`, steps: [
      'Review Windows hardware, firmware and device health attestation readiness in an authorised pilot group.',
      `In Intune, edit the Windows compliance policy Device Health settings to require ${label}.`,
      'Review included and excluded assignments and actions for noncompliance before expanding the pilot.',
    ], effort: 'medium' },
    implementationConsiderations: ['Unsupported devices or attestation failures can become noncompliant. Review exclusions and provide a controlled grace period.', 'A policy requirement is not evidence that every enrolled device is healthy or effectively targeted.'],
    impact: 'Devices that fail the requirement may lose access where Conditional Access requires compliance.',
    rollback: [`Restore the previous ${label} requirement and assignment configuration.`],
    validation: ['Re-run the assessment and inspect the policy device-status and per-setting reports in Intune.'],
    references: [INTUNE_REF.windowsComplianceSettings, { title: 'Windows compliance policy Graph v1.0 properties', publisher: 'Microsoft', url: 'https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-windows10compliancepolicy?view=graph-rest-1.0' }],
    frameworkMappings: [], tags: ['intune', 'windows', 'device-compliance'],
    applies: (ctx) => ({ applicable: ctx.data('intune.deviceOverview').windowsCount > 0, reason: 'No Windows devices are enrolled in Intune.' }),
    evaluate: (ctx) => {
      const policies = ctx.data('intune.compliancePolicies').filter(isWindows10Policy).filter(isAssigned);
      const unknown = policies.filter((p) => p.settings[field] === null);
      const required = policies.filter((p) => p.settings[field] === true);
      const facts = [fact('Assigned Windows policies', policies.length), fact(`Policies requiring ${label}`, required.length), fact('Policies with unavailable setting', unknown.length)];
      if (unknown.length > 0) return notAssessed({ reason: `${label} was not returned for every assigned Windows policy.`, summary: 'Some policy settings are unknown.', facts });
      if (required.length === 0) return fail({ reason: `No assigned Windows compliance policy requires ${label}.`, summary: `${label} is not required by the collected assigned policies.`, facts });
      if (required.length !== policies.length || !required.some((p) => isAssignedBroadly(p) && !p.assignments.some((a) => a.targetType.toLowerCase().includes('exclusion')))) return review({ reason: `${label} is required by some policies, but full assignment coverage needs review.`, summary: 'Validate effective policy assignments and exclusions.', facts, affectedObjects: policies.filter((p) => p.settings[field] !== true).map((p) => affected('compliancePolicy', p.id, p.displayName)) });
      return pass({ reason: `All collected assigned Windows policies require ${label}, including a broad assignment.`, summary: 'The policy requirement is configured.', facts, notes: ['Validate device status separately; this is not proof of hardware state or effective per-device coverage.'] });
    },
  });
}

export const intuneWindowsSecureBoot = healthControl('INTUNE-CMP-004', 'Secure Boot', 'secureBootEnabled');
export const intuneWindowsCodeIntegrity = healthControl('INTUNE-CMP-005', 'code integrity', 'codeIntegrityEnabled');
