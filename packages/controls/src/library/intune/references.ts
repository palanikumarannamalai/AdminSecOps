import type { Reference } from '@adminsecops/schemas';

/**
 * References specific to the Intune controls. Shared references live in
 * ../../references.ts. Every URL below was checked against Microsoft Learn when it
 * was added; only titles and URLs are stored, never copied text.
 */
const ms = (title: string, url: string): Reference => ({ title, url, publisher: 'Microsoft' });

const LEARN = 'https://learn.microsoft.com/en-us';

export const INTUNE_REF = {
  complianceOverview: ms(
    'Device compliance policies in Microsoft Intune',
    `${LEARN}/intune/device-security/compliance/overview`,
  ),
  createCompliancePolicy: ms(
    'Create device compliance policies in Microsoft Intune',
    `${LEARN}/intune/device-security/compliance/create-policy`,
  ),
  windowsComplianceSettings: ms(
    'Windows compliance settings in Microsoft Intune',
    `${LEARN}/intune/device-security/compliance/ref-windows-settings`,
  ),
  graphCompliancePolicy: ms(
    'deviceCompliancePolicy resource type (Microsoft Graph)',
    `${LEARN}/graph/api/resources/intune-deviceconfig-devicecompliancepolicy?view=graph-rest-1.0`,
  ),
  caRequireCompliantDevice: ms(
    'Require compliant, hybrid joined devices, or MFA',
    `${LEARN}/entra/identity/conditional-access/policy-alt-all-users-compliant-hybrid-or-mfa`,
  ),
  caAllUsersDeviceCompliance: ms(
    'How to require device compliance with Conditional Access',
    `${LEARN}/entra/identity/conditional-access/policy-all-users-device-compliance`,
  ),
} as const satisfies Record<string, Reference>;
