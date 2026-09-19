/**
 * Builders for schema-valid AD CS evidence used by control tests.
 */
import { AUTOENROLL_RIGHT_GUID, EKU, ENROLL_RIGHT_GUID } from '@adminsecops/inventory';
import { CONTOSO_SID } from './ad.js';

export const ALL_GUID = '00000000-0000-0000-0000-000000000000';

export interface AceInput {
  principalSid?: string | null;
  principalName?: string;
  accessControlType?: 'Allow' | 'Deny';
  rights: string[];
  objectType?: string | null;
}

export function ace(input: AceInput): Record<string, unknown> {
  return {
    principalSid: input.principalSid === undefined ? null : input.principalSid,
    principalName: input.principalName ?? 'CONTOSO\\Some Group',
    accessControlType: input.accessControlType ?? 'Allow',
    rights: input.rights,
    objectType: input.objectType === undefined ? null : input.objectType,
  };
}

export const DOMAIN_USERS = { principalSid: `${CONTOSO_SID}-513`, principalName: 'CONTOSO\\Domain Users' };
export const DOMAIN_COMPUTERS = { principalSid: `${CONTOSO_SID}-515`, principalName: 'CONTOSO\\Domain Computers' };
export const AUTHENTICATED_USERS = { principalSid: 'S-1-5-11', principalName: 'NT AUTHORITY\\Authenticated Users' };
export const EVERYONE = { principalSid: 'S-1-1-0', principalName: 'Everyone' };
export const DOMAIN_ADMINS = { principalSid: `${CONTOSO_SID}-512`, principalName: 'CONTOSO\\Domain Admins' };
export const PKI_ADMINS = { principalSid: `${CONTOSO_SID}-7001`, principalName: 'CONTOSO\\PKI Admins' };

/** Allow Enroll (ExtendedRight with the Enroll GUID) for a principal. */
export function enrollAce(principal: { principalSid: string | null; principalName: string }, type: 'Allow' | 'Deny' = 'Allow') {
  return ace({ ...principal, accessControlType: type, rights: ['ReadProperty', 'ExtendedRight'], objectType: ENROLL_RIGHT_GUID });
}

export function autoEnrollAce(principal: { principalSid: string | null; principalName: string }) {
  return ace({ ...principal, rights: ['ExtendedRight'], objectType: AUTOENROLL_RIGHT_GUID });
}

/** Default administrative ACEs present on every template. */
export function adminAces(): Record<string, unknown>[] {
  return [
    ace({ ...DOMAIN_ADMINS, rights: ['GenericAll'] }),
    ace({ ...AUTHENTICATED_USERS, rights: ['GenericRead'] }),
  ];
}

export interface TemplateInput {
  name: string;
  displayName?: string | null;
  schemaVersion?: number | null;
  enrolleeSuppliesSubject?: boolean;
  managerApproval?: boolean;
  raSignature?: number;
  extendedKeyUsage?: string[];
  applicationPolicies?: string[];
  permissions?: Record<string, unknown>[];
}

export function template(input: TemplateInput): Record<string, unknown> {
  return {
    name: input.name,
    displayName: input.displayName === undefined ? input.name : input.displayName,
    schemaVersion: input.schemaVersion === undefined ? 2 : input.schemaVersion,
    certificateNameFlag: input.enrolleeSuppliesSubject === true ? 0x1 : 0x2000000,
    enrollmentFlag: input.managerApproval === true ? 0x2 | 0x20 : 0x20,
    raSignature: input.raSignature ?? 0,
    extendedKeyUsage: input.extendedKeyUsage ?? [EKU.clientAuthentication],
    applicationPolicies: input.applicationPolicies ?? [],
    permissions: input.permissions ?? adminAces(),
  };
}

export function certificateAuthority(name: string, templates: string[]): Record<string, unknown> {
  return { name, dnsHostName: `${name.toLowerCase()}.contoso.com`, certificateTemplates: templates, caCertificateNotAfter: '2030-01-01T00:00:00Z' };
}

export { EKU };
