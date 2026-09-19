import { z } from 'zod';
import { list, optString, optTimestamp } from '../common.js';
import { defineDataset } from './define.js';

const DOMAIN_USER = 'Active Directory: authenticated domain user (read access to the Configuration partition)';

export const adcsCertificateAuthorities = defineDataset({
  id: 'adcs.certificateAuthorities',
  module: 'ADCS',
  technology: 'adcs',
  title: 'Enterprise certification authorities',
  description: 'Enterprise CAs registered in Active Directory and the templates each publishes.',
  source: 'ActiveDirectory',
  operations: [
    'Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,<ConfigurationNC>" -Filter "objectClass -eq \'pKIEnrollmentService\'"',
  ],
  permissions: [DOMAIN_USER],
  personalData: 'none',
  schema: z.array(
    z.object({
      name: z.string(),
      dnsHostName: optString,
      certificateTemplates: list(z.string()),
      caCertificateNotAfter: optTimestamp,
    }),
  ),
});

export const TemplateAceSchema = z.object({
  principalSid: optString,
  principalName: z.string(),
  /** Allow | Deny */
  accessControlType: z.string(),
  /** ActiveDirectoryRights flags, e.g. ["ExtendedRight"], ["GenericAll"], ["WriteDacl","WriteOwner"] */
  rights: list(z.string()),
  /** ObjectType GUID of the ACE; 00000000-0000-0000-0000-000000000000 means all */
  objectType: optString,
});
export type TemplateAce = z.output<typeof TemplateAceSchema>;

export const adcsCertificateTemplates = defineDataset({
  id: 'adcs.certificateTemplates',
  module: 'ADCS',
  technology: 'adcs',
  title: 'Certificate templates',
  description:
    'Certificate template configuration flags, extended key usages and access control entries. No certificates or keys are read.',
  source: 'ActiveDirectory',
  operations: [
    'Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,<ConfigurationNC>" -Properties msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-RA-Signature,pKIExtendedKeyUsage,msPKI-Certificate-Application-Policy,msPKI-Template-Schema-Version,nTSecurityDescriptor',
  ],
  permissions: [DOMAIN_USER],
  personalData: 'none',
  schema: z.array(
    z.object({
      name: z.string(),
      displayName: optString,
      schemaVersion: z.number().int().nullish().transform((v) => v ?? null),
      /** msPKI-Certificate-Name-Flag (bit 0x1 = ENROLLEE_SUPPLIES_SUBJECT) */
      certificateNameFlag: z.number().int(),
      /** msPKI-Enrollment-Flag (bit 0x2 = PEND_ALL_REQUESTS / manager approval) */
      enrollmentFlag: z.number().int(),
      /** msPKI-RA-Signature: number of authorised signatures required */
      raSignature: z.number().int(),
      extendedKeyUsage: list(z.string()),
      applicationPolicies: list(z.string()),
      permissions: list(TemplateAceSchema),
    }),
  ),
});

export const ADCS_DATASETS = [adcsCertificateAuthorities, adcsCertificateTemplates] as const;
