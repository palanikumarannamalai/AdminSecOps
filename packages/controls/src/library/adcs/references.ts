import type { Reference } from '@adminsecops/schemas';

/**
 * Authoritative references used by the AD CS controls. Only titles and URLs are
 * stored (no copied text); every URL was checked when added. Microsoft does not
 * publish a single AD CS hardening guide, so the Microsoft Defender for Identity
 * certificate posture assessments are the primary Microsoft source.
 */
const ms = (title: string, url: string): Reference => ({ title, url, publisher: 'Microsoft' });
const mitre = (title: string, url: string): Reference => ({ title, url, publisher: 'MITRE' });

const LEARN = 'https://learn.microsoft.com/en-us';
const MDI_CERTIFICATES = `${LEARN}/defender-for-identity/security-posture-assessments/certificates`;

export const ADCS_REF = {
  mdiCertificates: ms('Microsoft Defender for Identity: Certificates security posture assessments', MDI_CERTIFICATES),
  mdiEsc1: ms(
    'Microsoft Defender for Identity: Prevent users to request a certificate valid for arbitrary users (ESC1)',
    `${MDI_CERTIFICATES}#prevent-users-to-request-a-certificate-valid-for-arbitrary-users-based-on-the-certificate-template-esc1-preview`,
  ),
  mdiEsc4Acl: ms(
    'Microsoft Defender for Identity: Edit misconfigured certificate templates ACL (ESC4)',
    `${MDI_CERTIFICATES}#edit-misconfigured-certificate-templates-acl-esc4`,
  ),
  manageTemplates: ms('Manage certificate templates', `${LEARN}/windows-server/identity/ad-cs/manage-certificate-templates`),
  kb5014754: ms(
    'KB5014754: Certificate-based authentication changes on Windows domain controllers',
    'https://support.microsoft.com/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16',
  ),
  attackStealForgeCertificates: mitre(
    'MITRE ATT&CK T1649: Steal or Forge Authentication Certificates',
    'https://attack.mitre.org/techniques/T1649/',
  ),
} as const satisfies Record<string, Reference>;
