import {
  ALL_OBJECTS_GUID,
  CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
  CT_FLAG_PEND_ALL_REQUESTS,
  EKU,
  ENROLL_RIGHT_GUID,
  isLowPrivilegedPrincipal,
  normalizeAdRights,
  normalizeObjectType,
  publishedTemplateIndex,
  sameSid,
} from '@adminsecops/inventory';
import type { DatasetData, TemplateAce } from '@adminsecops/schemas';
import type { ControlContext } from '../../define.js';
import { affected } from '../../helpers.js';

/**
 * Read-only interpretation of certificate template configuration and ACLs. The
 * functions here decide which principals can enroll in or modify a template; the
 * controls decide whether that is a finding.
 */

export type CertificateTemplate = DatasetData<'adcs.certificateTemplates'>[number];

const WELL_KNOWN_EVERYONE = 'S-1-1-0';
const WELL_KNOWN_AUTHENTICATED_USERS = 'S-1-5-11';
const WELL_KNOWN_ANONYMOUS = 'S-1-5-7';

function principalLabel(ace: TemplateAce): string {
  return ace.principalName.length > 0 ? ace.principalName : (ace.principalSid ?? 'unknown principal');
}

function isAllow(ace: TemplateAce): boolean {
  return ace.accessControlType.trim().toLowerCase() === 'allow';
}

function isDeny(ace: TemplateAce): boolean {
  return ace.accessControlType.trim().toLowerCase() === 'deny';
}

function rightsOf(ace: TemplateAce): Set<string> {
  return new Set(normalizeAdRights(ace.rights));
}

function isLowPrivileged(ace: TemplateAce): boolean {
  return isLowPrivilegedPrincipal(ace.principalSid, ace.principalName);
}

function samePrincipal(a: TemplateAce, b: TemplateAce): boolean {
  if (a.principalSid !== null && b.principalSid !== null) return sameSid(a.principalSid, b.principalSid);
  return a.principalName.trim().toLowerCase() === b.principalName.trim().toLowerCase();
}

function isSid(ace: TemplateAce, sid: string, names: readonly string[]): boolean {
  if (ace.principalSid !== null) return sameSid(ace.principalSid, sid);
  const lower = ace.principalName.trim().toLowerCase();
  return names.some((n) => lower === n || lower.endsWith(`\\${n}`));
}

/**
 * Does a Deny ACE apply to the principal of an Allow ACE? It does when it names the same
 * principal, Everyone, or Authenticated Users (which contains every authenticated
 * principal except anonymous logons). Other group relationships cannot be resolved
 * from template evidence, so they are not assumed.
 */
function denyAppliesTo(deny: TemplateAce, allow: TemplateAce): boolean {
  if (samePrincipal(deny, allow)) return true;
  if (isSid(deny, WELL_KNOWN_EVERYONE, ['everyone'])) return true;
  if (isSid(deny, WELL_KNOWN_AUTHENTICATED_USERS, ['authenticated users'])) {
    return !isSid(allow, WELL_KNOWN_EVERYONE, ['everyone']) && !isSid(allow, WELL_KNOWN_ANONYMOUS, ['anonymous logon']);
  }
  return false;
}

/** ACE grants the Enroll extended right (GenericAll, or ExtendedRight for all rights or Enroll). AutoEnroll alone does not allow enrollment. */
function grantsEnroll(ace: TemplateAce): boolean {
  const rights = rightsOf(ace);
  if (rights.has('genericall')) return true;
  if (!rights.has('extendedright')) return false;
  const type = normalizeObjectType(ace.objectType);
  return type === ALL_OBJECTS_GUID || type === ENROLL_RIGHT_GUID;
}

export interface PrincipalGrant {
  principal: string;
  sid: string | null;
  rights: string[];
}

/** Low-privileged principals that can enroll, after removing grants cancelled by Deny ACEs. */
export function lowPrivilegedEnrollees(template: CertificateTemplate): PrincipalGrant[] {
  const denies = template.permissions.filter((a) => isDeny(a) && grantsEnroll(a));
  const out: PrincipalGrant[] = [];
  for (const ace of template.permissions) {
    if (!isAllow(ace) || !isLowPrivileged(ace) || !grantsEnroll(ace)) continue;
    if (denies.some((d) => denyAppliesTo(d, ace))) continue;
    if (out.some((g) => g.principal === principalLabel(ace))) continue;
    out.push({ principal: principalLabel(ace), sid: ace.principalSid, rights: ['Enroll'] });
  }
  return out;
}

const OBJECT_CONTROL_RIGHTS = ['genericall', 'genericwrite', 'writedacl', 'writeowner'] as const;
const DISPLAY: Readonly<Record<string, string>> = {
  genericall: 'GenericAll',
  genericwrite: 'GenericWrite',
  writedacl: 'WriteDacl',
  writeowner: 'WriteOwner',
  writeproperty: 'WriteProperty',
};

/** Which rights a Deny ACE removes (GenericAll denies everything; GenericWrite includes WriteProperty). */
function denyCovers(deny: TemplateAce, right: string, propertyGuid: string): boolean {
  const rights = rightsOf(deny);
  if (rights.has('genericall')) return true;
  if (rights.has(right) && (right !== 'writeproperty' || normalizeObjectType(deny.objectType) === ALL_OBJECTS_GUID || normalizeObjectType(deny.objectType) === propertyGuid)) {
    return true;
  }
  return right === 'writeproperty' && rights.has('genericwrite');
}

export interface WriteGrant extends PrincipalGrant {
  /** true when the only write access is WriteProperty on specific attributes */
  propertySpecificOnly: boolean;
}

/**
 * Low-privileged principals holding rights that allow changing the template or its
 * permissions: GenericAll, GenericWrite, WriteDacl, WriteOwner, or WriteProperty
 * (on all properties, or on a specific property which is reported separately).
 */
export function lowPrivilegedWriters(template: CertificateTemplate): WriteGrant[] {
  const denies = template.permissions.filter(isDeny);
  const byPrincipal = new Map<string, WriteGrant>();
  for (const ace of template.permissions) {
    if (!isAllow(ace) || !isLowPrivileged(ace)) continue;
    const rights = rightsOf(ace);
    const objectType = normalizeObjectType(ace.objectType);
    const granted: { right: string; specific: boolean }[] = [];
    for (const right of OBJECT_CONTROL_RIGHTS) if (rights.has(right)) granted.push({ right, specific: false });
    if (rights.has('writeproperty')) granted.push({ right: 'writeproperty', specific: objectType !== ALL_OBJECTS_GUID });
    const effective = granted.filter((g) => !denies.some((d) => denyAppliesTo(d, ace) && denyCovers(d, g.right, objectType)));
    if (effective.length === 0) continue;
    const key = principalLabel(ace);
    const existing = byPrincipal.get(key) ?? { principal: key, sid: ace.principalSid, rights: [], propertySpecificOnly: true };
    for (const g of effective) {
      const label = g.specific ? `WriteProperty (${objectType})` : (DISPLAY[g.right] ?? g.right);
      if (!existing.rights.includes(label)) existing.rights.push(label);
      if (!g.specific) existing.propertySpecificOnly = false;
    }
    byPrincipal.set(key, existing);
  }
  return [...byPrincipal.values()];
}

export interface TemplateTraits {
  enrolleeSuppliesSubject: boolean;
  managerApproval: boolean;
  authorizedSignatures: number;
  /** Union of pKIExtendedKeyUsage and msPKI-Certificate-Application-Policy */
  ekus: string[];
  authenticationCapable: boolean;
  anyPurposeOrNoEku: boolean;
  certificateRequestAgent: boolean;
  /** Issuance is gated by manager approval or at least one authorized signature. */
  issuanceGated: boolean;
}

export function templateTraits(template: CertificateTemplate): TemplateTraits {
  const ekus = [...new Set([...template.extendedKeyUsage, ...template.applicationPolicies].map((e) => e.trim()))];
  const noEku = ekus.length === 0;
  const anyPurpose = ekus.includes(EKU.anyPurpose);
  const authEku = [EKU.clientAuthentication, EKU.pkinitClientAuthentication, EKU.smartCardLogon].some((e) => ekus.includes(e));
  const managerApproval = (template.enrollmentFlag & CT_FLAG_PEND_ALL_REQUESTS) !== 0;
  return {
    enrolleeSuppliesSubject: (template.certificateNameFlag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) !== 0,
    managerApproval,
    authorizedSignatures: template.raSignature,
    ekus,
    authenticationCapable: noEku || anyPurpose || authEku,
    anyPurposeOrNoEku: noEku || anyPurpose,
    certificateRequestAgent: ekus.includes(EKU.certificateRequestAgent),
    issuanceGated: managerApproval || template.raSignature > 0,
  };
}

export function ekuDescription(traits: TemplateTraits): string {
  if (traits.ekus.length === 0) return 'no EKU (any purpose)';
  const names: Record<string, string> = {
    [EKU.clientAuthentication]: 'Client Authentication',
    [EKU.pkinitClientAuthentication]: 'PKINIT Client Authentication',
    [EKU.smartCardLogon]: 'Smart Card Logon',
    [EKU.anyPurpose]: 'Any Purpose',
    [EKU.certificateRequestAgent]: 'Certificate Request Agent',
  };
  return traits.ekus.map((e) => names[e] ?? e).join(', ');
}

export interface TemplateInventory {
  templates: CertificateTemplate[];
  published: Map<string, string[]>;
  caCount: number;
}

/** Templates plus the published-name index; null when no enterprise CA exists. */
export function loadTemplates(ctx: ControlContext): TemplateInventory | null {
  const cas = ctx.data('adcs.certificateAuthorities');
  const templates = ctx.data('adcs.certificateTemplates');
  if (cas.length === 0) return null;
  return { templates, published: publishedTemplateIndex(cas), caCount: cas.length };
}

export function publishingCas(inv: TemplateInventory, template: CertificateTemplate): string[] {
  return inv.published.get(template.name.trim().toLowerCase()) ?? [];
}

export function templateObject(template: CertificateTemplate, detail: string) {
  return affected('certificateTemplate', template.name, template.displayName ?? template.name, detail);
}

export const NO_ENTERPRISE_CA = {
  reason: 'No enterprise certification authority is registered in Active Directory, so no certificate template can be issued.',
  summary: 'AD CS enterprise CAs were not found.',
};
