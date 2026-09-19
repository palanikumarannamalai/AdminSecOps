import { describe, expect, it } from 'vitest';
import { CHILD_SID } from '../../../test/builders/ad.js';
import {
  ace,
  adminAces,
  ALL_GUID,
  AUTHENTICATED_USERS,
  autoEnrollAce,
  certificateAuthority,
  DOMAIN_ADMINS,
  DOMAIN_COMPUTERS,
  DOMAIN_USERS,
  EKU,
  enrollAce,
  EVERYONE,
  PKI_ADMINS,
  template,
} from '../../../test/builders/adcs.js';
import { run } from '../../../test/run.js';
import { adcsEsc1EnrolleeSuppliesSubject, adcsEsc2AnyPurpose, adcsEsc3EnrollmentAgent, adcsEsc4TemplateAcl } from './templates.js';

const esc1 = (overrides: Partial<Parameters<typeof template>[0]> = {}) =>
  template({
    name: 'VulnWeb',
    enrolleeSuppliesSubject: true,
    extendedKeyUsage: [EKU.clientAuthentication],
    permissions: [...adminAces(), enrollAce(DOMAIN_USERS)],
    ...overrides,
  });

describe('ADCS-TPL-001 enrollee-supplied subject with authentication EKU (ESC1)', () => {
  it('passes for a hardened environment', () => {
    const result = run(adcsEsc1EnrolleeSuppliesSubject, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['User', 'WebServer'])],
      'adcs.certificateTemplates': [
        template({ name: 'User', permissions: [...adminAces(), enrollAce(DOMAIN_USERS)] }),
        template({ name: 'WebServer', enrolleeSuppliesSubject: true, extendedKeyUsage: ['1.3.6.1.5.5.7.3.1'], permissions: [...adminAces(), enrollAce(DOMAIN_COMPUTERS)] }),
      ],
    });
    expect(result.status).toBe('PASS');
  });

  it('fails for a published vulnerable template (case-insensitive name match)', () => {
    const result = run(adcsEsc1EnrolleeSuppliesSubject, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['vulnweb'])],
      'adcs.certificateTemplates': [esc1()],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.id).toBe('VulnWeb');
    expect(result.affectedObjects[0]?.detail).toContain('Domain Users');
    expect(result.affectedObjects[0]?.detail).toContain('CA1');
    expect(result.confidence).toBe('medium');
  });

  it('notes but does not fail an unpublished vulnerable template', () => {
    const result = run(adcsEsc1EnrolleeSuppliesSubject, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['User'])],
      'adcs.certificateTemplates': [esc1()],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('VulnWeb');
  });

  it.each([
    ['manager approval', { managerApproval: true }],
    ['authorized signatures', { raSignature: 1 }],
    ['non-authentication EKU', { extendedKeyUsage: ['1.3.6.1.5.5.7.3.1'] }],
    ['subject built from AD', { enrolleeSuppliesSubject: false }],
    ['enrollment only for administrators', { permissions: [...adminAces(), enrollAce(PKI_ADMINS)] }],
  ])('is not vulnerable with %s', (_label, overrides) => {
    const result = run(adcsEsc1EnrolleeSuppliesSubject, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['VulnWeb'])],
      'adcs.certificateTemplates': [esc1(overrides)],
    });
    expect(result.status).toBe('PASS');
  });

  it.each([
    ['GenericAll', ace({ ...AUTHENTICATED_USERS, rights: ['GenericAll'] })],
    ['ExtendedRight on all rights', ace({ ...DOMAIN_COMPUTERS, rights: ['ExtendedRight'], objectType: ALL_GUID })],
    ['ExtendedRight with null object type', ace({ ...EVERYONE, rights: ['ReadProperty, ExtendedRight'] })],
    ['unresolved SID matched by name', ace({ principalSid: null, principalName: 'CONTOSO\\Domain Users', rights: ['ExtendedRight'], objectType: '0E10C968-78FB-11D2-90D4-00C04F79DC55' })],
    ['Domain Users of another domain', ace({ principalSid: `${CHILD_SID}-513`, principalName: 'EMEA\\Domain Users', rights: ['ExtendedRight'], objectType: ALL_GUID })],
  ])('detects enrollment granted through %s', (_label, grant) => {
    const result = run(adcsEsc1EnrolleeSuppliesSubject, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['VulnWeb'])],
      'adcs.certificateTemplates': [esc1({ permissions: [...adminAces(), grant] })],
    });
    expect(result.status).toBe('FAIL');
  });

  it('treats a template without EKU or with Any Purpose as authentication-capable', () => {
    for (const ekus of [[], [EKU.anyPurpose], [EKU.smartCardLogon]]) {
      const result = run(adcsEsc1EnrolleeSuppliesSubject, {
        'adcs.certificateAuthorities': [certificateAuthority('CA1', ['VulnWeb'])],
        'adcs.certificateTemplates': [esc1({ extendedKeyUsage: ekus })],
      });
      expect(result.status).toBe('FAIL');
    }
  });

  it('honours Deny ACEs for the same principal or Everyone', () => {
    for (const deny of [enrollAce(DOMAIN_USERS, 'Deny'), ace({ ...EVERYONE, accessControlType: 'Deny', rights: ['ExtendedRight'], objectType: ALL_GUID })]) {
      const result = run(adcsEsc1EnrolleeSuppliesSubject, {
        'adcs.certificateAuthorities': [certificateAuthority('CA1', ['VulnWeb'])],
        'adcs.certificateTemplates': [esc1({ permissions: [...adminAces(), enrollAce(DOMAIN_USERS), deny] })],
      });
      expect(result.status).toBe('PASS');
    }
  });

  it('does not let a Deny for Domain Users cancel an Allow for Authenticated Users', () => {
    const result = run(adcsEsc1EnrolleeSuppliesSubject, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['VulnWeb'])],
      'adcs.certificateTemplates': [esc1({ permissions: [...adminAces(), enrollAce(AUTHENTICATED_USERS), enrollAce(DOMAIN_USERS, 'Deny')] })],
    });
    expect(result.status).toBe('FAIL');
  });

  it('does not treat AutoEnroll alone as enrollment', () => {
    const result = run(adcsEsc1EnrolleeSuppliesSubject, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['VulnWeb'])],
      'adcs.certificateTemplates': [esc1({ permissions: [...adminAces(), autoEnrollAce(DOMAIN_USERS)] })],
    });
    expect(result.status).toBe('PASS');
  });

  it('is NOT_APPLICABLE without an enterprise CA', () => {
    const result = run(adcsEsc1EnrolleeSuppliesSubject, { 'adcs.certificateAuthorities': [], 'adcs.certificateTemplates': [esc1()] });
    expect(result.status).toBe('NOT_APPLICABLE');
  });

  it('is NOT_ASSESSED when templates were not collected', () => {
    expect(run(adcsEsc1EnrolleeSuppliesSubject, { 'adcs.certificateAuthorities': [certificateAuthority('CA1', [])] }).status).toBe('NOT_ASSESSED');
  });

  it('downgrades PASS on partial template evidence', () => {
    const result = run(
      adcsEsc1EnrolleeSuppliesSubject,
      { 'adcs.certificateAuthorities': [certificateAuthority('CA1', [])], 'adcs.certificateTemplates': [] },
      { partial: ['adcs.certificateTemplates'] },
    );
    expect(result.status).toBe('REVIEW');
  });
});

describe('ADCS-TPL-002 Any Purpose / no EKU (ESC2)', () => {
  const anyPurpose = (overrides: Partial<Parameters<typeof template>[0]> = {}) =>
    template({ name: 'AnyPurpose', extendedKeyUsage: [EKU.anyPurpose], permissions: [...adminAces(), enrollAce(DOMAIN_USERS)], ...overrides });

  it('fails for a published Any Purpose template enrollable by Domain Users', () => {
    const result = run(adcsEsc2AnyPurpose, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['AnyPurpose'])],
      'adcs.certificateTemplates': [anyPurpose()],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('Any Purpose');
  });

  it('fails for a published template without EKUs (application policies also empty)', () => {
    const result = run(adcsEsc2AnyPurpose, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['AnyPurpose'])],
      'adcs.certificateTemplates': [anyPurpose({ extendedKeyUsage: [], applicationPolicies: [] })],
    });
    expect(result.status).toBe('FAIL');
  });

  it('passes when the Any Purpose EKU only appears with approval or for admins (SubCA pattern)', () => {
    const result = run(adcsEsc2AnyPurpose, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['AnyPurpose', 'SubCA'])],
      'adcs.certificateTemplates': [
        anyPurpose({ managerApproval: true }),
        template({ name: 'SubCA', schemaVersion: 1, extendedKeyUsage: [], permissions: adminAces() }),
      ],
    });
    expect(result.status).toBe('PASS');
  });

  it('notes an unpublished template', () => {
    const result = run(adcsEsc2AnyPurpose, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', [])],
      'adcs.certificateTemplates': [anyPurpose()],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('AnyPurpose');
  });
});

describe('ADCS-TPL-003 template write permissions (ESC4)', () => {
  const writable = (grant: Record<string, unknown>, name = 'User') => template({ name, permissions: [...adminAces(), grant] });

  it('passes when only administrators can write', () => {
    const result = run(adcsEsc4TemplateAcl, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['User'])],
      'adcs.certificateTemplates': [template({ name: 'User', permissions: [...adminAces(), ace({ ...PKI_ADMINS, rights: ['WriteDacl', 'WriteOwner'] }), enrollAce(DOMAIN_USERS)] })],
    });
    expect(result.status).toBe('PASS');
  });

  it.each([
    ['GenericAll', ace({ ...DOMAIN_USERS, rights: ['GenericAll'] })],
    ['WriteDacl', ace({ ...AUTHENTICATED_USERS, rights: ['WriteDacl'] })],
    ['WriteOwner in a flags string', ace({ ...EVERYONE, rights: ['ReadProperty, WriteOwner'] })],
    ['GenericWrite', ace({ ...DOMAIN_COMPUTERS, rights: ['GenericWrite'] })],
    ['WriteProperty on all properties', ace({ ...DOMAIN_USERS, rights: ['WriteProperty'], objectType: ALL_GUID })],
  ])('fails for a published template with low-privileged %s', (_label, grant) => {
    const result = run(adcsEsc4TemplateAcl, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['User'])],
      'adcs.certificateTemplates': [writable(grant)],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('published by CA1');
  });

  it('requires review for an unpublished template with write rights', () => {
    const result = run(adcsEsc4TemplateAcl, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', [])],
      'adcs.certificateTemplates': [writable(ace({ ...DOMAIN_USERS, rights: ['GenericAll'] }))],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects[0]?.detail).toContain('not published');
  });

  it('requires review for WriteProperty on a specific attribute only', () => {
    const result = run(adcsEsc4TemplateAcl, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['User'])],
      'adcs.certificateTemplates': [writable(ace({ ...DOMAIN_USERS, rights: ['WriteProperty'], objectType: 'ea1dddc4-60ff-416e-8cc0-17cee534bce7' }))],
    });
    expect(result.status).toBe('REVIEW');
  });

  it('honours a Deny ACE that removes the write right', () => {
    const result = run(adcsEsc4TemplateAcl, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['User'])],
      'adcs.certificateTemplates': [
        template({
          name: 'User',
          permissions: [...adminAces(), ace({ ...DOMAIN_USERS, rights: ['WriteDacl'] }), ace({ ...DOMAIN_USERS, accessControlType: 'Deny', rights: ['WriteDacl'] })],
        }),
      ],
    });
    expect(result.status).toBe('PASS');
  });

  it('ignores write rights held by privileged groups such as Domain Admins', () => {
    const result = run(adcsEsc4TemplateAcl, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['User'])],
      'adcs.certificateTemplates': [writable(ace({ ...DOMAIN_ADMINS, rights: ['WriteOwner'] }))],
    });
    expect(result.status).toBe('PASS');
  });
});

describe('ADCS-TPL-004 enrollment agent templates (ESC3)', () => {
  const agent = (overrides: Partial<Parameters<typeof template>[0]> = {}) =>
    template({ name: 'EnrollmentAgentOpen', extendedKeyUsage: [EKU.certificateRequestAgent], permissions: [...adminAces(), enrollAce(DOMAIN_USERS)], ...overrides });
  const userV1 = template({ name: 'User', schemaVersion: 1, extendedKeyUsage: [EKU.clientAuthentication], permissions: [...adminAces(), enrollAce(DOMAIN_USERS)] });

  it('fails when an open agent template and a version 1 authentication template are published', () => {
    const result = run(adcsEsc3EnrollmentAgent, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['EnrollmentAgentOpen', 'User'])],
      'adcs.certificateTemplates': [agent(), userV1],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjectCount).toBe(2);
  });

  it('requires review when no version 1 target template is published', () => {
    const result = run(adcsEsc3EnrollmentAgent, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['EnrollmentAgentOpen'])],
      'adcs.certificateTemplates': [agent(), userV1],
    });
    expect(result.status).toBe('REVIEW');
  });

  it('detects the agent EKU in application policies', () => {
    const result = run(adcsEsc3EnrollmentAgent, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['EnrollmentAgentOpen', 'User'])],
      'adcs.certificateTemplates': [agent({ extendedKeyUsage: [], applicationPolicies: [EKU.certificateRequestAgent] }), userV1],
    });
    expect(result.status).toBe('FAIL');
  });

  it('passes when the agent template requires approval or is restricted', () => {
    for (const overrides of [{ managerApproval: true }, { permissions: [...adminAces(), enrollAce(PKI_ADMINS)] }]) {
      const result = run(adcsEsc3EnrollmentAgent, {
        'adcs.certificateAuthorities': [certificateAuthority('CA1', ['EnrollmentAgentOpen', 'User'])],
        'adcs.certificateTemplates': [agent(overrides), userV1],
      });
      expect(result.status).toBe('PASS');
    }
  });

  it('notes an unpublished open agent template', () => {
    const result = run(adcsEsc3EnrollmentAgent, {
      'adcs.certificateAuthorities': [certificateAuthority('CA1', ['User'])],
      'adcs.certificateTemplates': [agent(), userV1],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('EnrollmentAgentOpen');
  });

  it('is NOT_APPLICABLE without an enterprise CA', () => {
    expect(run(adcsEsc3EnrollmentAgent, { 'adcs.certificateAuthorities': [], 'adcs.certificateTemplates': [] }).status).toBe('NOT_APPLICABLE');
  });
});
