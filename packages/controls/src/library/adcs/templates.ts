import { defineControl } from '../../define.js';
import { fact, fail, notApplicable, pass, plural, review } from '../../helpers.js';
import { ADCS_REF } from './references.js';
import {
  ekuDescription,
  loadTemplates,
  lowPrivilegedEnrollees,
  lowPrivilegedWriters,
  NO_ENTERPRISE_CA,
  publishingCas,
  templateObject,
  templateTraits,
  type CertificateTemplate,
  type TemplateInventory,
} from './template-analysis.js';

const ACL_CONFIDENCE_NOTE =
  'Low-privileged principals are Everyone, Authenticated Users, Anonymous Logon, BUILTIN\\Users, Domain Users, Domain Computers and Domain Guests. Custom groups with broad membership cannot be recognised from template data and should be reviewed separately.';

function unpublishedNote(templates: readonly CertificateTemplate[], risk: string): string[] {
  if (templates.length === 0) return [];
  return [
    `${plural(templates.length, 'unpublished template')} (${templates.map((t) => t.name).join(', ')}) ${risk}. No CA currently issues them, so they are not a finding, but fix or delete them before any CA publishes them.`,
  ];
}

function grantees(template: CertificateTemplate): string {
  return lowPrivilegedEnrollees(template)
    .map((g) => g.principal)
    .join(', ');
}

function splitPublished(inv: TemplateInventory, templates: readonly CertificateTemplate[]) {
  return {
    published: templates.filter((t) => publishingCas(inv, t).length > 0),
    unpublished: templates.filter((t) => publishingCas(inv, t).length === 0),
  };
}

const COMMON_CONSIDERATIONS = [
  'Changing a template affects only certificates issued afterwards; certificates already issued from a vulnerable template remain valid. Review issued certificates (certsrv.msc > Issued Certificates, filtered by template) and revoke any that were not legitimately requested.',
  'Before removing enrollment permissions, identify who legitimately uses the template (application owners, auto-enrollment for specific computers) and grant enrollment to a dedicated group instead.',
  'Duplicate a template and test changes on the copy when you are unsure of the impact; you can switch the CA to publish the new version afterwards.',
  'Ensure domain controllers enforce strong certificate mapping (KB5014754) so that certificates are bound to the requesting account.',
];

export const adcsEsc1EnrolleeSuppliesSubject = defineControl({
  id: 'ADCS-TPL-001',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'No published template lets low-privileged users request authentication certificates for any identity',
  technology: 'adcs',
  category: 'Certificate templates',
  subcategory: 'Subject name control',
  description:
    'Finds published certificate templates that low-privileged principals can enroll in, that let the requester supply the subject or subject alternative name ("Supply in the request"), that can be used for client authentication, and that require neither CA manager approval nor authorized signatures. This combination is commonly called ESC1.',
  rationale:
    'A certificate that is valid for client authentication proves the identity written in its subject alternative name. If any domain user can enroll and write any name into the request, and nothing approves the request, a user can obtain a certificate for a domain administrator and sign in as that administrator. Microsoft Defender for Identity reports this configuration as a posture assessment.',
  severity: 'critical',
  confidence: 'medium',
  applicability: { description: 'Forests with at least one enterprise certification authority registered in Active Directory.' },
  requiredEvidence: ['adcs.certificateAuthorities', 'adcs.certificateTemplates'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'A template is vulnerable when all of: (1) an Allow ACE grants a low-privileged principal the Enroll right (GenericAll, or ExtendedRight for all extended rights or the Enroll GUID), not cancelled by a Deny ACE on the same principal, Everyone or Authenticated Users; (2) msPKI-Certificate-Name-Flag has ENROLLEE_SUPPLIES_SUBJECT (0x1); (3) the union of pKIExtendedKeyUsage and msPKI-Certificate-Application-Policy contains Client Authentication, PKINIT Client Authentication, Smart Card Logon or Any Purpose, or is empty; (4) msPKI-Enrollment-Flag lacks PEND_ALL_REQUESTS (0x2) and msPKI-RA-Signature is 0. FAIL when any vulnerable template is published by an enterprise CA (name match is case-insensitive). Vulnerable but unpublished templates are listed in a note and do not fail. PASS otherwise. NOT_APPLICABLE when there is no enterprise CA. Confidence is medium because group membership behind ACEs is interpreted heuristically.',
    parameters: {},
  },
  expectedState: 'No published template combines low-privileged enrollment, requester-supplied subject, an authentication EKU and no issuance approval.',
  remediation: {
    summary: 'For each listed template remove at least one of the dangerous conditions: stop requesters from supplying the subject, remove broad enrollment rights, remove authentication EKUs, require manager approval, or stop publishing the template.',
    steps: [
      'Open the Certificate Templates console (certtmpl.msc) as an Enterprise Admin or delegated PKI administrator and open the listed template.',
      'Subject Name tab: select "Build from this Active Directory information" instead of "Supply in the request" unless the use case genuinely needs custom names (for example web server certificates, which should not have client authentication EKUs).',
      'Security tab: remove Enroll and Autoenroll for Domain Users, Domain Computers, Authenticated Users or Everyone, and grant them to a dedicated group containing only the accounts that need this template.',
      'Extensions tab > Application Policies: remove Client Authentication, Smart Card Logon, PKINIT Client Authentication or Any Purpose if the template is not meant for authentication.',
      'If requesters must supply names, go to the Issuance Requirements tab and select "CA certificate manager approval" so each request is checked by a person.',
      'If the template is not used, remove it from every CA: Certification Authority console (certsrv.msc) > Certificate Templates > right-click the template > Delete (this only unpublishes it).',
      'Review certificates already issued from the template and revoke any that were not legitimately requested.',
    ],
    scriptExample: [
      '# Read-only review; changes are made in certtmpl.msc / certsrv.msc. AdminSecOps never runs this.',
      '# List templates published by each enterprise CA:',
      'certutil -CATemplates',
      '# Show the configuration of one template:',
      "Get-ADObject -SearchBase ('CN=Certificate Templates,CN=Public Key Services,CN=Services,' + (Get-ADRootDSE).configurationNamingContext) -Filter \"cn -eq 'VulnTemplate'\" -Properties msPKI-Certificate-Name-Flag,msPKI-Enrollment-Flag,msPKI-RA-Signature,pKIExtendedKeyUsage",
      '# Unpublish a template from a CA (run on the CA, after review):',
      '# certutil -SetCATemplates -VulnTemplate',
    ].join('\n'),
    effort: 'medium',
  },
  implementationConsiderations: COMMON_CONSIDERATIONS,
  impact: 'Users lose the ability to request certificates with arbitrary names from this template, or requests wait for approval. Legitimate applications that depended on it need a dedicated, restricted template.',
  rollback: [
    'Restore the previous template settings in certtmpl.msc (document them before changing), or re-publish the template on the CA with certsrv.msc > Certificate Templates > New > Certificate Template to Issue.',
  ],
  validation: [
    'In certtmpl.msc confirm the template no longer has "Supply in the request" with broad enrollment, or requires approval.',
    'Re-run the AdminSecOps AD CS collector and confirm ADCS-TPL-001 is PASS.',
  ],
  references: [ADCS_REF.mdiEsc1, ADCS_REF.manageTemplates, ADCS_REF.kb5014754, ADCS_REF.attackStealForgeCertificates],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5(2)' },
    { framework: 'NIST-800-53r5', id: 'AC-6' },
    { framework: 'NIST-800-53r5', id: 'CM-6' },
    { framework: 'MITRE-ATTACK', id: 'T1649' },
  ],
  tags: ['adcs', 'certificates', 'privileged-access', 'esc1'],
  evaluate: (ctx) => {
    const inv = loadTemplates(ctx);
    if (inv === null) return notApplicable(NO_ENTERPRISE_CA);
    const vulnerable = inv.templates.filter((t) => {
      const traits = templateTraits(t);
      return traits.enrolleeSuppliesSubject && traits.authenticationCapable && !traits.issuanceGated && lowPrivilegedEnrollees(t).length > 0;
    });
    const { published, unpublished } = splitPublished(inv, vulnerable);
    const facts = [
      fact('Enterprise CAs', inv.caCount),
      fact('Templates evaluated', inv.templates.length),
      fact('Published vulnerable templates', published.length),
      fact('Unpublished vulnerable templates', unpublished.length),
    ];
    const notes = [...unpublishedNote(unpublished, 'have the same dangerous combination'), ACL_CONFIDENCE_NOTE];
    if (published.length > 0) {
      return fail({
        reason: `${plural(published.length, 'published template')} let low-privileged principals request authentication certificates for any identity.`,
        summary: published.map((t) => t.name).join(', '),
        facts,
        affectedObjects: published.map((t) =>
          templateObject(
            t,
            `Enroll: ${grantees(t)}; requester supplies subject; EKU: ${ekuDescription(templateTraits(t))}; no approval or signatures; published by ${publishingCas(inv, t).join(', ')}`,
          ),
        ),
        notes,
      });
    }
    return pass({
      reason: 'No published template combines low-privileged enrollment, a requester-supplied subject, an authentication EKU and no issuance approval.',
      summary: `${plural(inv.templates.length, 'template')} evaluated.`,
      facts,
      notes,
    });
  },
});

export const adcsEsc2AnyPurpose = defineControl({
  id: 'ADCS-TPL-002',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'No published Any Purpose or no-EKU template is enrollable by low-privileged users without approval',
  technology: 'adcs',
  category: 'Certificate templates',
  subcategory: 'Extended key usage',
  description:
    'Finds published certificate templates that have the Any Purpose EKU or no EKU at all, that low-privileged principals can enroll in, and that require neither manager approval nor authorized signatures (commonly called ESC2).',
  rationale:
    'A certificate with Any Purpose or without any EKU restriction is accepted for every use: client authentication, code signing, server authentication and acting as an enrollment agent. If any domain user can obtain one without approval, they can impersonate servers (TLS), sign code that is trusted internally, or use it to request certificates on behalf of other users. Microsoft Defender for Identity reports such templates.',
  severity: 'high',
  confidence: 'medium',
  applicability: { description: 'Forests with at least one enterprise certification authority registered in Active Directory.' },
  requiredEvidence: ['adcs.certificateAuthorities', 'adcs.certificateTemplates'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'A template is vulnerable when a low-privileged principal has an effective Enroll right (as in ADCS-TPL-001, Deny ACEs considered), the union of pKIExtendedKeyUsage and msPKI-Certificate-Application-Policy is empty or contains Any Purpose (2.5.29.37.0), and issuance requires neither manager approval (PEND_ALL_REQUESTS) nor authorized signatures. FAIL when any such template is published by an enterprise CA; unpublished ones are noted. PASS otherwise; NOT_APPLICABLE without an enterprise CA.',
    parameters: {},
  },
  expectedState: 'Templates with Any Purpose or no EKU are not published, or are enrollable only by specific administrators and require approval.',
  remediation: {
    summary: 'Replace Any Purpose / no-EKU templates with templates limited to the EKUs actually required, restrict enrollment, or require manager approval.',
    steps: [
      'Open certtmpl.msc and open the listed template. Identify the real purpose of the certificates it issues (for example server authentication only).',
      'Extensions tab > Application Policies: remove Any Purpose and add only the specific policies required. A template with no policies at all should be given explicit policies.',
      'Security tab: remove Enroll for Domain Users, Domain Computers, Authenticated Users and Everyone; grant it to a dedicated group.',
      'If broad enrollment must remain, require CA certificate manager approval on the Issuance Requirements tab.',
      'If the template is not needed, remove it from each CA in certsrv.msc > Certificate Templates.',
    ],
    scriptExample: [
      '# Read-only review; changes are made in certtmpl.msc / certsrv.msc. AdminSecOps never runs this.',
      'certutil -CATemplates',
      "certutil -v -dsTemplate AnyPurposeTemplate",
    ].join('\n'),
    effort: 'medium',
  },
  implementationConsiderations: [
    'The built-in Subordinate Certification Authority template has no EKU by design; it must remain enrollable only by administrators.',
    ...COMMON_CONSIDERATIONS,
  ],
  impact: 'Certificates issued afterwards are limited to their intended purposes; broad self-service enrollment for this template ends.',
  rollback: ['Restore the previous template extensions and permissions in certtmpl.msc from your documented configuration.'],
  validation: [
    'In certtmpl.msc confirm the template lists only specific application policies or restricted enrollment.',
    'Re-run the AdminSecOps AD CS collector and confirm ADCS-TPL-002 is PASS.',
  ],
  references: [ADCS_REF.mdiCertificates, ADCS_REF.manageTemplates, ADCS_REF.attackStealForgeCertificates],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5(2)' },
    { framework: 'NIST-800-53r5', id: 'AC-6' },
    { framework: 'MITRE-ATTACK', id: 'T1649' },
  ],
  tags: ['adcs', 'certificates', 'privileged-access', 'esc2'],
  evaluate: (ctx) => {
    const inv = loadTemplates(ctx);
    if (inv === null) return notApplicable(NO_ENTERPRISE_CA);
    const vulnerable = inv.templates.filter((t) => {
      const traits = templateTraits(t);
      return traits.anyPurposeOrNoEku && !traits.issuanceGated && lowPrivilegedEnrollees(t).length > 0;
    });
    const { published, unpublished } = splitPublished(inv, vulnerable);
    const facts = [
      fact('Enterprise CAs', inv.caCount),
      fact('Templates evaluated', inv.templates.length),
      fact('Published vulnerable templates', published.length),
      fact('Unpublished vulnerable templates', unpublished.length),
    ];
    const notes = [...unpublishedNote(unpublished, 'have Any Purpose or no EKU and broad enrollment'), ACL_CONFIDENCE_NOTE];
    if (published.length > 0) {
      return fail({
        reason: `${plural(published.length, 'published template')} issue unrestricted-purpose certificates to low-privileged principals without approval.`,
        summary: published.map((t) => t.name).join(', '),
        facts,
        affectedObjects: published.map((t) =>
          templateObject(t, `Enroll: ${grantees(t)}; EKU: ${ekuDescription(templateTraits(t))}; no approval or signatures; published by ${publishingCas(inv, t).join(', ')}`),
        ),
        notes,
      });
    }
    return pass({
      reason: 'No published Any Purpose or no-EKU template is enrollable by low-privileged principals without approval.',
      summary: `${plural(inv.templates.length, 'template')} evaluated.`,
      facts,
      notes,
    });
  },
});

export const adcsEsc4TemplateAcl = defineControl({
  id: 'ADCS-TPL-003',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Low-privileged users cannot modify certificate templates',
  technology: 'adcs',
  category: 'Certificate templates',
  subcategory: 'Template permissions',
  description:
    'Finds certificate templates whose access control list gives low-privileged principals rights to change the template or its permissions: Full Control (GenericAll), GenericWrite, WriteDacl, WriteOwner or WriteProperty (commonly called ESC4).',
  rationale:
    'Whoever can edit a template can turn it into a vulnerable one, for example by enabling "Supply in the request" and adding Client Authentication, request a certificate for an administrator, and change it back. Template objects must therefore be writable only by PKI administrators. Microsoft Defender for Identity reports such ACL entries.',
  severity: 'high',
  confidence: 'medium',
  applicability: { description: 'Forests with at least one enterprise certification authority registered in Active Directory.' },
  requiredEvidence: ['adcs.certificateAuthorities', 'adcs.certificateTemplates'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'For every template, Allow ACEs for low-privileged principals granting GenericAll, GenericWrite, WriteDacl, WriteOwner or WriteProperty are collected, minus rights removed by Deny ACEs that apply to the same principal, Everyone or Authenticated Users. FAIL when a published template grants any of these object-wide rights. REVIEW when such rights exist only on unpublished templates (they can be abused as soon as a CA publishes the template) or only as WriteProperty on specific attributes of a published template. PASS otherwise; NOT_APPLICABLE without an enterprise CA. The template owner is not part of the evidence and is not evaluated.',
    parameters: {},
  },
  expectedState: 'Only PKI administrators (for example Enterprise Admins, Domain Admins or a dedicated PKI admin group) can modify certificate templates.',
  remediation: {
    summary: 'Remove write, Full Control, change-permission and take-ownership rights for broad groups from the listed templates.',
    steps: [
      'Open certtmpl.msc, open the listed template and go to the Security tab (use Advanced to see every entry).',
      'For Domain Users, Domain Computers, Authenticated Users, Everyone or other broad groups, clear Full Control and Write, and remove any special entries granting Write all properties, Modify permissions or Modify owner. Keep Read and, where needed, Enroll.',
      'Check the template owner under Advanced > Owner and make sure it is a PKI administrator group, not a user or broad group.',
      'Review the template settings afterwards: if they were changed by someone, restore the intended configuration and review certificates issued meanwhile.',
      'Also review the ACL of the Certificate Templates container and the Public Key Services container for the same broad write rights.',
    ],
    scriptExample: [
      '# Read-only review of a template ACL. AdminSecOps never runs this.',
      "$dn = 'CN=VulnTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,' + (Get-ADRootDSE).configurationNamingContext",
      "(Get-Acl -Path \"AD:$dn\").Access | Where-Object { $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty' } | Select-Object IdentityReference, AccessControlType, ActiveDirectoryRights, ObjectType",
      '(Get-Acl -Path "AD:$dn").Owner',
    ].join('\n'),
    effort: 'low',
  },
  implementationConsiderations: [
    'Some third-party PKI or MDM connectors are granted write access to templates; give such service accounts rights through a dedicated group rather than a broad group, and document them.',
    ...COMMON_CONSIDERATIONS.slice(0, 1),
  ],
  impact: 'Broad groups can no longer edit templates; PKI administrators are unaffected.',
  rollback: ['Re-add the removed permission entries in certtmpl.msc > Security from your documented ACL (not recommended for broad groups).'],
  validation: [
    'Re-check the template Security tab and confirm broad groups have only Read (and Enroll where intended).',
    'Re-run the AdminSecOps AD CS collector and confirm ADCS-TPL-003 is PASS.',
  ],
  references: [ADCS_REF.mdiEsc4Acl, ADCS_REF.manageTemplates, ADCS_REF.attackStealForgeCertificates],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'AC-3' },
    { framework: 'NIST-800-53r5', id: 'AC-6' },
    { framework: 'MITRE-ATTACK', id: 'T1649' },
  ],
  tags: ['adcs', 'certificates', 'privileged-access', 'acl', 'esc4'],
  evaluate: (ctx) => {
    const inv = loadTemplates(ctx);
    if (inv === null) return notApplicable(NO_ENTERPRISE_CA);
    const findings = inv.templates
      .map((t) => ({ template: t, writers: lowPrivilegedWriters(t), cas: publishingCas(inv, t) }))
      .filter((f) => f.writers.length > 0);
    const critical = findings.filter((f) => f.cas.length > 0 && f.writers.some((w) => !w.propertySpecificOnly));
    const lesser = findings.filter((f) => !critical.includes(f));
    const facts = [
      fact('Enterprise CAs', inv.caCount),
      fact('Templates evaluated', inv.templates.length),
      fact('Published templates writable by low-privileged principals', critical.length),
      fact('Other templates with low-privileged write rights', lesser.length),
    ];
    const describe = (f: (typeof findings)[number]) =>
      `${f.writers.map((w) => `${w.principal}: ${w.rights.join(', ')}`).join('; ')}; ${f.cas.length > 0 ? `published by ${f.cas.join(', ')}` : 'not published'}`;
    const affectedObjects = [...critical, ...lesser].map((f) => templateObject(f.template, describe(f)));
    const notes = [ACL_CONFIDENCE_NOTE];
    if (critical.length > 0) {
      return fail({
        reason: `${plural(critical.length, 'published template')} can be modified by low-privileged principals.`,
        summary: critical.map((f) => f.template.name).join(', '),
        facts,
        affectedObjects,
        notes,
      });
    }
    if (lesser.length > 0) {
      return review({
        reason: `Low-privileged principals have write rights on ${plural(lesser.length, 'template')} that are unpublished or limited to specific attributes.`,
        summary: lesser.map((f) => f.template.name).join(', '),
        facts,
        affectedObjects,
        notes,
      });
    }
    return pass({
      reason: 'No certificate template grants low-privileged principals rights to modify it or its permissions.',
      summary: `${plural(inv.templates.length, 'template')} evaluated.`,
      facts,
      notes,
    });
  },
});

export const adcsEsc3EnrollmentAgent = defineControl({
  id: 'ADCS-TPL-004',
  version: '1.0.0',
  lifecycle: 'stable',
  title: 'Enrollment agent templates are not enrollable by low-privileged users without approval',
  technology: 'adcs',
  category: 'Certificate templates',
  subcategory: 'Enrollment agents',
  description:
    'Finds published templates with the Certificate Request Agent EKU that low-privileged principals can enroll in without manager approval or authorized signatures, and checks whether a published authentication template would accept requests signed by such an enrollment agent (commonly called ESC3).',
  rationale:
    'An enrollment agent certificate allows its holder to request certificates on behalf of other users. If any domain user can obtain one, and a published authentication template accepts enrollment-agent requests, that user can request a sign-in certificate for an administrator. Microsoft Defender for Identity reports misconfigured enrollment agent templates.',
  severity: 'high',
  confidence: 'medium',
  applicability: { description: 'Forests with at least one enterprise certification authority registered in Active Directory.' },
  requiredEvidence: ['adcs.certificateAuthorities', 'adcs.certificateTemplates'],
  optionalEvidence: [],
  evaluation: {
    logic:
      'Agent templates: published templates whose EKUs/application policies include Certificate Request Agent (1.3.6.1.4.1.311.20.2.1), with an effective Enroll right for a low-privileged principal and no manager approval or authorized signatures. Target templates: published, authentication-capable (see ADCS-TPL-001), enrollable by a low-privileged principal, without manager approval, and schema version 1 (version 1 templates accept enrollment-agent requests without issuance requirements). FAIL when at least one agent template and one target template exist. REVIEW when agent templates exist but no version 1 target was identified, because version 2+ templates that require an authorized signature may accept the agent signature (the required application policy is not part of the evidence) and CA enrollment agent restrictions are not collected. Unpublished agent templates are noted. PASS when no exploitable agent template is published; NOT_APPLICABLE without an enterprise CA.',
    parameters: {},
  },
  expectedState: 'Enrollment agent certificates can only be requested by designated enrollment agents, with approval, and CA enrollment agent restrictions limit whom they can enroll for.',
  remediation: {
    summary: 'Restrict who can enroll for enrollment agent certificates, require approval, and configure enrollment agent restrictions on the CA.',
    steps: [
      'Open certtmpl.msc and open the listed agent template (for example "Enrollment Agent" or a copy of it).',
      'Security tab: remove Enroll for Domain Users, Domain Computers, Authenticated Users and Everyone; grant Enroll only to a group of designated enrollment agents (for example smart card issuance staff).',
      'Issuance Requirements tab: select "CA certificate manager approval".',
      'In the Certification Authority console (certsrv.msc), open the CA Properties > Enrollment Agents tab, select "Restrict enrollment agents" and define which agents may enroll for which templates and which users (exclude administrative groups).',
      'For authentication templates listed as targets, upgrade them to version 2+ copies (Duplicate Template) that require an authorized signature only where on-behalf-of enrollment is intended.',
      'If the agent template is not needed, remove it from every CA (certsrv.msc > Certificate Templates > Delete).',
    ],
    scriptExample: [
      '# Read-only review; changes are made in certtmpl.msc / certsrv.msc. AdminSecOps never runs this.',
      'certutil -CATemplates',
      'certutil -v -dsTemplate EnrollmentAgent',
    ].join('\n'),
    effort: 'medium',
  },
  implementationConsiderations: [
    'Smart card issuance stations and MDM/SCEP connectors legitimately use enrollment agent certificates; identify their accounts before restricting enrollment and add them to the dedicated group.',
    'Enrollment agent restrictions are a CA setting and are not part of the evidence collected by AdminSecOps; if you already use them, record them when reviewing this finding.',
    ...COMMON_CONSIDERATIONS.slice(0, 2),
  ],
  impact: 'Only designated enrollment agents can obtain agent certificates, and on-behalf-of requests are limited by CA restrictions.',
  rollback: ['Restore previous template permissions and issuance requirements in certtmpl.msc, and clear CA enrollment agent restrictions if they block a legitimate process.'],
  validation: [
    'In certtmpl.msc confirm the agent template is enrollable only by the designated group and requires approval.',
    'Re-run the AdminSecOps AD CS collector and confirm ADCS-TPL-004 is PASS.',
  ],
  references: [ADCS_REF.mdiCertificates, ADCS_REF.manageTemplates, ADCS_REF.attackStealForgeCertificates],
  frameworkMappings: [
    { framework: 'NIST-800-53r5', id: 'IA-5(2)' },
    { framework: 'NIST-800-53r5', id: 'AC-6' },
    { framework: 'MITRE-ATTACK', id: 'T1649' },
  ],
  tags: ['adcs', 'certificates', 'privileged-access', 'enrollment-agent', 'esc3'],
  evaluate: (ctx) => {
    const inv = loadTemplates(ctx);
    if (inv === null) return notApplicable(NO_ENTERPRISE_CA);
    const agentCandidates = inv.templates.filter((t) => {
      const traits = templateTraits(t);
      return traits.certificateRequestAgent && !traits.issuanceGated && lowPrivilegedEnrollees(t).length > 0;
    });
    const { published: agents, unpublished } = splitPublished(inv, agentCandidates);
    const targets = inv.templates.filter((t) => {
      const traits = templateTraits(t);
      return (
        publishingCas(inv, t).length > 0 &&
        traits.authenticationCapable &&
        !traits.managerApproval &&
        t.schemaVersion === 1 &&
        lowPrivilegedEnrollees(t).length > 0 &&
        !agents.includes(t)
      );
    });
    const facts = [
      fact('Enterprise CAs', inv.caCount),
      fact('Published agent templates enrollable by low-privileged principals', agents.length),
      fact('Published version 1 authentication templates (on-behalf-of targets)', targets.length),
      fact('Unpublished risky agent templates', unpublished.length),
    ];
    const notes = [
      ...unpublishedNote(unpublished, 'issue enrollment agent certificates to low-privileged principals without approval'),
      'CA enrollment agent restrictions are not collected; if they are configured they may limit this risk.',
      ACL_CONFIDENCE_NOTE,
    ];
    const agentObjects = agents.map((t) =>
      templateObject(t, `Certificate Request Agent EKU; Enroll: ${grantees(t)}; no approval or signatures; published by ${publishingCas(inv, t).join(', ')}`),
    );
    if (agents.length > 0 && targets.length > 0) {
      return fail({
        reason: `${plural(agents.length, 'published enrollment agent template')} can be enrolled by low-privileged principals, and ${plural(targets.length, 'published authentication template')} accept enrollment-agent requests.`,
        summary: `Agent: ${agents.map((t) => t.name).join(', ')}; targets: ${targets.map((t) => t.name).join(', ')}.`,
        facts,
        affectedObjects: [...agentObjects, ...targets.map((t) => templateObject(t, `Version 1 authentication template (${ekuDescription(templateTraits(t))}) that accepts on-behalf-of requests`))],
        notes,
      });
    }
    if (agents.length > 0) {
      return review({
        reason: `${plural(agents.length, 'published enrollment agent template')} can be enrolled by low-privileged principals. No version 1 authentication template was found, but version 2+ templates requiring an authorized signature may accept the agent certificate.`,
        summary: agents.map((t) => t.name).join(', '),
        facts,
        affectedObjects: agentObjects,
        notes,
      });
    }
    return pass({
      reason: 'No published enrollment agent template is enrollable by low-privileged principals without approval.',
      summary: `${plural(inv.templates.length, 'template')} evaluated.`,
      facts,
      notes,
    });
  },
});
