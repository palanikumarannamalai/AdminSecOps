import type { Reference } from '@adminsecops/schemas';

/**
 * Authoritative references used by the Active Directory controls. Only titles and
 * URLs are stored (no copied text). Every URL was checked against Microsoft Learn or
 * the publisher's site when added. Shared references live in ../../references.ts.
 */
const ms = (title: string, url: string): Reference => ({ title, url, publisher: 'Microsoft' });
const mitre = (title: string, url: string): Reference => ({ title, url, publisher: 'MITRE' });

const LEARN = 'https://learn.microsoft.com/en-us';
const MDI_ACCOUNTS = `${LEARN}/defender-for-identity/security-posture-assessments/accounts`;
const SECURITY_POLICY = `${LEARN}/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings`;
const AD_BEST_PRACTICES = `${LEARN}/windows-server/identity/ad-ds/plan/security-best-practices`;

export const AD_REF = {
  nistPasswordRequirements: {
    title: 'NIST SP 800-63B-4: Password requirements',
    url: 'https://pages.nist.gov/800-63-4/sp800-63b/authenticators/',
    publisher: 'NIST',
  },
  // --- Microsoft Defender for Identity posture assessments ----------------------
  mdiUnsecureAccountAttributes: ms(
    'Microsoft Defender for Identity: Unsecure account attributes assessment',
    `${MDI_ACCOUNTS}#unsecure-account-attributes`,
  ),
  mdiUnsecureDelegation: ms(
    'Microsoft Defender for Identity: Unsecure Kerberos delegation assessment',
    `${MDI_ACCOUNTS}#unsecure-kerberos-delegation`,
  ),
  mdiPrivilegedNotDelegated: ms(
    'Microsoft Defender for Identity: Ensure privileged accounts are not delegated',
    `${MDI_ACCOUNTS}#ensure-privileged-accounts-are-not-delegated`,
  ),
  mdiKrbtgt: ms(
    'Microsoft Defender for Identity: Change password for krbtgt account',
    `${MDI_ACCOUNTS}#change-password-for-krbtgt-account`,
  ),
  mdiDormantSensitive: ms(
    'Microsoft Defender for Identity: Dormant entities in sensitive groups',
    `${MDI_ACCOUNTS}#dormant-entities-in-sensitive-groups`,
  ),
  mdiLaps: ms('Microsoft Defender for Identity: Microsoft LAPS usage assessment', `${MDI_ACCOUNTS}#microsoft-laps-usage`),
  mdiUnsecureSidHistory: ms(
    'Microsoft Defender for Identity: Unsecure SID History attributes',
    `${MDI_ACCOUNTS}#unsecure-sid-history-attributes`,
  ),

  // --- Accounts and Kerberos ----------------------------------------------------
  userAccountControlFlags: ms(
    'Use the UserAccountControl flags to manipulate user account properties',
    `${LEARN}/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties`,
  ),
  krbtgtReset: ms(
    'AD forest recovery - Reset the krbtgt password',
    `${LEARN}/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password`,
  ),
  protectedUsers: ms(
    'Protected Users security group',
    `${LEARN}/windows-server/security/credentials-protection-and-management/protected-users-security-group`,
  ),
  gmsaOverview: ms(
    'Group Managed Service Accounts overview',
    `${LEARN}/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview`,
  ),
  kerberosConstrainedDelegation: ms(
    'Kerberos constrained delegation overview',
    `${LEARN}/windows-server/security/kerberos/kerberos-constrained-delegation-overview`,
  ),

  // --- Privileged access ----------------------------------------------------------
  privilegedGroupsAppendixB: ms(
    'Appendix B: Privileged accounts and groups in Active Directory',
    `${AD_BEST_PRACTICES}/appendix-b--privileged-accounts-and-groups-in-active-directory`,
  ),
  enterpriseAdminsAppendixE: ms(
    'Appendix E: Securing Enterprise Admins groups in Active Directory',
    `${AD_BEST_PRACTICES}/appendix-e--securing-enterprise-admins-groups-in-active-directory`,
  ),
  securingActiveDirectory: ms('Best practices for securing Active Directory', `${AD_BEST_PRACTICES}/best-practices-for-securing-active-directory`),
  schemaAdminsEmpty: ms(
    'Remove all members from the Schema Admins group unless you are actively changing the schema',
    `${LEARN}/services-hub/microsoft-engage-center/health/remediation-steps-ad/remove-all-members-from-the-schema-admins-group-unless-you-are-actively-changing-the-schema`,
  ),

  // --- Password and lockout policy ------------------------------------------------
  minimumPasswordLength: ms('Minimum password length (security policy setting)', `${SECURITY_POLICY}/minimum-password-length`),
  reversibleEncryptionPolicy: ms(
    'Store passwords using reversible encryption (security policy setting)',
    `${SECURITY_POLICY}/store-passwords-using-reversible-encryption`,
  ),
  lockoutThresholdRecommendation: ms(
    'Set the account lockout threshold to the recommended value',
    `${LEARN}/services-hub/microsoft-engage-center/health/remediation-steps-ad/set-the-account-lockout-threshold-to-the-recommended-value`,
  ),
  m365PasswordRecommendations: ms(
    'Password policy recommendations for Microsoft 365 passwords',
    `${LEARN}/microsoft-365/admin/misc/password-policy-recommendations`,
  ),
  fineGrainedPasswordPolicies: ms(
    'Configure fine grained password policies for Active Directory Domain Services',
    `${LEARN}/windows-server/identity/ad-ds/get-started/adac/fine-grained-password-policies`,
  ),

  // --- Domain and forest configuration --------------------------------------------
  machineAccountQuota: ms('ms-DS-MachineAccountQuota attribute', `${LEARN}/windows/win32/adschema/a-ms-ds-machineaccountquota`),
  recycleBin: ms('Active Directory Recycle Bin', `${LEARN}/windows-server/identity/ad-ds/get-started/adac/active-directory-recycle-bin`),
  functionalLevels: ms(
    'Active Directory Domain Services functional levels',
    `${LEARN}/windows-server/identity/ad-ds/active-directory-functional-levels`,
  ),
  netdomTrust: ms('netdom trust (quarantine / SID filtering)', `${LEARN}/windows-server/administration/windows-commands/netdom-trust`),

  // --- Computers and domain controllers -------------------------------------------
  lapsOverview: ms('Windows LAPS overview', `${LEARN}/windows-server/identity/laps/laps-overview`),
  lifecycleFaqWindows: ms('Lifecycle FAQ - Windows products', `${LEARN}/lifecycle/faq/windows`),
  ldapSigning: ms('LDAP signing for Active Directory Domain Services', `${LEARN}/windows-server/identity/ad-ds/ldap-signing`),
  ldapChannelBindingRequirements: ms(
    'LDAP session security settings and requirements after ADV190023',
    `${LEARN}/troubleshoot/windows-server/active-directory/ldap-session-security-settings-requirements-adv190023`,
  ),
  smbSigning: ms('What is Server Message Block signing?', `${LEARN}/windows-server/storage/file-server/smb-signing-overview`),

  // --- MITRE ATT&CK ---------------------------------------------------------------
  attackKerberoasting: mitre('MITRE ATT&CK T1558.003: Kerberoasting', 'https://attack.mitre.org/techniques/T1558/003/'),
  attackAsRepRoasting: mitre('MITRE ATT&CK T1558.004: AS-REP Roasting', 'https://attack.mitre.org/techniques/T1558/004/'),
  attackGoldenTicket: mitre('MITRE ATT&CK T1558.001: Golden Ticket', 'https://attack.mitre.org/techniques/T1558/001/'),
  attackKerberosTickets: mitre('MITRE ATT&CK T1558: Steal or Forge Kerberos Tickets', 'https://attack.mitre.org/techniques/T1558/'),
  attackPasswordGuessing: mitre('MITRE ATT&CK T1110.001: Password Guessing', 'https://attack.mitre.org/techniques/T1110/001/'),
  attackPasswordCracking: mitre('MITRE ATT&CK T1110.002: Password Cracking', 'https://attack.mitre.org/techniques/T1110/002/'),
  attackDomainAccounts: mitre('MITRE ATT&CK T1078.002: Domain Accounts', 'https://attack.mitre.org/techniques/T1078/002/'),
  attackPassTheHash: mitre('MITRE ATT&CK T1550.002: Pass the Hash', 'https://attack.mitre.org/techniques/T1550/002/'),
  attackAdversaryInTheMiddle: mitre('MITRE ATT&CK T1557: Adversary-in-the-Middle', 'https://attack.mitre.org/techniques/T1557/'),
  attackRemoteServices: mitre('MITRE ATT&CK T1210: Exploitation of Remote Services', 'https://attack.mitre.org/techniques/T1210/'),
  attackSidHistoryInjection: mitre(
    'MITRE ATT&CK T1134.005: SID-History Injection',
    'https://attack.mitre.org/techniques/T1134/005/',
  ),
} as const satisfies Record<string, Reference>;
