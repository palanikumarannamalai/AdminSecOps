/** Registry values evaluated by Windows and Group Policy controls. */
export const REGISTRY = {
  lmCompatibilityLevel: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel',
  wdigestUseLogonCredential: 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential',
} as const;

/** "Network security: LAN Manager authentication level" options by LmCompatibilityLevel value. */
export const LM_LEVEL_LABELS: Readonly<Record<number, string>> = {
  0: 'Send LM & NTLM responses',
  1: 'Send LM & NTLM - use NTLMv2 session security if negotiated',
  2: 'Send NTLM response only',
  3: 'Send NTLMv2 response only',
  4: 'Send NTLMv2 response only. Refuse LM',
  5: 'Send NTLMv2 response only. Refuse LM & NTLM',
};

/** Windows default LmCompatibilityLevel when the value is not configured (Windows Vista / Server 2008 and later). */
export const LM_LEVEL_OS_DEFAULT = 3;
