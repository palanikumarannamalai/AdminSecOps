/**
 * Detection of secret material in evidence and log output.
 *
 * AdminSecOps must never store passwords, password hashes, tokens, private keys,
 * authentication cookies or content (mail bodies, messages, documents). Collectors
 * are designed not to request such data; this module is a defence-in-depth check
 * applied to every evidence file on ingestion and to structured log fields.
 */

/**
 * Property names that must never appear in evidence. Comparison is case-insensitive
 * and ignores '-', '_' and '.' so that `access_token`, `AccessToken` and
 * `ms-Mcs-AdmPwd` are all matched. Names are deliberately exact (not substring)
 * so legitimate metadata such as `pwdLastSet` or `passwordCredentials` is allowed.
 */
const FORBIDDEN_PROPERTY_NAMES = [
  'password',
  'passwd',
  'passwordhash',
  'passwordvalue',
  'secret',
  'secrettext',
  'clientsecret',
  'hint', // passwordCredential.hint contains the first characters of a client secret
  'accesstoken',
  'refreshtoken',
  'idtoken',
  'bearertoken',
  'sastoken',
  'privatekey',
  'privatekeypem',
  'accountkey',
  'primarykey',
  'secondarykey',
  'connectionstring',
  'cpassword',
  'nthash',
  'lmhash',
  'unicodepwd',
  'userpassword',
  'msmcsadmpwd',
  'mslapspassword',
  'mslapsencryptedpassword',
  'mslapsencryptedpasswordhistory',
  'dbcspwd',
  'supplementalcredentials',
  'cookie',
  'setcookie',
  'authorization',
  'body',
  'uniquebody',
  'bodypreview',
  'messagebody',
  'mimecontent',
] as const;

const FORBIDDEN_NAME_SET: ReadonlySet<string> = new Set(FORBIDDEN_PROPERTY_NAMES);

export function normalizePropertyName(name: string): string {
  return name.toLowerCase().replace(/[-_.\s]/g, '');
}

export function isForbiddenPropertyName(name: string): boolean {
  return FORBIDDEN_NAME_SET.has(normalizePropertyName(name));
}

interface ValuePattern {
  id: string;
  description: string;
  pattern: RegExp;
}

/** Patterns for secret values that may appear under innocuous property names. */
const SECRET_VALUE_PATTERNS: readonly ValuePattern[] = [
  {
    id: 'jwt',
    description: 'JSON Web Token (access or ID token)',
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/,
  },
  {
    id: 'pem-private-key',
    description: 'PEM-encoded private key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |ENCRYPTED |OPENSSH )?PRIVATE KEY-----/,
  },
  {
    id: 'storage-account-key',
    description: 'Azure Storage connection string containing an account key',
    pattern: /AccountKey=[A-Za-z0-9+/=]{20,}/i,
  },
  {
    id: 'sas-signature',
    description: 'Shared access signature',
    pattern: /[?&]sig=[A-Za-z0-9%+/=]{20,}/i,
  },
  {
    id: 'gpp-cpassword',
    description: 'Group Policy Preferences cpassword value',
    pattern: /cpassword="[^"]+"/i,
  },
];

export interface SensitiveContentFinding {
  /** JSON path to the offending property, e.g. `$.data[3].hint`. Never contains the value. */
  path: string;
  rule: string;
  description: string;
}

/**
 * Walk a parsed JSON value and report forbidden property names and secret-looking
 * values. The returned findings never include the offending value.
 */
export function findSensitiveContent(root: unknown, maxFindings = 50): SensitiveContentFinding[] {
  const findings: SensitiveContentFinding[] = [];
  const stack: Array<{ value: unknown; path: string }> = [{ value: root, path: '$' }];

  while (stack.length > 0 && findings.length < maxFindings) {
    const item = stack.pop();
    if (item === undefined) break;
    const { value, path } = item;

    if (typeof value === 'string') {
      for (const rule of SECRET_VALUE_PATTERNS) {
        if (rule.pattern.test(value)) {
          findings.push({ path, rule: rule.id, description: rule.description });
          break;
        }
      }
      continue;
    }
    if (value === null || typeof value !== 'object') continue;

    if (Array.isArray(value)) {
      value.forEach((child, index) => stack.push({ value: child, path: `${path}[${index}]` }));
      continue;
    }

    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const childPath = `${path}.${key}`;
      if (isForbiddenPropertyName(key) && child !== null && child !== '' && child !== undefined) {
        findings.push({
          path: childPath,
          rule: 'forbidden-property',
          description: `Property name '${key}' is not permitted in evidence`,
        });
        continue;
      }
      stack.push({ value: child, path: childPath });
    }
  }
  return findings;
}

const REDACTED = '[REDACTED]';
const MAX_LOG_STRING = 500;

/**
 * Produce a copy of a log field value with sensitive properties and secret-looking
 * strings replaced. Used by the structured logger.
 */
export function redactForLog(value: unknown, depth = 0): unknown {
  if (depth > 6) return '[TRUNCATED]';
  if (typeof value === 'string') {
    if (SECRET_VALUE_PATTERNS.some((rule) => rule.pattern.test(value))) return REDACTED;
    return value.length > MAX_LOG_STRING ? `${value.slice(0, MAX_LOG_STRING)}...[truncated]` : value;
  }
  if (value === null || typeof value !== 'object') return value;
  if (value instanceof Error) return { name: value.name, message: redactForLog(value.message, depth + 1) };
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redactForLog(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    out[key] = isForbiddenPropertyName(key) ? REDACTED : redactForLog(child, depth + 1);
  }
  return out;
}
