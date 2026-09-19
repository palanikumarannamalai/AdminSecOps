import { describe, expect, it } from 'vitest';
import {
  AdminSecOpsError,
  deterministicId,
  findSensitiveContent,
  isForbiddenPropertyName,
  redactForLog,
  safeJsonParse,
  sha256Hex,
  stableStringify,
  toPublicErrorMessage,
} from './index.js';

describe('safeJsonParse', () => {
  it('parses valid JSON and strips a UTF-8 BOM', () => {
    const bytes = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"a":1}')]);
    expect(safeJsonParse(bytes)).toEqual({ a: 1 });
  });

  it('rejects prototype pollution keys', () => {
    expect(() => safeJsonParse('{"__proto__":{"x":1}}')).toThrow(AdminSecOpsError);
    expect(() => safeJsonParse('{"a":{"constructor":{}}}')).toThrow(/forbidden property/);
  });

  it('rejects oversized input before parsing', () => {
    expect(() => safeJsonParse('[1,2,3]', { maxBytes: 3 })).toThrow(/maximum allowed size/);
  });

  it('rejects excessive nesting', () => {
    const deep = '['.repeat(100) + ']'.repeat(100);
    expect(() => safeJsonParse(deep, { maxDepth: 64 })).toThrow(/nesting depth/);
  });

  it('rejects invalid JSON and invalid UTF-8 with safe messages', () => {
    expect(() => safeJsonParse('{bad', { label: 'x.json' })).toThrow('x.json is not valid JSON.');
    expect(() => safeJsonParse(Buffer.from([0xff, 0xfe, 0x00]))).toThrow(/UTF-8/);
  });
});

describe('hashing and identifiers', () => {
  it('computes SHA-256 hex', () => {
    expect(sha256Hex('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('derives stable identifiers', () => {
    expect(deterministicId('F', 'a', 'b')).toBe(deterministicId('F', 'a', 'b'));
    expect(deterministicId('F', 'a', 'b')).not.toBe(deterministicId('F', 'ab', ''));
  });

  it('serialises with sorted keys', () => {
    expect(stableStringify({ b: 1, a: { d: 1, c: 2 } })).toBe('{"a":{"c":2,"d":1},"b":1}');
  });
});

describe('sensitive content detection', () => {
  it('matches forbidden property names regardless of case and separators', () => {
    for (const name of ['password', 'Access_Token', 'refresh-token', 'ms-Mcs-AdmPwd', 'secretText', 'hint', 'cpassword']) {
      expect(isForbiddenPropertyName(name)).toBe(true);
    }
    for (const name of ['pwdLastSet', 'passwordCredentials', 'passwordNeverExpires', 'keyId', 'tokenLifetime']) {
      expect(isForbiddenPropertyName(name)).toBe(false);
    }
  });

  it('finds secret properties and values without returning the values', () => {
    const findings = findSensitiveContent({
      data: [
        { keyId: '1', hint: 'abc' },
        { note: 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature' },
        { cert: '-----BEGIN RSA PRIVATE KEY-----\nMIIE' },
        { xml: '<Properties cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" />' },
      ],
    });
    expect(findings.map((f) => f.rule).sort()).toEqual(['forbidden-property', 'gpp-cpassword', 'jwt', 'pem-private-key']);
    expect(JSON.stringify(findings)).not.toContain('abc');
    expect(JSON.stringify(findings)).not.toContain('eyJ');
  });

  it('ignores empty forbidden properties', () => {
    expect(findSensitiveContent({ password: null, secret: '' })).toEqual([]);
  });

  it('redacts log fields', () => {
    const redacted = redactForLog({ user: 'x', accessToken: 'abc', nested: { password: 'p' } }) as Record<string, unknown>;
    expect(redacted).toEqual({ user: 'x', accessToken: '[REDACTED]', nested: { password: '[REDACTED]' } });
  });
});

describe('errors', () => {
  it('only exposes public messages', () => {
    expect(toPublicErrorMessage(new AdminSecOpsError('X', 'safe', { internalDetail: 'secret' }))).toBe('safe');
    expect(toPublicErrorMessage(new Error('C:\\Users\\admin\\token=abc'))).toBe('An unexpected internal error occurred.');
  });
});
