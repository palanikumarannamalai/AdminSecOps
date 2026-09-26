import { describe, expect, it } from 'vitest';
import { caPolicy, sku } from '../../../test/builders/entra.js';
import { run } from '../../../test/run.js';
import { entraCaSignInRisk } from './conditional-access-advanced.js';

describe('risk policy descriptions', () => {
  it('does not label an ordinary MFA policy as risk-based', () => {
    const r = run(entraCaSignInRisk, { 'entra.subscribedSkus': [sku(['AAD_PREMIUM_P2'])], 'entra.conditionalAccessPolicies': [caPolicy({ displayName: 'Require MFA' })] });
    expect(r.status).toBe('REVIEW');
    expect(r.statusReason).toContain('Require MFA');
    expect(r.statusReason).not.toContain('Risk-related');
    expect(r.observed.summary).not.toContain('Risk-based');
  });
  it('still accepts a universal fresh MFA challenge as protecting high risk', () => {
    const p = { ...caPolicy(), sessionControls: { signInFrequency: { isEnabled: true, frequencyInterval: 'everyTime' } } };
    const r = run(entraCaSignInRisk, { 'entra.subscribedSkus': [sku(['AAD_PREMIUM_P2'])], 'entra.conditionalAccessPolicies': [p] });
    expect(r.status).toBe('PASS');
    expect(r.observed.summary).toContain('all risk levels');
  });
});
