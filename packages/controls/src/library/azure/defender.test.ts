import { describe, expect, it } from 'vitest';
import { ALL_KEY_PLANS_STANDARD, defenderPlans, securityContact, SUB_A, SUB_B, subscription } from '../../../test/builders/azure.js';
import { run } from '../../../test/run.js';
import { azDefenderPlans, azDefenderSecurityContacts } from './defender.js';

describe('AZ-DEF-001 Defender for Cloud plans', () => {
  it('passes when every key plan is Standard in every subscription', () => {
    const result = run(azDefenderPlans, {
      'azure.defenderPlans': [...defenderPlans(SUB_A, ALL_KEY_PLANS_STANDARD), ...defenderPlans(SUB_B, ALL_KEY_PLANS_STANDARD)],
    });
    expect(result.status).toBe('PASS');
  });

  it('requires review (never fail) when key plans are Free and lists them', () => {
    const result = run(azDefenderPlans, {
      'azure.defenderPlans': [
        ...defenderPlans(SUB_A, ALL_KEY_PLANS_STANDARD),
        ...defenderPlans(SUB_B, { ...ALL_KEY_PLANS_STANDARD, VirtualMachines: 'Free', CloudPosture: 'Free' }),
      ],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects).toHaveLength(1);
    expect(result.affectedObjects[0]?.detail).toContain('Defender for Servers');
    expect(result.affectedObjects[0]?.detail).toContain('Defender CSPM');
    expect(result.notes.join(' ')).toContain('cost');
  });

  it('ignores Free plans that are not key plans', () => {
    const result = run(azDefenderPlans, {
      'azure.defenderPlans': defenderPlans(SUB_A, { ...ALL_KEY_PLANS_STANDARD, SqlServers: 'Free', Containers: 'Free' }),
    });
    expect(result.status).toBe('PASS');
  });

  it('never passes a subscription whose plans were not reported', () => {
    const result = run(azDefenderPlans, {
      'azure.defenderPlans': defenderPlans(SUB_A, ALL_KEY_PLANS_STANDARD),
      'azure.subscriptions': [subscription(SUB_A), subscription(SUB_B)],
    });
    expect(result.status).toBe('REVIEW');
    expect(result.affectedObjects.map((o) => o.id)).toEqual([`/subscriptions/${SUB_B}`]);
  });

  it('treats a key plan missing from the evidence as not evaluable', () => {
    const { Arm: _arm, ...withoutArm } = ALL_KEY_PLANS_STANDARD;
    const result = run(azDefenderPlans, { 'azure.defenderPlans': defenderPlans(SUB_A, withoutArm) });
    expect(result.status).toBe('NOT_ASSESSED');
    expect(result.affectedObjects[0]?.detail).toContain('Defender for Resource Manager');
  });

  it('is NOT_ASSESSED when there are no plans or subscriptions', () => {
    expect(run(azDefenderPlans, { 'azure.defenderPlans': [] }).status).toBe('NOT_ASSESSED');
  });
});

describe('AZ-DEF-002 security contact notifications', () => {
  const contacts = (subscriptionId: string, list: Record<string, unknown>[]) => ({ subscriptionId, contacts: list });

  it('passes with an enabled contact with email recipients and alert notifications', () => {
    const result = run(azDefenderSecurityContacts, {
      'azure.securityContacts': [contacts(SUB_A, [securityContact()]), contacts(SUB_B, [securityContact({ emailCount: 0 })])],
    });
    expect(result.status).toBe('PASS');
  });

  it('fails when a subscription has no contact', () => {
    const result = run(azDefenderSecurityContacts, {
      'azure.securityContacts': [contacts(SUB_A, [securityContact()]), contacts(SUB_B, [])],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.id)).toEqual([`/subscriptions/${SUB_B}`]);
  });

  it('fails when alert notifications are off', () => {
    const result = run(azDefenderSecurityContacts, {
      'azure.securityContacts': [contacts(SUB_A, [securityContact({ alertMinimalSeverity: null })])],
    });
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.detail).toContain('alert notifications are off');
  });

  it('fails when there are no recipients', () => {
    const result = run(azDefenderSecurityContacts, {
      'azure.securityContacts': [contacts(SUB_A, [securityContact({ emailCount: 0, notifyRolesState: 'Off' })])],
    });
    expect(result.status).toBe('FAIL');
  });

  it('fails when the contact is disabled', () => {
    const result = run(azDefenderSecurityContacts, {
      'azure.securityContacts': [contacts(SUB_A, [securityContact({ isEnabled: false })])],
    });
    expect(result.status).toBe('FAIL');
  });

  it('does not pass when the enabled state is unknown', () => {
    const result = run(azDefenderSecurityContacts, {
      'azure.securityContacts': [contacts(SUB_A, [securityContact({ isEnabled: null })])],
    });
    expect(result.status).toBe('NOT_ASSESSED');
  });

  it('requires review for a subscription missing from the evidence', () => {
    const result = run(azDefenderSecurityContacts, {
      'azure.securityContacts': [contacts(SUB_A, [securityContact()])],
      'azure.subscriptions': [subscription(SUB_A), subscription(SUB_B)],
    });
    expect(result.status).toBe('REVIEW');
  });

  it('notes High-only alert notifications', () => {
    const result = run(azDefenderSecurityContacts, {
      'azure.securityContacts': [contacts(SUB_A, [securityContact({ alertMinimalSeverity: 'High' })])],
    });
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('High severity');
  });
});
