import { describe, expect, it } from 'vitest';
import { nsg, nsgRule, SUB_B } from '../../../test/builders/azure.js';
import { run } from '../../../test/run.js';
import { azNsgNoInternetRdp, azNsgNoInternetSsh } from './network.js';

const data = (...groups: Record<string, unknown>[]) => ({ 'azure.networkSecurityGroups': groups });

describe('AZ-NET-001 RDP from the internet', () => {
  it('passes when RDP is only allowed from a private range', () => {
    const result = run(azNsgNoInternetRdp, data(nsg('nsg-app', [nsgRule({ source: '10.0.0.0/8' })])));
    expect(result.status).toBe('PASS');
  });

  it.each([
    ['*', '3389'],
    ['Internet', '3389'],
    ['Any', '3389'],
    ['0.0.0.0/0', '3389'],
    ['*', '3000-4000'],
    ['*', '*'],
  ])('fails for source %s and port %s', (source, port) => {
    const result = run(azNsgNoInternetRdp, data(nsg('nsg-web', [nsgRule({ name: 'allow-rdp', source, port })])));
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects[0]?.name).toBe('nsg-web');
    expect(result.affectedObjects[0]?.detail).toContain('allow-rdp');
  });

  it('fails for internet sources and ports given as arrays', () => {
    const rule = nsgRule({ source: null, sources: ['203.0.113.10/32', 'Internet'], port: null, ports: ['22', '3389'] });
    expect(run(azNsgNoInternetRdp, data(nsg('nsg-arrays', [rule]))).status).toBe('FAIL');
  });

  it('passes when the port range does not include 3389', () => {
    expect(run(azNsgNoInternetRdp, data(nsg('nsg-web', [nsgRule({ port: '3390-4000' }), nsgRule({ port: '443' })]))).status).toBe('PASS');
  });

  it('ignores Deny rules, outbound rules and UDP-only rules', () => {
    const result = run(
      azNsgNoInternetRdp,
      data(nsg('nsg', [nsgRule({ access: 'Deny' }), nsgRule({ direction: 'Outbound' }), nsgRule({ protocol: 'Udp' })])),
    );
    expect(result.status).toBe('PASS');
  });

  it('treats an Allow rule shadowed by a higher-priority internet Deny as not effective, with a note', () => {
    const result = run(
      azNsgNoInternetRdp,
      data(nsg('nsg', [nsgRule({ name: 'deny-all', access: 'Deny', priority: 100, port: '*' }), nsgRule({ name: 'old-rdp', priority: 200 })])),
    );
    expect(result.status).toBe('PASS');
    expect(result.notes.join(' ')).toContain('old-rdp');
  });

  it('still fails when the Deny rule has lower priority than the Allow rule', () => {
    const result = run(
      azNsgNoInternetRdp,
      data(nsg('nsg', [nsgRule({ name: 'rdp', priority: 100 }), nsgRule({ name: 'deny', access: 'Deny', priority: 4000, port: '*' })])),
    );
    expect(result.status).toBe('FAIL');
  });

  it('reports only the exposed NSGs across subscriptions', () => {
    const result = run(
      azNsgNoInternetRdp,
      data(nsg('nsg-a', [nsgRule({ source: 'VirtualNetwork' })]), nsg('nsg-b', [nsgRule()], SUB_B)),
    );
    expect(result.status).toBe('FAIL');
    expect(result.affectedObjects.map((o) => o.name)).toEqual(['nsg-b']);
  });

  it('is NOT_APPLICABLE without NSGs', () => {
    expect(run(azNsgNoInternetRdp, data()).status).toBe('NOT_APPLICABLE');
  });
});

describe('AZ-NET-002 SSH from the internet', () => {
  it('fails when SSH is open to the internet', () => {
    expect(run(azNsgNoInternetSsh, data(nsg('nsg', [nsgRule({ port: '22' })]))).status).toBe('FAIL');
  });

  it('fails for a range starting at 22', () => {
    expect(run(azNsgNoInternetSsh, data(nsg('nsg', [nsgRule({ port: '22-25', protocol: '*' })]))).status).toBe('FAIL');
  });

  it('passes when only RDP is open (evaluated by AZ-NET-001)', () => {
    expect(run(azNsgNoInternetSsh, data(nsg('nsg', [nsgRule({ port: '3389' })]))).status).toBe('PASS');
  });

  it('passes when SSH is restricted to a specific public address', () => {
    expect(run(azNsgNoInternetSsh, data(nsg('nsg', [nsgRule({ port: '22', source: '203.0.113.10/32' })]))).status).toBe('PASS');
  });
});
