import type { NsgRule } from '@adminsecops/schemas';

/** Source prefixes that mean "any address on the internet". */
const INTERNET_SOURCES = new Set(['*', 'internet', 'any', '0.0.0.0/0', '0.0.0.0', '::/0']);

export function isInternetSource(prefix: string): boolean {
  return INTERNET_SOURCES.has(prefix.trim().toLowerCase());
}

/** All source prefixes of a rule (single and plural properties combined). */
export function ruleSources(rule: NsgRule): string[] {
  const sources = [...rule.sourceAddressPrefixes];
  if (rule.sourceAddressPrefix !== null && rule.sourceAddressPrefix !== '') sources.push(rule.sourceAddressPrefix);
  return sources;
}

/** All destination port expressions of a rule ("*", "3389", "1000-2000"). */
export function rulePorts(rule: NsgRule): string[] {
  const ports = [...rule.destinationPortRanges];
  if (rule.destinationPortRange !== null && rule.destinationPortRange !== '') ports.push(rule.destinationPortRange);
  return ports;
}

/** True when a port expression includes the given port. Unparseable expressions return false. */
export function portExpressionIncludes(expression: string, port: number): boolean {
  const value = expression.trim();
  if (value === '*') return true;
  const range = /^(\d{1,5})\s*-\s*(\d{1,5})$/.exec(value);
  if (range?.[1] !== undefined && range[2] !== undefined) {
    return port >= Number(range[1]) && port <= Number(range[2]);
  }
  return /^\d{1,5}$/.test(value) && Number(value) === port;
}

/** Inbound Allow rule reachable from the internet that includes the given TCP port. */
export function allowsInternetInboundToPort(rule: NsgRule, port: number): boolean {
  if (rule.direction.toLowerCase() !== 'inbound' || rule.access.toLowerCase() !== 'allow') return false;
  const protocol = rule.protocol.toLowerCase();
  if (!['*', 'tcp', 'any'].includes(protocol)) return false;
  if (!ruleSources(rule).some(isInternetSource)) return false;
  return rulePorts(rule).some((p) => portExpressionIncludes(p, port));
}
