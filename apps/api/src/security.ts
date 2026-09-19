import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { AdminSecOpsError } from '@adminsecops/core';

export const CLIENT_HEADER = 'x-adminsecops-client';

/** CSP for the dashboard: only same-origin scripts, styles, images and API calls. */
export const APP_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
};

export function allowedHosts(port: number): Set<string> {
  return new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
}

/**
 * Protections for a local, unauthenticated web service (docs/THREAT-MODEL.md):
 * - Host header allowlist defeats DNS-rebinding attacks from malicious websites.
 * - State-changing requests require a custom header, which browsers cannot send
 *   cross-origin without a CORS preflight that this server never approves (CSRF).
 * - Cross-origin Origin headers are rejected outright.
 * - Security headers and no-store caching on every response.
 */
export function registerSecurity(app: FastifyInstance, port: number, extraHosts: readonly string[] = []): void {
  const hosts = allowedHosts(port);
  for (const h of extraHosts) hosts.add(h);

  app.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    const host = (request.headers.host ?? '').toLowerCase();
    if (!hosts.has(host)) {
      await reply.code(421).send({ error: { code: 'HOST_NOT_ALLOWED', message: 'Requests must be addressed to the local AdminSecOps application.' } });
      return reply;
    }
    const origin = request.headers.origin;
    if (origin !== undefined && origin !== 'null') {
      let originHost: string;
      try {
        originHost = new URL(origin).host.toLowerCase();
      } catch {
        originHost = '';
      }
      if (!hosts.has(originHost)) {
        await reply.code(403).send({ error: { code: 'ORIGIN_NOT_ALLOWED', message: 'Cross-origin requests are not permitted.' } });
        return reply;
      }
    }
    const mutating = !['GET', 'HEAD', 'OPTIONS'].includes(request.method);
    if (mutating && request.headers[CLIENT_HEADER] !== 'web' && request.headers[CLIENT_HEADER] !== 'cli') {
      await reply.code(403).send({ error: { code: 'CLIENT_HEADER_REQUIRED', message: 'Missing X-AdminSecOps-Client header.' } });
      return reply;
    }
    if (request.method === 'OPTIONS') {
      await reply.code(405).send({ error: { code: 'METHOD_NOT_ALLOWED', message: 'CORS is not supported.' } });
      return reply;
    }
    return undefined;
  });

  app.addHook('onSend', async (request, reply, payload) => {
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) reply.header(name, value);
    if (!reply.hasHeader('Content-Security-Policy')) reply.header('Content-Security-Policy', APP_CSP);
    if (request.url.startsWith('/api/')) reply.header('Cache-Control', 'no-store');
    return payload;
  });
}

export function requireFound<T>(value: T | undefined, what = 'Assessment'): T {
  if (value === undefined) throw new AdminSecOpsError('NOT_FOUND', `${what} not found.`, { statusCode: 404 });
  return value;
}
