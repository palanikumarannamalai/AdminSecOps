import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export interface ApiConfig {
  /** Always a loopback address in this release; see docs/THREAT-MODEL.md. */
  host: string;
  port: number;
  /** Directory where processed assessment results are stored (sensitive). */
  dataDir: string;
  /** Built web application to serve, if present. */
  webDistDir: string;
  /** Sanitized sample evidence directories. */
  samplesDir: string;
  maxUploadBytes: number;
}

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);
const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function defaultDataDir(): string {
  const base = process.env.LOCALAPPDATA ?? path.join(homedir(), '.local', 'share');
  return path.join(base, 'AdminSecOps', 'data');
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): ApiConfig {
  const host = env.ADMINSECOPS_HOST ?? '127.0.0.1';
  if (!LOOPBACK_HOSTS.has(host)) {
    throw new Error(
      `ADMINSECOPS_HOST must be a loopback address (127.0.0.1, ::1 or localhost). The local application has no authentication and must not be exposed to the network.`,
    );
  }
  const port = Number.parseInt(env.ADMINSECOPS_PORT ?? '4310', 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('ADMINSECOPS_PORT must be a valid TCP port.');
  return {
    host,
    port,
    dataDir: path.resolve(env.ADMINSECOPS_DATA_DIR ?? defaultDataDir()),
    webDistDir: path.resolve(env.ADMINSECOPS_WEB_DIST ?? path.join(appRoot, '..', 'web', 'dist')),
    samplesDir: path.resolve(env.ADMINSECOPS_SAMPLES_DIR ?? path.join(appRoot, '..', '..', 'fixtures', 'assessments')),
    maxUploadBytes: 100 * 1024 * 1024,
  };
}
