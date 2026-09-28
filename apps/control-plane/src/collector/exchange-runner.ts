import { spawn as nodeSpawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CollectionCancelledError } from './graph-client.js';

/**
 * Server-side Exchange Online runner.
 *
 * The hosted service reads Exchange Online configuration with the signed-in administrator's
 * delegated Exchange Online token by running ONE fixed, repository-owned PowerShell script
 * (runtime/exchange/Invoke-AsoExchangeCollection.ps1) with the ExchangeOnlineManagement module.
 *
 * Security properties:
 * - No shell and no user input on the command line: the executable path comes from deployment
 *   configuration, the arguments are constant, and the request (token, UPN, tenant, limits) is
 *   written to standard input as JSON and validated again by the script.
 * - The script imports only a fixed list of Get-* cmdlets (Connect-ExchangeOnline -CommandName)
 *   and runs a fixed operation table; there is no way to supply a command.
 * - The child process gets a minimal environment (no client secret, database URL or
 *   encryption key), a hard timeout, an output size cap and is killed on cancellation.
 * - Standard error is discarded and error messages are never returned: only fixed status codes.
 */

export const EXCHANGE_MODULE_VERSION = '3.10.1';
export const EXCHANGE_MIN_POWERSHELL = '7.6';

/** Fixed operation table. Must match the script (a test enforces it). */
export const EXCHANGE_OPERATIONS = {
  organizationConfig: { cmdlet: 'Get-OrganizationConfig', single: true },
  transportConfig: { cmdlet: 'Get-TransportConfig', single: true },
  adminAuditLogConfig: { cmdlet: 'Get-AdminAuditLogConfig', single: true },
  acceptedDomains: { cmdlet: 'Get-AcceptedDomain', single: false },
  dkimSigningConfigs: { cmdlet: 'Get-DkimSigningConfig', single: false },
  outboundSpamPolicies: { cmdlet: 'Get-HostedOutboundSpamFilterPolicy', single: false },
  remoteDomains: { cmdlet: 'Get-RemoteDomain', single: false },
  mailboxForwarding: { cmdlet: 'Get-EXOMailbox', single: false },
  smtpAuthMailboxes: { cmdlet: 'Get-EXOCASMailbox', single: false },
  atpPolicy: { cmdlet: 'Get-AtpPolicyForO365', single: true },
  inboxRules: { cmdlet: 'Get-InboxRule', single: false },
  transportRules: { cmdlet: 'Get-TransportRule', single: false },
} as const;
export type ExchangeOperationId = keyof typeof EXCHANGE_OPERATIONS;
const OPERATION_IDS = Object.keys(EXCHANGE_OPERATIONS) as [ExchangeOperationId, ...ExchangeOperationId[]];

export interface ExchangeRunRequest {
  readonly tenantId: string;
  readonly userPrincipalName: string;
  readonly accessToken: string;
  /** Maximum objects returned per list operation; more makes the dataset Partial. */
  readonly maxItems: number;
  /** Maximum CAS mailboxes scanned for SMTP AUTH overrides. */
  readonly maxMailboxScan: number;
}

export type ExchangeItem = Readonly<Record<string, string | number | boolean | null>>;
export type ExchangeOperationResult =
  | { readonly status: 'ok'; readonly items: readonly ExchangeItem[]; readonly truncated: boolean }
  | { readonly status: 'unauthorized' | 'not-available' | 'failed' };

export interface ExchangeRunResult {
  readonly kind: 'adminsecops.exchange.result';
  readonly status: 'ok' | 'connect-unauthorized' | 'connect-failed' | 'invalid-request' | 'runtime-unavailable';
  readonly connectedTenantId: string | null;
  readonly operations: Partial<Record<ExchangeOperationId, ExchangeOperationResult>>;
}

interface ExchangeProbe {
  readonly ok: boolean;
  readonly powershellVersion: string | null;
  readonly moduleVersion: string | null;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const shortString = (v: unknown, max: number): v is string => typeof v === 'string' && v.length <= max;
const nullableShort = (v: unknown, max: number): boolean => v === null || shortString(v, max);

function parseItem(v: unknown): ExchangeItem | undefined {
  if (!isObject(v)) return undefined;
  const entries = Object.entries(v);
  if (entries.length > 50) return undefined;
  for (const [key, value] of entries) {
    if (key.length > 100) return undefined;
    if (!(value === null || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value)) || shortString(value, 4096))) return undefined;
  }
  return v as ExchangeItem;
}

function parseOperation(v: unknown): ExchangeOperationResult | undefined {
  if (!isObject(v)) return undefined;
  if (v['status'] === 'unauthorized' || v['status'] === 'not-available' || v['status'] === 'failed') return { status: v['status'] };
  if (v['status'] !== 'ok' || typeof v['truncated'] !== 'boolean' || !Array.isArray(v['items']) || v['items'].length > 100_000) return undefined;
  const items: ExchangeItem[] = [];
  for (const raw of v['items'] as unknown[]) {
    const item = parseItem(raw);
    if (item === undefined) return undefined;
    items.push(item);
  }
  return { status: 'ok', items, truncated: v['truncated'] };
}

/** Strict validation of the runner output; anything unexpected is rejected as a whole. */
export function parseRunResult(v: unknown): ExchangeRunResult | undefined {
  if (!isObject(v) || v['kind'] !== 'adminsecops.exchange.result') return undefined;
  const status = v['status'];
  if (status !== 'ok' && status !== 'connect-unauthorized' && status !== 'connect-failed' && status !== 'invalid-request' && status !== 'runtime-unavailable') return undefined;
  if (!nullableShort(v['connectedTenantId'], 100)) return undefined;
  const rawOps = v['operations'] ?? {};
  if (!isObject(rawOps)) return undefined;
  const operations: Partial<Record<ExchangeOperationId, ExchangeOperationResult>> = {};
  for (const [id, raw] of Object.entries(rawOps)) {
    if (!OPERATION_IDS.includes(id as ExchangeOperationId)) return undefined;
    const op = parseOperation(raw);
    if (op === undefined) return undefined;
    operations[id as ExchangeOperationId] = op;
  }
  return { kind: 'adminsecops.exchange.result', status, connectedTenantId: (v['connectedTenantId'] as string | null) ?? null, operations };
}

function parseProbe(v: unknown): ExchangeProbe | undefined {
  if (!isObject(v) || v['kind'] !== 'adminsecops.exchange.probe' || typeof v['ok'] !== 'boolean') return undefined;
  if (!nullableShort(v['powershellVersion'], 50) || !nullableShort(v['moduleVersion'], 50)) return undefined;
  return { ok: v['ok'], powershellVersion: (v['powershellVersion'] as string | null) ?? null, moduleVersion: (v['moduleVersion'] as string | null) ?? null };
}

export interface ExchangeRuntimeStatus {
  readonly available: boolean;
  /** Secret-free explanation shown to administrators. */
  readonly reason: string;
}

export interface ExchangeRunner {
  /** Whether the server has the PowerShell runtime and pinned module. */
  status(signal?: AbortSignal): Promise<ExchangeRuntimeStatus>;
  run(request: ExchangeRunRequest, signal?: AbortSignal): Promise<ExchangeRunResult>;
}

/** A runner failure. `code` is fixed text; nothing from the child process is included. */
export class ExchangeRunnerError extends Error {
  readonly code: 'RUNTIME_UNAVAILABLE' | 'TIMEOUT' | 'OUTPUT_TOO_LARGE' | 'INVALID_OUTPUT' | 'PROCESS_FAILED';
  constructor(code: ExchangeRunnerError['code'], text: string) {
    super(text);
    this.name = 'ExchangeRunnerError';
    this.code = code;
  }
}

type SpawnFn = typeof nodeSpawn;

export interface PowerShellRunnerOptions {
  /** Absolute path of pwsh. */
  readonly pwshPath: string;
  readonly scriptPath?: string;
  readonly timeoutMs?: number;
  readonly maxOutputBytes?: number;
  /** Extra environment for the child (only PSModulePath / HOME / TMPDIR are copied). */
  readonly env?: NodeJS.ProcessEnv;
  readonly spawn?: SpawnFn;
}

export const DEFAULT_EXCHANGE_SCRIPT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../runtime/exchange/Invoke-AsoExchangeCollection.ps1',
);

const BEGIN = '@@ADMINSECOPS-RESULT-BEGIN@@';
const END = '@@ADMINSECOPS-RESULT-END@@';

/** Environment passed to PowerShell: only what it needs to start and find the module. */
export function childEnvironment(source: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { POWERSHELL_TELEMETRY_OPTOUT: '1', POWERSHELL_UPDATECHECK: 'Off', DOTNET_CLI_TELEMETRY_OPTOUT: '1' };
  for (const key of ['PATH', 'HOME', 'TMPDIR', 'PSModulePath', 'SystemRoot', 'TEMP', 'TMP', 'USERPROFILE']) {
    const value = source[key];
    if (typeof value === 'string' && value !== '') env[key] = value;
  }
  // Azure App Service reserves PSModulePath as an app-setting name. Map our own
  // setting only into the isolated PowerShell child's environment.
  const modulePath = source['EXCHANGE_MODULE_PATH'];
  if (typeof modulePath === 'string' && modulePath !== '') {
    if (!path.isAbsolute(modulePath)) throw new Error('The Exchange module path must be absolute.');
    env['PSModulePath'] = modulePath;
  }
  return env;
}

export class PowerShellExchangeRunner implements ExchangeRunner {
  private readonly options: Required<Omit<PowerShellRunnerOptions, 'env' | 'spawn'>> & { env: NodeJS.ProcessEnv; spawn: SpawnFn };
  private cached: { at: number; status: ExchangeRuntimeStatus } | undefined;
  private probing: Promise<ExchangeRuntimeStatus> | undefined;

  constructor(options: PowerShellRunnerOptions) {
    if (!path.isAbsolute(options.pwshPath)) throw new Error('The PowerShell path must be absolute.');
    this.options = {
      pwshPath: options.pwshPath,
      scriptPath: options.scriptPath ?? DEFAULT_EXCHANGE_SCRIPT,
      timeoutMs: options.timeoutMs ?? 300_000,
      maxOutputBytes: options.maxOutputBytes ?? 32 * 1024 * 1024,
      env: childEnvironment(options.env ?? process.env),
      spawn: options.spawn ?? nodeSpawn,
    };
  }

  async status(signal?: AbortSignal): Promise<ExchangeRuntimeStatus> {
    if (this.cached !== undefined && Date.now() - this.cached.at < 10 * 60_000) return this.cached.status;
    // One probe at a time: concurrent callers share it instead of starting more processes.
    this.probing ??= this.probe(signal).finally(() => { this.probing = undefined; });
    return this.probing;
  }

  private async probe(signal?: AbortSignal): Promise<ExchangeRuntimeStatus> {
    let status: ExchangeRuntimeStatus;
    try {
      const probe = parseProbe(await this.execute({ mode: 'probe' }, Math.min(this.options.timeoutMs, 60_000), signal));
      status = probe === undefined
        ? { available: false, reason: 'The Exchange Online runtime check returned an unexpected result.' }
        : probe.ok
          ? { available: true, reason: `PowerShell ${probe.powershellVersion ?? '?'} with ExchangeOnlineManagement ${probe.moduleVersion ?? '?'} is installed.` }
          : { available: false, reason: `The server needs PowerShell ${EXCHANGE_MIN_POWERSHELL} or later with ExchangeOnlineManagement ${EXCHANGE_MODULE_VERSION}; found PowerShell ${probe.powershellVersion ?? 'none'} and module ${probe.moduleVersion ?? 'none'}.` };
    } catch (error) {
      if (error instanceof CollectionCancelledError) throw error;
      status = { available: false, reason: 'PowerShell is not installed or could not be started on this server.' };
    }
    this.cached = { at: Date.now(), status };
    return status;
  }

  async run(request: ExchangeRunRequest, signal?: AbortSignal): Promise<ExchangeRunResult> {
    const parsed = parseRunResult(await this.execute({ mode: 'collect', ...request }, this.options.timeoutMs, signal));
    if (parsed === undefined) throw new ExchangeRunnerError('INVALID_OUTPUT', 'The Exchange Online runner returned an unexpected result.');
    return parsed;
  }

  private execute(input: Record<string, unknown>, timeoutMs: number, signal?: AbortSignal): Promise<unknown> {
    const { pwshPath, scriptPath, maxOutputBytes, env, spawn } = this.options;
    return new Promise((resolve, reject) => {
      if (signal?.aborted === true) {
        reject(new CollectionCancelledError());
        return;
      }
      let settled = false;
      const chunks: Buffer[] = [];
      let size = 0;
      const child = spawn(pwshPath, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File', scriptPath], {
        shell: false,
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'ignore'],
        env,
      });
      const finish = (error: Error | null, value?: unknown): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        if (error !== null) {
          child.kill('SIGKILL');
          reject(error);
        } else resolve(value);
      };
      const onAbort = (): void => finish(new CollectionCancelledError());
      const timer = setTimeout(() => finish(new ExchangeRunnerError('TIMEOUT', 'The Exchange Online collection exceeded its time limit.')), timeoutMs);
      signal?.addEventListener('abort', onAbort, { once: true });
      child.on('error', () => finish(new ExchangeRunnerError('RUNTIME_UNAVAILABLE', 'PowerShell could not be started on this server.')));
      child.stdout?.on('data', (chunk: Buffer) => {
        size += chunk.byteLength;
        if (size > maxOutputBytes) finish(new ExchangeRunnerError('OUTPUT_TOO_LARGE', 'The Exchange Online collection output exceeded its size limit.'));
        else chunks.push(chunk);
      });
      child.on('close', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        const start = text.lastIndexOf(BEGIN);
        const end = text.lastIndexOf(END);
        if (start < 0 || end < start) {
          finish(new ExchangeRunnerError('PROCESS_FAILED', 'The Exchange Online runner ended without a result.'));
          return;
        }
        try {
          finish(null, JSON.parse(text.slice(start + BEGIN.length, end)) as unknown);
        } catch {
          finish(new ExchangeRunnerError('INVALID_OUTPUT', 'The Exchange Online runner returned an unexpected result.'));
        }
      });
      child.stdin?.on('error', () => undefined);
      child.stdin?.end(JSON.stringify(input));
    });
  }
}
