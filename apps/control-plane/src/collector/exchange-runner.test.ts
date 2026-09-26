import { EventEmitter } from 'node:events';
import { existsSync, readFileSync } from 'node:fs';
import { PassThrough } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';
import type { spawn as nodeSpawn } from 'node:child_process';
import { CollectionCancelledError } from './graph-client.js';
import {
  DEFAULT_EXCHANGE_SCRIPT,
  EXCHANGE_MODULE_VERSION,
  EXCHANGE_OPERATIONS,
  ExchangeRunnerError,
  PowerShellExchangeRunner,
  childEnvironment,
  parseRunResult,
} from './exchange-runner.js';

const TENANT = '11111111-2222-4333-8444-555555555555';
const REQUEST = { tenantId: TENANT, userPrincipalName: 'admin@contoso.example', accessToken: 'exo.token.value', maxItems: 10, maxMailboxScan: 10 };
const wrap = (value: unknown): string => `WARNING: noise from the module\n@@ADMINSECOPS-RESULT-BEGIN@@${JSON.stringify(value)}@@ADMINSECOPS-RESULT-END@@`;
const okResult = { kind: 'adminsecops.exchange.result', status: 'ok', connectedTenantId: TENANT, operations: { transportConfig: { status: 'ok', truncated: false, items: [{ SmtpClientAuthenticationDisabled: true }] } } };

interface FakeChild extends EventEmitter {
  stdin: PassThrough;
  stdout: PassThrough;
  kill: ReturnType<typeof vi.fn>;
}

function fakeSpawn(behaviour: (child: FakeChild, input: string) => void) {
  const calls: { command: string; args: readonly string[]; options: Record<string, unknown>; input: Promise<string> }[] = [];
  const spawn = vi.fn((command: string, args: readonly string[], options: Record<string, unknown>) => {
    const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), kill: vi.fn() }) as FakeChild;
    const chunks: Buffer[] = [];
    const input = new Promise<string>((resolve) => {
      child.stdin.on('data', (c: Buffer) => chunks.push(c));
      child.stdin.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve(text);
        behaviour(child, text);
      });
    });
    calls.push({ command, args, options, input });
    return child;
  });
  return { spawn: spawn as unknown as typeof nodeSpawn, calls };
}

const respond = (output: string) => (child: FakeChild) => {
  child.stdout.write(output);
  child.stdout.end();
  setImmediate(() => child.emit('close', 0));
};

describe('PowerShell Exchange runner', () => {
  it('maps the Azure-compatible module setting only into the child environment', () => {
    const env = childEnvironment({ EXCHANGE_MODULE_PATH: '/home/site/tools/psmodules', PSModulePath: '/old', DATABASE_URL: 'secret' });
    expect(env['PSModulePath']).toBe('/home/site/tools/psmodules');
    expect(env['EXCHANGE_MODULE_PATH']).toBeUndefined();
    expect(env['DATABASE_URL']).toBeUndefined();
    expect(() => childEnvironment({ EXCHANGE_MODULE_PATH: 'relative/path' })).toThrow('absolute');
  });

  it('starts a fixed command with no shell, a minimal environment and the request only on stdin', async () => {
    const { spawn, calls } = fakeSpawn(respond(wrap(okResult)));
    const runner = new PowerShellExchangeRunner({
      pwshPath: '/usr/bin/pwsh',
      spawn,
      env: { PATH: '/usr/bin', HOME: '/home/app', AZURE_CLIENT_SECRET: 'client-secret', TOKEN_ENCRYPTION_KEY: 'key', DATABASE_URL: 'postgres://x' },
    });
    const result = await runner.run(REQUEST);
    expect(result.operations.transportConfig).toEqual({ status: 'ok', truncated: false, items: [{ SmtpClientAuthenticationDisabled: true }] });
    const call = calls[0]!;
    expect(call.command).toBe('/usr/bin/pwsh');
    expect(call.args).toEqual(['-NoLogo', '-NoProfile', '-NonInteractive', '-File', DEFAULT_EXCHANGE_SCRIPT]);
    expect(call.options['shell']).toBe(false);
    expect(call.options['stdio']).toEqual(['pipe', 'pipe', 'ignore']);
    const env = call.options['env'] as Record<string, string>;
    expect(env).not.toHaveProperty('AZURE_CLIENT_SECRET');
    expect(env).not.toHaveProperty('TOKEN_ENCRYPTION_KEY');
    expect(env).not.toHaveProperty('DATABASE_URL');
    expect(env['PATH']).toBe('/usr/bin');
    expect(JSON.stringify(call.args)).not.toContain(REQUEST.accessToken);
    expect(JSON.parse(await call.input)).toEqual({ mode: 'collect', ...REQUEST });
  });

  it('rejects output that is not the expected result shape', async () => {
    for (const bad of [
      { ...okResult, status: 'something-else' },
      { ...okResult, operations: { 'Set-Mailbox': { status: 'ok', truncated: false, items: [] } } },
      { ...okResult, operations: { transportConfig: { status: 'ok', truncated: false, items: [{ nested: { a: 1 } }] } } },
      { ...okResult, kind: 'other' },
    ]) {
      expect(parseRunResult(bad), JSON.stringify(bad)).toBeUndefined();
      const runner = new PowerShellExchangeRunner({ pwshPath: '/usr/bin/pwsh', spawn: fakeSpawn(respond(wrap(bad))).spawn });
      await expect(runner.run(REQUEST)).rejects.toSatisfy((e: unknown) => e instanceof ExchangeRunnerError && e.code === 'INVALID_OUTPUT');
    }
    const noMarkers = new PowerShellExchangeRunner({ pwshPath: '/usr/bin/pwsh', spawn: fakeSpawn(respond(JSON.stringify(okResult))).spawn });
    await expect(noMarkers.run(REQUEST)).rejects.toSatisfy((e: unknown) => e instanceof ExchangeRunnerError && e.code === 'PROCESS_FAILED');
  });

  it('kills the process on timeout, on oversized output and on cancellation', async () => {
    const hanging = fakeSpawn(() => undefined);
    const slow = new PowerShellExchangeRunner({ pwshPath: '/usr/bin/pwsh', spawn: hanging.spawn, timeoutMs: 20 });
    await expect(slow.run(REQUEST)).rejects.toSatisfy((e: unknown) => e instanceof ExchangeRunnerError && e.code === 'TIMEOUT');

    const big = fakeSpawn((child) => child.stdout.write('x'.repeat(2048)));
    const large = new PowerShellExchangeRunner({ pwshPath: '/usr/bin/pwsh', spawn: big.spawn, maxOutputBytes: 1024 });
    await expect(large.run(REQUEST)).rejects.toSatisfy((e: unknown) => e instanceof ExchangeRunnerError && e.code === 'OUTPUT_TOO_LARGE');

    const controller = new AbortController();
    const waiting = fakeSpawn(() => controller.abort());
    const cancelled = new PowerShellExchangeRunner({ pwshPath: '/usr/bin/pwsh', spawn: waiting.spawn });
    await expect(cancelled.run(REQUEST, controller.signal)).rejects.toBeInstanceOf(CollectionCancelledError);
    await expect(cancelled.run(REQUEST, controller.signal)).rejects.toBeInstanceOf(CollectionCancelledError);
  });

  it('reports a missing runtime and an incompatible module as unavailable, without secrets', async () => {
    const missing = vi.fn(() => {
      const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), kill: vi.fn() });
      setImmediate(() => child.emit('error', new Error('spawn ENOENT /usr/bin/pwsh')));
      return child;
    }) as unknown as typeof nodeSpawn;
    const none = await new PowerShellExchangeRunner({ pwshPath: '/usr/bin/pwsh', spawn: missing }).status();
    expect(none).toEqual({ available: false, reason: 'PowerShell is not installed or could not be started on this server.' });

    const old = fakeSpawn(respond(wrap({ kind: 'adminsecops.exchange.probe', ok: false, powershellVersion: '7.4.6', moduleVersion: null })));
    const incompatible = await new PowerShellExchangeRunner({ pwshPath: '/usr/bin/pwsh', spawn: old.spawn }).status();
    expect(incompatible.available).toBe(false);
    expect(incompatible.reason).toContain(EXCHANGE_MODULE_VERSION);

    const good = fakeSpawn(respond(wrap({ kind: 'adminsecops.exchange.probe', ok: true, powershellVersion: '7.6.0', moduleVersion: EXCHANGE_MODULE_VERSION })));
    const runner = new PowerShellExchangeRunner({ pwshPath: '/usr/bin/pwsh', spawn: good.spawn });
    // Concurrent status requests share one probe process, and the result is cached.
    const results = await Promise.all([runner.status(), runner.status(), runner.status()]);
    expect(results.every((r) => r.available)).toBe(true);
    expect(await runner.status()).toEqual(results[0]);
    expect(good.calls).toHaveLength(1);
    expect(JSON.parse(await good.calls[0]!.input)).toEqual({ mode: 'probe' });
  });

  it('requires an absolute PowerShell path and copies only allow-listed environment variables', () => {
    expect(() => new PowerShellExchangeRunner({ pwshPath: 'pwsh' })).toThrow('absolute');
    expect(Object.keys(childEnvironment({ PATH: '/bin', AZURE_CLIENT_SECRET: 's', RANDOM: 'x', PSModulePath: '/m' })).sort()).toEqual(
      ['DOTNET_CLI_TELEMETRY_OPTOUT', 'PATH', 'POWERSHELL_TELEMETRY_OPTOUT', 'POWERSHELL_UPDATECHECK', 'PSModulePath'].sort(),
    );
  });
});

const LOCAL_PWSH = [process.env['ADMINSECOPS_TEST_PWSH'] ?? '', 'C:\\Program Files\\PowerShell\\7\\pwsh.exe', '/usr/bin/pwsh', '/usr/local/bin/pwsh', '/opt/microsoft/powershell/7/pwsh'].find((p) => p !== '' && existsSync(p));

describe.skipIf(LOCAL_PWSH === undefined)('Exchange collection script with a local PowerShell (no network)', () => {
  it('parses, answers the runtime probe and rejects an invalid request before connecting', { timeout: 120_000 }, async () => {
    const runner = new PowerShellExchangeRunner({ pwshPath: LOCAL_PWSH!, timeoutMs: 60_000 });
    const status = await runner.status();
    expect(typeof status.available).toBe('boolean');
    expect(status.reason).not.toMatch(/could not be started|unexpected result/);
    // A malformed token is rejected by the script's own validation; no connection is attempted.
    const result = await runner.run({ ...REQUEST, accessToken: 'short' });
    expect(result).toEqual({ kind: 'adminsecops.exchange.result', status: 'invalid-request', connectedTenantId: null, operations: {} });
    const badTenant = await runner.run({ ...REQUEST, tenantId: '../../etc', accessToken: 'a'.repeat(40) });
    expect(badTenant.status).toBe('invalid-request');
  });
});

describe('Exchange collection script', () => {
  const script = readFileSync(DEFAULT_EXCHANGE_SCRIPT, 'utf8');

  it('runs exactly the fixed read-only cmdlets of the TypeScript operation table', () => {
    const table = [...script.matchAll(/^\s{4}(\w+)\s+=\s+@\{ Cmdlet = '([\w-]+)'/gm)].map((m) => [m[1], m[2]]);
    expect(Object.fromEntries(table)).toEqual(Object.fromEntries(Object.entries(EXCHANGE_OPERATIONS).map(([id, op]) => [id, op.cmdlet])));
    for (const [, cmdlet] of table) expect(cmdlet).toMatch(/^Get-/);
    expect(script).toContain(`$script:ModuleVersion = '${EXCHANGE_MODULE_VERSION}'`);
    expect(script).toMatch(/Connect-ExchangeOnline -AccessToken \$token -UserPrincipalName \$upn -CommandName \$cmdlets/);
  });

  it('contains no state-changing cmdlet, dynamic code or process execution', () => {
    const code = script.replace(/<#[\s\S]*?#>/g, '').replace(/#.*$/gm, '');
    for (const forbidden of [/\b(Set|New|Remove|Add|Enable|Disable|Update|Start|Stop|Clear|Import-Csv|Export)-[A-Z]\w*/g, /Invoke-(Expression|Command|WebRequest|RestMethod)/i, /\biex\b/i, /Start-Process/i, /\[scriptblock\]::Create/i, /Add-Type/i]) {
      const hits = [...code.matchAll(new RegExp(forbidden.source, forbidden.flags.includes('g') ? forbidden.flags : `${forbidden.flags}g`))].map((m) => m[0]);
      // Set-StrictMode is the only allowed Set-* (script hygiene, not a tenant change).
      expect(hits.filter((h) => h !== 'Set-StrictMode'), forbidden.source).toEqual([]);
    }
  });
});
