import { redactForLog } from './sensitive.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_ORDER: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export interface Logger {
  debug(message: string, fields?: Record<string, unknown>): void;
  info(message: string, fields?: Record<string, unknown>): void;
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
  child(bindings: Record<string, unknown>): Logger;
}

export interface LoggerOptions {
  level?: LogLevel;
  /** Output sink. Defaults to process.stderr so stdout stays clean for CLI output. */
  write?: (line: string) => void;
  bindings?: Record<string, unknown>;
}

/**
 * Structured JSON-lines logger. Convention: never pass evidence payloads to the
 * logger. As a second line of defence all fields are passed through `redactForLog`.
 */
export function createLogger(options: LoggerOptions = {}): Logger {
  const minLevel = options.level ?? 'info';
  const write =
    options.write ??
    ((line: string) => {
      // Node.js: stderr keeps stdout clean for CLI output. Browsers have no process object.
      if (typeof process !== 'undefined' && typeof process.stderr?.write === 'function') process.stderr.write(`${line}\n`);
      else console.error(line);
    });
  const bindings = options.bindings ?? {};

  const log = (level: LogLevel, message: string, fields?: Record<string, unknown>): void => {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[minLevel]) return;
    const entry = {
      time: new Date().toISOString(),
      level,
      msg: message,
      ...(redactForLog({ ...bindings, ...fields }) as Record<string, unknown>),
    };
    write(JSON.stringify(entry));
  };

  return {
    debug: (m, f) => log('debug', m, f),
    info: (m, f) => log('info', m, f),
    warn: (m, f) => log('warn', m, f),
    error: (m, f) => log('error', m, f),
    child: (childBindings) =>
      createLogger({ level: minLevel, write, bindings: { ...bindings, ...childBindings } }),
  };
}

/** Logger that discards everything (tests, library defaults). */
export const silentLogger: Logger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  child: () => silentLogger,
};
