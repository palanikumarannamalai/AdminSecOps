import { windowsBuildNumber } from '@adminsecops/inventory';
import type { DatasetData, ObservedFact } from '@adminsecops/schemas';
import type { ControlContext, EvaluationOutcome } from '../../define.js';
import { aggregateVerdicts, type Subject, type Verdict } from '../shared/verdicts.js';

export type WindowsHost = DatasetData<'windows.hosts'>[number];

export function hostSubject(host: WindowsHost): Subject {
  return { type: 'windowsHost', id: host.hostName, name: host.hostName };
}

export function hostBuild(host: WindowsHost): number | null {
  return windowsBuildNumber(host.osBuild, host.osVersion);
}

export function osLabel(host: WindowsHost): string {
  return host.osCaption ?? 'unknown operating system';
}

/** Windows 11 client (by caption, or by build 22000+ on a non-server host). */
export function isWindows11Client(host: WindowsHost): boolean {
  if (host.isServer) return false;
  if (host.osCaption !== null && /\bwindows 11\b/i.test(host.osCaption)) return true;
  const build = hostBuild(host);
  return build !== null && build >= 22000;
}

export interface HostEvaluation {
  requirement: string;
  classify: (host: WindowsHost) => Verdict;
  reviewGuidance?: string;
  extraFacts?: ObservedFact[];
  notes?: string[];
}

/** Evaluate every host in windows.hosts; affected objects are hosts. */
export function evaluateHosts(ctx: ControlContext, evaluation: HostEvaluation): EvaluationOutcome {
  return aggregateVerdicts({
    items: ctx.data('windows.hosts'),
    subject: hostSubject,
    noun: ['host', 'hosts'],
    empty: {
      status: 'NOT_ASSESSED',
      reason: 'The Windows host evidence contains no hosts, so the configuration could not be evaluated.',
    },
    ...evaluation,
  });
}
