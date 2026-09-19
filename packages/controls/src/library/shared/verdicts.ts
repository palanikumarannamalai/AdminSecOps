import type { ObservedFact } from '@adminsecops/schemas';
import type { EvaluationOutcome } from '../../define.js';
import { affected, fact, fail, notApplicable, notAssessed, pass, review } from '../../helpers.js';

/**
 * Per-object verdicts aggregated into one control outcome. Used by controls that
 * evaluate a collection (hosts, storage accounts, subscriptions...) one object at a time.
 *
 * - pass: the object meets the requirement.
 * - fail: the object does not meet the requirement.
 * - review: the evidence is complete but an administrator must decide (explain why in detail).
 * - unknown: the evidence lacks a value needed to decide (never treated as compliant).
 * - na: the requirement does not apply to this object.
 *
 * Aggregation: any fail -> FAIL; otherwise any review/unknown -> REVIEW, except that when
 * every applicable object is unknown the result is NOT_ASSESSED; otherwise any pass -> PASS;
 * all objects not applicable -> NOT_APPLICABLE; no objects -> the configured empty status.
 */
export type VerdictState = 'pass' | 'fail' | 'review' | 'unknown' | 'na';

export interface Verdict {
  state: VerdictState;
  /** Why the object got this verdict (shown on affected objects). Never include secrets. */
  detail: string;
}

export interface Subject {
  type: string;
  id: string;
  name: string;
}

export interface AggregateOptions<T> {
  items: readonly T[];
  subject: (item: T) => Subject;
  classify: (item: T) => Verdict;
  /** Singular and plural noun for the objects, e.g. ['host', 'hosts']. */
  noun: readonly [string, string];
  /** Requirement in plain language, e.g. "the SMBv1 server is disabled". */
  requirement: string;
  /** Outcome when there are no objects at all. */
  empty: { status: 'NOT_APPLICABLE' | 'NOT_ASSESSED' | 'PASS'; reason: string };
  /** Explanation added when objects need administrator review. */
  reviewGuidance?: string;
  extraFacts?: ObservedFact[];
  notes?: string[];
}

export const pass_ = (detail: string): Verdict => ({ state: 'pass', detail });
export const fail_ = (detail: string): Verdict => ({ state: 'fail', detail });
export const review_ = (detail: string): Verdict => ({ state: 'review', detail });
export const unknown_ = (detail: string): Verdict => ({ state: 'unknown', detail });
export const na_ = (detail: string): Verdict => ({ state: 'na', detail });

function count(n: number, noun: readonly [string, string]): string {
  return `${n} ${n === 1 ? noun[0] : noun[1]}`;
}

export function aggregateVerdicts<T>(options: AggregateOptions<T>): EvaluationOutcome {
  const { items, noun, requirement } = options;
  const notes = [...(options.notes ?? [])];
  if (items.length === 0) {
    const init = {
      reason: options.empty.reason,
      summary: `No ${noun[1]} were found in the evidence.`,
      facts: [fact(`${capitalize(noun[1])} evaluated`, 0), ...(options.extraFacts ?? [])],
      notes,
    };
    if (options.empty.status === 'PASS') return pass(init);
    return options.empty.status === 'NOT_APPLICABLE' ? notApplicable(init) : notAssessed(init);
  }

  const results = items.map((item) => ({ subject: options.subject(item), verdict: options.classify(item) }));
  const by = (state: VerdictState) => results.filter((r) => r.verdict.state === state);
  const passed = by('pass');
  const failed = by('fail');
  const reviewed = by('review');
  const unknown = by('unknown');
  const na = by('na');
  const applicable = items.length - na.length;

  const toObject = (r: (typeof results)[number]) => affected(r.subject.type, r.subject.id, r.subject.name, r.verdict.detail);
  const facts = [
    fact(`${capitalize(noun[1])} evaluated`, items.length),
    fact('Compliant', passed.length),
    fact('Non-compliant', failed.length),
    fact('Require review', reviewed.length),
    fact('Could not be evaluated', unknown.length),
    fact('Not applicable', na.length),
    ...(options.extraFacts ?? []),
  ];

  if (unknown.length > 0 && (failed.length > 0 || passed.length > 0 || reviewed.length > 0)) {
    notes.push(
      `${count(unknown.length, noun)} could not be evaluated because the evidence did not contain the required value; they are listed as affected objects and are never counted as compliant.`,
    );
  }

  if (failed.length > 0) {
    return fail({
      reason: `${failed.length} of ${count(applicable, noun)} do not meet the requirement: ${requirement}.`,
      summary: `${count(failed.length, noun)} non-compliant, ${passed.length} compliant, ${reviewed.length + unknown.length} to review.`,
      facts,
      affectedObjects: [...failed, ...reviewed, ...unknown].map(toObject),
      notes,
    });
  }

  if (reviewed.length > 0 || unknown.length > 0) {
    if (reviewed.length === 0 && passed.length === 0) {
      return notAssessed({
        reason: `The evidence did not contain the values needed to decide whether ${requirement} for any of the ${count(unknown.length, noun)}.`,
        summary: `${count(unknown.length, noun)} could not be evaluated.`,
        facts,
        affectedObjects: unknown.map(toObject),
        notes,
      });
    }
    const parts: string[] = [];
    if (reviewed.length > 0) parts.push(`${count(reviewed.length, noun)} require administrator confirmation`);
    if (unknown.length > 0) parts.push(`${count(unknown.length, noun)} could not be evaluated from the evidence`);
    if (options.reviewGuidance !== undefined && reviewed.length > 0) notes.unshift(options.reviewGuidance);
    return review({
      reason: `No non-compliant ${noun[1]} were found, but ${parts.join(' and ')} (requirement: ${requirement}).`,
      summary: `${passed.length} compliant; ${parts.join('; ')}.`,
      facts,
      affectedObjects: [...reviewed, ...unknown].map(toObject),
      notes,
    });
  }

  if (passed.length > 0) {
    return pass({
      reason: `All ${count(passed.length, noun)} in scope meet the requirement: ${requirement}.${na.length > 0 ? ` ${count(na.length, noun)} were not applicable.` : ''}`,
      summary: `${count(passed.length, noun)} compliant.`,
      facts,
      notes,
    });
  }

  return notApplicable({
    reason: `The requirement does not apply to any of the ${count(na.length, noun)} (${na
      .slice(0, 5)
      .map((r) => `${r.subject.name}: ${r.verdict.detail}`)
      .join('; ')}).`,
    summary: `No ${noun[1]} in scope.`,
    facts,
    notes,
  });
}

function capitalize(value: string): string {
  return value.length === 0 ? value : `${value[0]?.toUpperCase() ?? ''}${value.slice(1)}`;
}
