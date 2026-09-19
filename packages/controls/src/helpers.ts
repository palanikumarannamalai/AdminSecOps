import type { AffectedObject, ObservedFact } from '@adminsecops/schemas';
import type { EvaluationOutcome } from './define.js';

/** Build an affected object. */
export function affected(type: string, id: string, name: string, detail?: string): AffectedObject {
  return detail === undefined ? { type, id, name } : { type, id, name, detail };
}

/** Build an observed fact. */
export function fact(label: string, value: string | number | boolean | null): ObservedFact {
  return { label, value };
}

export function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

type OutcomeInit = Omit<EvaluationOutcome, 'status' | 'observed'> & {
  summary: string;
  facts?: EvaluationOutcome['observed']['facts'];
};

function outcome(status: EvaluationOutcome['status'], init: OutcomeInit): EvaluationOutcome {
  const { summary, facts, ...rest } = init;
  return { status, observed: facts === undefined ? { summary } : { summary, facts }, ...rest };
}

export const pass = (init: OutcomeInit): EvaluationOutcome => outcome('PASS', init);
export const fail = (init: OutcomeInit): EvaluationOutcome => outcome('FAIL', init);
export const review = (init: OutcomeInit): EvaluationOutcome => outcome('REVIEW', init);
export const notApplicable = (init: OutcomeInit): EvaluationOutcome => outcome('NOT_APPLICABLE', init);
export const notAssessed = (init: OutcomeInit): EvaluationOutcome => outcome('NOT_ASSESSED', init);

/** Case-insensitive string equality. */
export function eqi(a: string | null | undefined, b: string): boolean {
  return (a ?? '').toLowerCase() === b.toLowerCase();
}
