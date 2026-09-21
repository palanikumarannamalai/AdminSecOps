import { CONFIDENCE_RANK, type Confidence, type ControlStatus } from '@adminsecops/core';
import { ControlContext, EvidenceUnavailableError, type ControlDefinition, type EvaluationOutcome } from '@adminsecops/controls';
import type { Inventory } from '@adminsecops/inventory';
import {
  MAX_AFFECTED_OBJECTS,
  type ControlResult,
  type DatasetId,
  type EvidenceReference,
} from '@adminsecops/schemas';

/**
 * Evaluate one control against an inventory. This function defines the evaluation
 * semantics that every control inherits (see docs/CONTROL-MODEL.md):
 *
 * 1. If any required dataset is unavailable the result is NOT_ASSESSED - or
 *    NOT_APPLICABLE when every unavailable dataset was reported NotApplicable by the
 *    collector. Missing evidence is never converted into PASS.
 * 2. `applies()` may return NOT_APPLICABLE with a reason.
 * 3. Reading unavailable optional evidence during evaluation yields NOT_ASSESSED.
 * 4. Any other exception yields ERROR; the message shown is generic.
 * 5. A PASS computed from Partial evidence is downgraded to REVIEW.
 * 6. A result's confidence never exceeds the control's declared confidence.
 */
export function evaluateControl(control: ControlDefinition, inventory: Inventory): ControlResult {
  const meta = control.metadata;
  const ctx = new ControlContext(inventory, meta.evaluation.parameters);
  const required = meta.requiredEvidence as DatasetId[];

  const unavailable = required
    .map((id) => ({ id, fact: inventory.get(id) }))
    .filter((entry) => !entry.fact.available);

  if (unavailable.length > 0) {
    const allNotApplicable = unavailable.every(
      (u) => !u.fact.available && u.fact.collectionStatus === 'NotApplicable',
    );
    const reasons = unavailable.map((u) => `${u.id}: ${u.fact.available ? '' : u.fact.reason}`);
    return baseResult(control, inventory, required, {
      status: allNotApplicable ? 'NOT_APPLICABLE' : 'NOT_ASSESSED',
      reason: allNotApplicable
        ? `The collector reported the required evidence as not applicable to this environment (${unavailable.map((u) => u.id).join(', ')}).`
        : `Required evidence was not available, so this control was not assessed. ${reasons.join(' ')}`,
      observed: { summary: 'No evaluation was performed.' },
    });
  }

  let outcome: EvaluationOutcome;
  try {
    if (control.applies !== undefined) {
      const applicability = control.applies(ctx);
      if (!applicability.applicable) {
        return baseResult(control, inventory, withUsed(required, ctx), {
          status: 'NOT_APPLICABLE',
          reason: applicability.reason,
          observed: { summary: 'The control does not apply to this environment.' },
        });
      }
    }
    outcome = control.evaluate(ctx);
  } catch (error) {
    if (error instanceof EvidenceUnavailableError) {
      return baseResult(control, inventory, withUsed(required, ctx), {
        status: 'NOT_ASSESSED',
        reason: `Evidence needed for this control was not available (${error.datasetId}): ${error.reason}`,
        observed: { summary: 'No evaluation was performed.' },
      });
    }
    return baseResult(control, inventory, withUsed(required, ctx), {
      status: 'ERROR',
      reason: `The control failed to evaluate (${error instanceof Error ? error.name : 'unknown error'}). This is a defect in AdminSecOps, not a finding about your environment.`,
      observed: { summary: 'Evaluation error.' },
    });
  }

  const notes = [...(outcome.notes ?? [])];
  const partial = withUsed(required, ctx).filter((id) => {
    const fact = inventory.get(id);
    return fact.available && fact.partial;
  });
  if (outcome.status === 'PASS' && partial.length > 0) {
    notes.push(
      `The collector reported partial collection for ${partial.join(', ')}; a PASS cannot be confirmed from incomplete evidence, so this result requires review.`,
    );
    outcome = { ...outcome, status: 'REVIEW', reason: `${outcome.reason} (downgraded from PASS: evidence was only partially collected)` };
  } else if (partial.length > 0) {
    notes.push(`Evidence for ${partial.join(', ')} was partially collected; additional affected objects may exist.`);
  }

  return baseResult(control, inventory, withUsed(required, ctx), { ...outcome, notes });
}

function withUsed(required: readonly string[], ctx: ControlContext): DatasetId[] {
  return [...new Set([...required, ...ctx.usedDatasets()])] as DatasetId[];
}

function lowerConfidence(declared: Confidence, outcome: Confidence | undefined): Confidence {
  if (outcome === undefined) return declared;
  return CONFIDENCE_RANK[outcome] < CONFIDENCE_RANK[declared] ? outcome : declared;
}

function baseResult(
  control: ControlDefinition,
  inventory: Inventory,
  datasets: readonly DatasetId[],
  outcome: Omit<EvaluationOutcome, 'status'> & { status: ControlStatus },
): ControlResult {
  const meta = control.metadata;
  const affected = outcome.affectedObjects ?? [];
  const evidence: EvidenceReference[] = datasets.map((id) => inventory.reference(id));
  return {
    controlId: meta.id,
    controlVersion: meta.version,
    title: meta.title,
    technology: meta.technology,
    category: meta.category,
    subcategory: meta.subcategory,
    severity: meta.severity,
    confidence: lowerConfidence(lowerConfidence(meta.confidence, outcome.confidence), outcome.status === 'REVIEW' ? 'medium' : undefined),
    status: outcome.status,
    statusReason: outcome.reason,
    observed: { summary: outcome.observed.summary, facts: (outcome.observed.facts ?? []).slice(0, 50) },
    expected: meta.expectedState,
    affectedObjects: affected.slice(0, MAX_AFFECTED_OBJECTS),
    affectedObjectCount: affected.length,
    evidence,
    notes: (outcome.notes ?? []).slice(0, 20),
  };
}
