import {
  CONTROL_STATUSES,
  ENGINE_VERSION,
  RESULT_SCHEMA_VERSION,
  SEVERITIES,
  TECHNOLOGIES,
  deterministicId,
  isFindingStatus,
  type ControlStatus,
  type Technology,
} from '@adminsecops/core';
import { CONTROL_LIBRARY_VERSION, type ControlDefinition } from '@adminsecops/controls';
import type { EvidenceBundle } from '@adminsecops/evidence/browser';
import { Inventory, datasetAvailability, summarizeInventory } from '@adminsecops/inventory';
import type {
  AssessmentResult,
  AssessmentSummary,
  ControlResult,
  Finding,
  StatusCounts,
} from '@adminsecops/schemas';
import { evaluateControl } from './evaluate.js';
import { prioritize } from './prioritize.js';

export interface AssessmentOptions {
  /** Processing timestamp; injectable for reproducible tests. */
  processedAt?: Date;
}

/**
 * Run the full deterministic assessment over a verified evidence bundle:
 * inventory -> control results -> findings -> prioritization -> summary.
 * Given the same evidence and control library the output is identical apart from
 * `processedAt`.
 */
export function runAssessment(
  bundle: EvidenceBundle,
  controls: readonly ControlDefinition[],
  options: AssessmentOptions = {},
): AssessmentResult {
  const inventory = Inventory.fromBundle(bundle);
  const ordered = [...controls].sort((a, b) => a.metadata.id.localeCompare(b.metadata.id));
  const results = ordered.map((control) => evaluateControl(control, inventory));
  const findings = buildFindings(inventory.assessmentId, ordered, results);

  return {
    resultSchemaVersion: RESULT_SCHEMA_VERSION,
    engineVersion: ENGINE_VERSION,
    controlLibraryVersion: CONTROL_LIBRARY_VERSION,
    assessmentId: bundle.manifest.assessmentId,
    assessedAt: bundle.manifest.createdAt,
    processedAt: (options.processedAt ?? new Date()).toISOString(),
    collection: {
      collector: {
        name: bundle.manifest.collector.name,
        version: bundle.manifest.collector.version,
        powershellVersion: bundle.manifest.collector.powershellVersion,
        platform: bundle.manifest.collector.platform,
      },
      environment: bundle.manifest.environment,
      options: bundle.manifest.options,
      modules: bundle.manifest.modules,
      manifestSha256: bundle.manifestSha256,
    },
    evidence: {
      integrityVerified: bundle.integrityVerified,
      files: [...bundle.files],
      datasets: datasetAvailability(inventory),
      issues: [...bundle.issues],
    },
    inventory: summarizeInventory(inventory),
    summary: summarize(results, findings),
    results,
    findings,
  };
}

export function buildFindings(
  assessmentId: string,
  controls: readonly ControlDefinition[],
  results: readonly ControlResult[],
): Finding[] {
  const byId = new Map(controls.map((c) => [c.metadata.id, c]));
  const candidates = results.filter((r) => isFindingStatus(r.status));
  const priorities = prioritize(
    candidates.map((r) => {
      const meta = byId.get(r.controlId)?.metadata;
      return {
        key: r.controlId,
        status: r.status as 'FAIL' | 'REVIEW',
        severity: r.severity,
        confidence: r.confidence,
        tags: meta?.tags ?? [],
        effort: meta?.remediation.effort ?? 'medium',
      };
    }),
  );

  const findings: Finding[] = [];
  for (const result of candidates) {
    const control = byId.get(result.controlId);
    const priority = priorities.get(result.controlId);
    if (control === undefined || priority === undefined) continue;
    const meta = control.metadata;
    findings.push({
      findingId: deterministicId('F', assessmentId, result.controlId),
      findingKey: result.controlId,
      assessmentId,
      controlId: result.controlId,
      controlVersion: result.controlVersion,
      status: result.status as 'FAIL' | 'REVIEW',
      severity: result.severity,
      confidence: result.confidence,
      technology: result.technology,
      category: result.category,
      title: meta.title,
      description: meta.description,
      observedState: { summary: result.observed.summary, facts: result.observed.facts },
      expectedState: meta.expectedState,
      affectedObjects: result.affectedObjects,
      affectedObjectCount: result.affectedObjectCount,
      evidence: result.evidence,
      risk: meta.rationale,
      remediation: meta.remediation,
      implementationConsiderations: meta.implementationConsiderations,
      impact: meta.impact,
      rollback: meta.rollback,
      validation: meta.validation,
      references: meta.references,
      frameworkMappings: meta.frameworkMappings,
      tags: meta.tags,
      effort: meta.remediation.effort,
      notes: result.notes,
      priority,
    });
  }
  return findings.sort((a, b) => a.priority.rank - b.priority.rank);
}

function emptyStatusCounts(): StatusCounts {
  return Object.fromEntries(CONTROL_STATUSES.map((s) => [s, 0])) as StatusCounts;
}

export function summarize(results: readonly ControlResult[], findings: readonly Finding[]): AssessmentSummary {
  const byStatus = emptyStatusCounts();
  const byTechnology = {} as Record<Technology, StatusCounts>;
  for (const tech of TECHNOLOGIES) byTechnology[tech] = emptyStatusCounts();
  for (const result of results) {
    byStatus[result.status] += 1;
    byTechnology[result.technology][result.status] += 1;
  }
  const findingsBySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as AssessmentSummary['findingsBySeverity'];
  for (const finding of findings) findingsBySeverity[finding.severity] += 1;

  const assessedStatuses: ControlStatus[] = ['PASS', 'FAIL', 'REVIEW'];
  const assessed = assessedStatuses.reduce((sum, s) => sum + byStatus[s], 0);
  const applicable = results.length - byStatus.NOT_APPLICABLE;
  return {
    controlsEvaluated: results.length,
    byStatus,
    findingsBySeverity,
    byTechnology,
    assessmentCoverage: { assessed, applicable },
  };
}
