import type { AssessmentComparison, AssessmentResult, Finding } from '@adminsecops/schemas';

type FindingChange = AssessmentComparison['changedFindings'][number];

function ref(finding: Finding, other: AssessmentResult): AssessmentComparison['newFindings'][number] {
  return {
    findingKey: finding.findingKey,
    controlId: finding.controlId,
    title: finding.title,
    severity: finding.severity,
    status: finding.status,
    otherStatus: other.results.find((r) => r.controlId === finding.controlId)?.status ?? null,
  };
}

function objectKeys(finding: Finding): Set<string> {
  return new Set(finding.affectedObjects.map((o) => `${o.type}:${o.id}`));
}

/**
 * Compare two assessments (baseline -> current). Findings are matched by findingKey
 * (control ID), which is stable across assessments. This is the foundation for
 * drift reporting; see docs/ROADMAP.md for planned configuration-level drift.
 */
export function compareAssessments(baseline: AssessmentResult, current: AssessmentResult): AssessmentComparison {
  const before = new Map(baseline.findings.map((f) => [f.findingKey, f]));
  const after = new Map(current.findings.map((f) => [f.findingKey, f]));

  const newFindings = [...after.values()].filter((f) => !before.has(f.findingKey)).map((f) => ref(f, baseline));
  const resolvedFindings = [...before.values()].filter((f) => !after.has(f.findingKey)).map((f) => ref(f, current));

  const changedFindings: FindingChange[] = [];
  let unchanged = 0;
  for (const [key, currentFinding] of after) {
    const previous = before.get(key);
    if (previous === undefined) continue;
    const changes: FindingChange['changes'] = [];
    if (previous.status !== currentFinding.status) changes.push({ field: 'status', from: previous.status, to: currentFinding.status });
    if (previous.severity !== currentFinding.severity) changes.push({ field: 'severity', from: previous.severity, to: currentFinding.severity });
    if (previous.controlVersion !== currentFinding.controlVersion) {
      changes.push({ field: 'controlVersion', from: previous.controlVersion, to: currentFinding.controlVersion });
    }
    if (previous.affectedObjectCount !== currentFinding.affectedObjectCount) {
      changes.push({ field: 'affectedObjectCount', from: previous.affectedObjectCount, to: currentFinding.affectedObjectCount });
    }
    const beforeObjects = objectKeys(previous);
    const afterObjects = objectKeys(currentFinding);
    const addedObjects = [...afterObjects].filter((o) => !beforeObjects.has(o)).sort();
    const removedObjects = [...beforeObjects].filter((o) => !afterObjects.has(o)).sort();
    if ((addedObjects.length > 0 || removedObjects.length > 0) && !changes.some((c) => c.field === 'affectedObjectCount')) {
      changes.push({ field: 'affectedObjects', from: beforeObjects.size, to: afterObjects.size });
    }
    if (changes.length === 0) {
      unchanged += 1;
      continue;
    }
    changedFindings.push({
      findingKey: key,
      controlId: currentFinding.controlId,
      title: currentFinding.title,
      severity: currentFinding.severity,
      changes,
      addedObjects,
      removedObjects,
    });
  }

  const beforeStatus = new Map(baseline.results.map((r) => [r.controlId, r]));
  const afterStatus = new Map(current.results.map((r) => [r.controlId, r]));
  const controlIds = [...new Set([...beforeStatus.keys(), ...afterStatus.keys()])].sort();
  const controlStatusChanges = controlIds
    .map((id) => ({
      controlId: id,
      title: afterStatus.get(id)?.title ?? beforeStatus.get(id)?.title ?? id,
      from: beforeStatus.get(id)?.status ?? null,
      to: afterStatus.get(id)?.status ?? null,
    }))
    .filter((c) => c.from !== c.to);

  const envA = baseline.collection.environment;
  const envB = current.collection.environment;
  const sameEnvironment =
    (envA.tenantId === null || envB.tenantId === null || envA.tenantId.toLowerCase() === envB.tenantId.toLowerCase()) &&
    (envA.adForestName === null || envB.adForestName === null || envA.adForestName.toLowerCase() === envB.adForestName.toLowerCase());

  // Only changes between two *assessed* states count as improvement or regression:
  // a finding that disappears because evidence was not collected is not an improvement,
  // and a finding that appears because evidence was newly collected is not a regression.
  const assessed = (status: string | null) => status !== null && status !== 'NOT_ASSESSED' && status !== 'ERROR';
  const improved = resolvedFindings.some((f) => assessed(f.otherStatus));
  const regressed = newFindings.some((f) => assessed(f.otherStatus));
  const direction = improved && regressed ? 'mixed' : improved ? 'improved' : regressed ? 'regressed' : 'unchanged';

  return {
    baseline: { assessmentId: baseline.assessmentId, assessedAt: baseline.assessedAt },
    current: { assessmentId: current.assessmentId, assessedAt: current.assessedAt },
    sameEnvironment,
    factChanges: sameEnvironment ? current.results.flatMap(r=>{const prior=baseline.results.find(p=>p.controlId===r.controlId);if(!prior||prior.controlVersion!==r.controlVersion||['NOT_ASSESSED','ERROR'].includes(prior.status)||['NOT_ASSESSED','ERROR'].includes(r.status))return [];
      return r.observed.facts.flatMap(f=>{const old=prior.observed.facts.filter(o=>o.label===f.label);if(old.length!==1||r.observed.facts.filter(o=>o.label===f.label).length!==1||Object.is(old[0]!.value,f.value))return [];return [{controlId:r.controlId,label:f.label,from:JSON.stringify(old[0]!.value),to:JSON.stringify(f.value)}];});}) : [],
    lostCoverage: controlStatusChanges.filter(c=>c.from!==null&&c.to!==null&&!['NOT_ASSESSED','ERROR'].includes(c.from)&&['NOT_ASSESSED','ERROR'].includes(c.to)).map(c=>({controlId:c.controlId,title:c.title,from:c.from!,to:c.to!})),
    newFindings,
    resolvedFindings,
    changedFindings,
    unchangedFindingCount: unchanged,
    controlStatusChanges,
    direction,
  };
}
