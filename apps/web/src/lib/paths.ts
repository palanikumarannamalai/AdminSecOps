export function assessmentPath(assessmentId: string, sub = ''): string {
  const base = `/assessments/${encodeURIComponent(assessmentId)}`;
  return sub === '' ? base : `${base}/${sub}`;
}

export function findingPath(assessmentId: string, findingId: string): string {
  return assessmentPath(assessmentId, `findings/${encodeURIComponent(findingId)}`);
}
