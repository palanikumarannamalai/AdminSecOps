import { PRODUCT_NAME } from '@adminsecops/core';
import { AssessmentResultSchema, type AssessmentResult } from '@adminsecops/schemas';

export interface JsonReport {
  reportType: 'adminsecops.assessment';
  reportVersion: '1.0';
  generatedBy: string;
  generatedAt: string;
  assessment: AssessmentResult;
}

/**
 * Machine-readable report. The assessment is re-validated against the published
 * schema so consumers can rely on the structure (docs/EVIDENCE-MODEL.md).
 */
export function buildJsonReport(result: AssessmentResult, generatedAt: Date = new Date()): JsonReport {
  const assessment = AssessmentResultSchema.parse(result);
  return {
    reportType: 'adminsecops.assessment',
    reportVersion: '1.0',
    generatedBy: `${PRODUCT_NAME} ${assessment.engineVersion}`,
    generatedAt: generatedAt.toISOString(),
    assessment,
  };
}

export function serializeJsonReport(report: JsonReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

/** Suggested download file name (no characters that are unsafe in file names or headers). */
export function reportFileName(result: AssessmentResult, extension: 'html' | 'json'): string {
  const env = result.collection.environment;
  const name = (env.label ?? env.primaryDomain ?? env.adForestName ?? 'assessment').replace(/[^A-Za-z0-9.-]+/g, '-').slice(0, 60);
  const date = result.assessedAt.slice(0, 10);
  return `adminsecops-report-${name}-${date}.${extension}`;
}
