import type { CollectorModule, Technology } from '@adminsecops/core';
import type {
  AssessmentComparison,
  AssessmentResult,
  AssessmentSummary,
  ControlMetadata,
  DatasetDefinition,
} from '@adminsecops/schemas';

export type { AssessmentComparison, AssessmentResult, AssessmentSummary, ControlMetadata };

export interface HealthResponse {
  status: 'ok';
  product: 'AdminSecOps';
  version: string;
  engineVersion: string;
  controlLibraryVersion: string;
}

export interface AssessmentListItem {
  assessmentId: string;
  label: string | null;
  tenantDisplayName: string | null;
  primaryDomain: string | null;
  adForestName: string | null;
  assessedAt: string;
  processedAt: string;
  integrityVerified: boolean;
  source: 'upload' | 'sample';
  summary: AssessmentSummary;
}

export type SampleName = 'contoso' | 'contoso-followup' | 'fabrikam';

export interface SampleInfo {
  name: SampleName;
  title: string;
  description: string;
}

export interface ControlLibraryResponse {
  controls: ControlMetadata[];
  libraryVersion: string;
}

export interface DatasetInfo {
  id: string;
  module: CollectorModule;
  technology: Technology;
  title: string;
  description: string;
  source: DatasetDefinition['source'];
  operations: string[];
  permissions: string[];
  prerequisites: string[] | null | undefined;
  personalData: DatasetDefinition['personalData'];
}

export interface CreatedAssessment {
  assessmentId: string;
}
